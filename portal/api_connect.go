package portal

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func (s *Server) HandleReverseEndpoint(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	req, ok := utils.DecodeJSONRequest[types.ReverseEndpointRequest](w, r, defaultControlBodyLimit)
	if !ok {
		return
	}
	endpointInput, err := s.registry.resolveReverseEndpoint(req)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	endpoint, err := s.issueReverseEndpoint(endpointInput)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	utils.WriteAPIData(w, http.StatusOK, endpoint)
}

func (s *Server) serveReverseMux(lease *leaseRecord, session *transport.ReverseMux, sourceAddr netip.Addr) {
	if err := lease.attachReverseMux(session); err != nil {
		_ = session.Close()
		return
	}
	defer lease.detachReverseMux(session)

	log.Info().Str("address", lease.Address).Str("lease_name", lease.Name).Msg("sdk reverse session opened over websocket")
	for {
		stream, capability, err := session.Accept()
		if err != nil {
			return
		}
		admitted, authErr := s.registry.admitReverseCapability(capability)
		authorized := authErr == nil && admitted == lease
		if err := transport.ConfirmReverseStream(stream, authorized); err != nil || !authorized {
			_ = stream.Close()
			continue
		}
		if err := lease.reverse.Offer(stream); err != nil {
			continue
		}
		s.registry.Touch(lease.ServiceKey(), sourceAddr, time.Now())
	}
}

func (s *Server) hijackReverseConn(w http.ResponseWriter) (net.Conn, bool) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeHijackUnsupported, "hijacking is not supported")
		return nil, false
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeHijackFailed, err.Error())
		return nil, false
	}
	if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: raw\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		_ = conn.Close()
		return nil, false
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, false
	}
	return conn, true
}

func (s *Server) offerReverseLease(lease *leaseRecord, conn net.Conn, sourceAddr netip.Addr) {
	remoteAddr := ""
	if conn.RemoteAddr() != nil {
		remoteAddr = conn.RemoteAddr().String()
	}
	if err := lease.reverse.Offer(conn); err != nil {
		log.Warn().
			Err(err).
			Str("address", lease.Address).
			Str("lease_name", lease.Name).
			Str("remote_addr", remoteAddr).
			Msg("sdk reverse rejected")
		return
	}
	s.registry.Touch(lease.ServiceKey(), sourceAddr, time.Now())
	log.Info().
		Str("address", lease.Address).
		Str("lease_name", lease.Name).
		Str("remote_addr", remoteAddr).
		Int("ready", lease.reverse.ReadyCount()).
		Msg("sdk reverse connected")
}

func (s *Server) HandleConnect(w http.ResponseWriter, r *http.Request, sourceAddr netip.Addr) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	if r.ProtoMajor != 1 {
		utils.WriteAPIError(w, http.StatusHTTPVersionNotSupported, types.APIErrorCodeHTTP11Only, "reverse connect requires HTTP/1.1")
		return
	}

	if s.serveHandleConnectMux(w, r, sourceAddr) {
		return
	}

	capability := strings.TrimSpace(r.Header.Get(types.HeaderReverseCapability))
	if s.serveHandleConnectOverlay(w, r, capability, sourceAddr) {
		return
	}

	lease, err := s.registry.admitReverseCapability(capability)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}

	conn, ok := s.hijackReverseConn(w)
	if !ok {
		return
	}
	s.offerReverseLease(lease, conn, sourceAddr)
}

func (s *Server) serveHandleConnectMux(w http.ResponseWriter, r *http.Request, sourceAddr netip.Addr) bool {
	if !transport.IsReverseMuxRequest(r) {
		return false
	}
	lease, err := s.registry.admitReverseCapability(transport.ReverseMuxCapability(r))
	if err != nil {
		writeAPIErrorResponse(w, err)
		return true
	}
	session, err := transport.AcceptReverseMux(w, r)
	if err != nil {
		return true
	}
	s.serveReverseMux(lease, session, sourceAddr)
	return true
}

func (s *Server) serveHandleConnectOverlay(w http.ResponseWriter, r *http.Request, capability string, sourceAddr netip.Addr) bool {
	if s.overlay == nil || !s.overlay.Handles(capability) {
		return false
	}
	client, gateway := s.overlay.HandleConnect(w, r, capability, sourceAddr)
	if client != nil {
		s.proxy.bridge(s.ingressCtx, client, gateway, types.ServiceIdentityKey{}, s.registry.bps)
	}
	return true
}

func (s *Server) HandleStaticCache(w http.ResponseWriter, req *http.Request) {
	record, err := s.registry.admitLeaseByToken(req.Header.Get(types.HeaderAccessToken), false)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	generation := s.registry.cache.Generation(record.id)
	if !s.registry.isRoutable(record.ServiceKey()) {
		writeAPIErrorResponse(w, errLeaseRejected)
		return
	}
	s.registry.cache.Handle(w, req, record.id, generation)
}

// HandleSign authenticates a transcript-signing request and binds the
// signature to the live lease the access token belongs to.
func (s *Server) HandleSign(w http.ResponseWriter, r *http.Request) {
	if s.signer == nil {
		http.NotFound(w, r)
		return
	}
	leaseID, ok := s.registry.verifySigningAccessTokenLease(r)
	if !ok {
		writeAPIErrorResponse(w, errUnauthorized)
		return
	}
	s.signer.ServeHTTP(w, r, leaseID)
}
func (s *Server) serveCachedSite(w http.ResponseWriter, req *http.Request, host string) {
	if utils.IsLocalTLSHostname(host, s.registry.rootHostname) {
		http.Error(w, "local TLS hostnames require tunnel termination", http.StatusMisdirectedRequest)
		return
	}
	if req.TLS == nil || utils.NormalizeHostname(req.TLS.ServerName) != host {
		http.Error(w, "TLS name and request host must match", http.StatusMisdirectedRequest)
		return
	}
	if s.registry.cache.Serve(w, req, host) {
		return
	}
	// A snapshot can be evicted between ClientHello routing and HTTP lookup.
	// Reuse the reverse stream for fallback, never dial a user-supplied URL.
	// This already-terminated connection remains within the cache trust opt-in.
	record, ok := s.registry.Lookup(host)
	if !ok || !s.registry.isRoutable(record.ServiceKey()) || !s.registry.cache.Eligible(record.id) {
		http.Error(w, "static origin unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
	defer cancel()
	httpTransport := s.serveCachedSiteFallbackTransport(host, record)
	defer httpTransport.CloseIdleConnections()
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "https", Host: host})
	proxy.Transport = httpTransport
	proxy.ServeHTTP(w, req.WithContext(ctx))
}

func (s *Server) serveCachedSiteFallbackTransport(host string, record *leaseRecord) *http.Transport {
	return &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			binding := s.registry.bindings.Issue(record.id, nil)
			var upstream net.Conn
			for {
				var err error
				upstream, err = record.reverse.Acquire(ctx)
				if err != nil {
					s.registry.bindings.Discard(binding)
					return nil, err
				}
				if err := transport.WriteTLSStart(upstream, binding); err == nil {
					break
				}
				_ = upstream.Close()
			}
			conn := tls.Client(s.registry.bindings.FixHelloOnWrite(upstream, binding), s.acmeManager.TenantTLSConfig(host))
			if err := conn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("cache fallback TLS: %w", err)
			}
			return conn, nil
		},
	}
}
