package portal

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// handoffListener accepts already-inspected TLS connections without a TCP redial,
// preserving the socket peer for both HTTP and hijacked reverse sessions.
type handoffListener struct {
	addr      net.Addr
	conns     chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

func (l *handoffListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *handoffListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (l *handoffListener) Addr() net.Addr { return l.addr }

type apiError struct {
	code   string
	msg    string
	status int
}

func (e *apiError) Error() string { return e.msg }

var (
	errFeatureUnavailable       = &apiError{types.APIErrorCodeFeatureUnavailable, "feature unavailable", http.StatusServiceUnavailable}
	errHostnameConflict         = &apiError{types.APIErrorCodeHostnameConflict, "hostname conflict", http.StatusConflict}
	errLeaseNotFound            = &apiError{types.APIErrorCodeLeaseNotFound, "lease not found", http.StatusNotFound}
	errLeaseRejected            = &apiError{types.APIErrorCodeLeaseRejected, "lease is not approved for routing", http.StatusForbidden}
	errTransportMismatch        = &apiError{types.APIErrorCodeTransportMismatch, "transport mismatch", http.StatusConflict}
	errUnauthorized             = &apiError{types.APIErrorCodeUnauthorized, "unauthorized", http.StatusForbidden}
	errUDPDisabled              = &apiError{types.APIErrorCodeUDPDisabled, "udp disabled", http.StatusForbidden}
	errUDPCapacityExceeded      = &apiError{types.APIErrorCodeUDPCapacityExceeded, "udp capacity exceeded", http.StatusServiceUnavailable}
	errUDPPortExhausted         = &apiError{types.APIErrorCodeUDPPortExhausted, "no udp ports available", http.StatusServiceUnavailable}
	errTCPPortDisabled          = &apiError{types.APIErrorCodeTCPPortDisabled, "tcp port disabled", http.StatusForbidden}
	errTCPPortCapacityExceeded  = &apiError{types.APIErrorCodeTCPPortCapacityExceeded, "tcp port capacity exceeded", http.StatusServiceUnavailable}
	errTCPPortExhausted         = &apiError{types.APIErrorCodeTCPPortExhausted, "no tcp ports available", http.StatusServiceUnavailable}
	errRegisterChallengePending = &apiError{types.APIErrorCodeRateLimited, "too many pending register challenges", http.StatusTooManyRequests}
)

func writeAPIErrorResponse(w http.ResponseWriter, err error) {
	if ae, ok := errors.AsType[*apiError](err); ok {
		utils.WriteAPIError(w, ae.status, ae.code, ae.msg)
		return
	}
	utils.InvalidRequestError(err).Write(w)
}

func (s *Server) newAPIServer(handler http.Handler, apiTLS *tls.Config) (*http.Server, io.Closer, error) {
	if len(s.apiKeyPEM) > 0 {
		signer, err := keyless.NewSigner(s.apiKeyPEM, s.registry.bindings)
		if err != nil {
			return nil, nil, fmt.Errorf("configure api signer: %w", err)
		}
		s.signer = signer
	}

	apiServer := &http.Server{
		Handler:           s.apiHandler(handler),
		ReadHeaderTimeout: 10 * time.Second,
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		TLSConfig:         apiTLS,
	}
	return apiServer, nil, nil
}

// apiHandler keeps the tenant data path ahead of the composed route table:
// a tenant TLS connection is bound to its own Host, and cached tenant sites
// never reach the relay control plane. Route dispatch itself is composed by
// the relay's policy package; this layer only owns portal data-path routing.
func (s *Server) apiHandler(base http.Handler) http.Handler {
	// A nil *http.ServeMux reaches this handler as a typed-nil interface: it
	// compares non-nil, then panics on the first ServeHTTP call. Normalize it
	// so the root fallback below still covers Start(ctx, nil).
	if mux, ok := base.(*http.ServeMux); ok && mux == nil {
		base = nil
	}
	if base == nil {
		mux := http.NewServeMux()
		mux.HandleFunc("/{$}", s.HandleRoot)
		base = mux
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := utils.NormalizeHostname(r.Host)
		if hostname, _, err := net.SplitHostPort(r.Host); err == nil {
			host = utils.NormalizeHostname(hostname)
		}
		// Bind a tenant TLS connection to its Host even if the next request
		// tries to address a control-plane path or the canonical root host.
		if r.TLS != nil && r.TLS.ServerName != "" && utils.NormalizeHostname(r.TLS.ServerName) != s.identity.Name {
			s.serveCachedSite(w, r, host)
			return
		}
		// An IP-literal Host carries no tenant identity (cache entries are
		// keyed by hostname), so it stays on the control plane.
		if s.registry.cache != nil && host != s.identity.Name && net.ParseIP(host) == nil {
			s.serveCachedSite(w, r, host)
			return
		}
		base.ServeHTTP(w, r)
	})
}

// HandleRoot answers the relay's own root document when no application
// handler owns the path.
func (s *Server) HandleRoot(w http.ResponseWriter, _ *http.Request) {
	utils.WriteAPIData(w, http.StatusOK, map[string]any{
		"service": "portal-relay",
		"root":    s.identity.Name,
	})
}

func (s *Server) HandleRelayDiscovery(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	if s.relaySet == nil {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "relay discovery disabled")
		return
	}

	now := time.Now().UTC()
	self, err := s.newSelfDescriptor(now)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, err.Error())
		return
	}

	utils.WriteAPIData(w, http.StatusOK, types.DiscoveryResponse{
		ProtocolVersion:      types.DiscoveryVersion,
		GeneratedAt:          now,
		Relays:               s.relaySet.Descriptors(self),
		IncompatibleRelays:   s.relaySet.KnownIncompatibleRelays(),
		ReleaseVersion:       types.ReleaseVersion,
		RelayReleaseVersions: s.relaySet.KnownRelayReleaseVersions(),
	})
}

func (s *Server) HandleRelayDiscoveryAnnounce(w http.ResponseWriter, r *http.Request, clientIP string) {
	if s.relaySet == nil {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "relay discovery disabled")
		return
	}

	req, ok := utils.DecodeJSONRequest[types.DiscoveryAnnounceRequest](w, r, defaultControlBodyLimit)
	if !ok {
		return
	}
	if req.ProtocolVersion != "" && req.ProtocolVersion != types.DiscoveryVersion {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest,
			fmt.Sprintf("announce protocol mismatch: relay=%q client=%q", types.DiscoveryVersion, req.ProtocolVersion))
		return
	}

	desc, err := discovery.NormalizeRelayDescriptor(req.Descriptor)
	if err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
		return
	}
	// Self-announce guard: the relay's own URL is established locally, not
	// gossiped through the announce endpoint. Validate the normalized URL so
	// scheme-less inputs are checked the same way signature verification will
	// check them later.
	announceURL, err := url.Parse(desc.APIHTTPSAddr)
	if err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
		return
	}
	host := utils.NormalizeHostname(announceURL.Hostname())
	if utils.IsLocalRelayHost(host) {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest,
			fmt.Sprintf("self-announce rejected: host %q is local-only", host))
		return
	}
	cfg := s.config()
	if selfURL, err := utils.NormalizeRelayURL(cfg.PortalURL); err == nil && desc.APIHTTPSAddr == selfURL {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest,
			fmt.Sprintf("self-announce rejected: %q matches receiving relay url", desc.APIHTTPSAddr))
		return
	}
	if host != "" && host == utils.NormalizeHostname(s.identity.Name) {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest,
			fmt.Sprintf("self-announce rejected: host %q matches receiving relay host", host))
		return
	}

	now := time.Now().UTC()
	if err := s.relaySet.InsertCandidate(desc, now); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
		return
	}

	log.Info().
		Str("relay", desc.APIHTTPSAddr).
		Str("source_ip", clientIP).
		Msg("relay discovery announce accepted")

	utils.WriteAPIData(w, http.StatusAccepted, types.DiscoveryAnnounceResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Accepted:        true,
	})
}

// DomainReport returns the relay-owned /sdk/domain payload. An
// application that sets ServerConfig.ApplicationOwnsDomainReport composes its
// own metadata onto this value and serves the result itself. x402
// facilitator metadata is owned by the application that mounts the
// facilitator (cmd/relay-server); this report stays x402-blind.
func (s *Server) DomainReport() types.DomainResponse {
	return types.DomainResponse{
		Cache:           s.registry.cache.Limits(),
		ProtocolVersion: types.SDKVersion,
		ReleaseVersion:  types.ReleaseVersion,
		ENS:             s.acmeManager.ENSStatus(),
	}
}

func (s *Server) HandleDomain(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	utils.WriteAPIData(w, http.StatusOK, s.DomainReport())
}

// handleCertificateChain serves the public chain already presented by the relay's
// TLS endpoint to runtimes whose TLS stack does not expose peer certificates.
func (s *Server) HandleCertificateChain(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	if len(s.apiCertPEM) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(s.apiCertPEM)
}

// HandleRegister completes a verified registration without publishing the
// success response. The relay first applies the returned identity's access
// decision, then writes the response so the lease cannot become observable
// before its routability is known.
func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request, clientIP string) (string, types.RegisterResponse, bool) {
	req, ok := utils.DecodeJSONRequest[types.RegisterRequest](w, r, defaultControlBodyLimit)
	if !ok {
		return "", types.RegisterResponse{}, false
	}

	challenge, err := s.registry.consumeVerifiedRegisterChallenge(req)
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrRegisterChallengeInvalidSignature):
			utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, err.Error())
		default:
			utils.InvalidRequestError(err).Write(w)
		}
		return "", types.RegisterResponse{}, false
	}
	identityKey := challenge.Request.Identity.Key()
	// A registering identity starts fail-closed. Mux replaces this projection
	// with the relay's current access decision before publishing success.
	s.registry.suspendIdentity(identityKey)

	var self types.RelayDescriptor
	var descriptors []types.RelayDescriptor
	if challenge.Request.Overlay {
		self, descriptors, err = s.overlayIssueDescriptors(time.Now().UTC())
		if err != nil {
			log.Warn().Err(err).Str("lease", challenge.Request.Identity.Key()).Msg("relay overlay descriptors unavailable; using direct reverse transport")
			self = types.RelayDescriptor{}
			descriptors = nil
		}
	}
	record, resp, err := s.registry.Register(challenge.Request, clientIP, req.ReportedIP, self, descriptors)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return identityKey, types.RegisterResponse{}, false
	}
	dnsCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), defaultClaimTimeout)
	err = record.syncENSGaslessDNS(dnsCtx, s.acmeManager)
	cancel()
	if err != nil {
		removed, _ := s.registry.Unregister(types.UnregisterRequest{AccessToken: resp.AccessToken})
		if removed == nil {
			record.Close()
			removed = record
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(r.Context()), defaultClaimTimeout)
		removed.deleteDNS(cleanupCtx, s.acmeManager)
		cleanupCancel()
		writeAPIErrorResponse(w, err)
		return identityKey, types.RegisterResponse{}, false
	}
	if record.tcpPort > 0 {
		go s.serveTCP(record)
	}

	return record.Key(), resp, true
}

// HandleRegisterChallenge issues a registration challenge without publishing
// the success response, allowing the relay to apply access state first.
func (s *Server) HandleRegisterChallenge(w http.ResponseWriter, r *http.Request, clientIP string) (string, types.RegisterChallengeResponse, bool) {
	req, ok := utils.DecodeJSONRequest[types.RegisterChallengeRequest](w, r, defaultControlBodyLimit)
	if !ok {
		return "", types.RegisterChallengeResponse{}, false
	}

	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	domain := strings.TrimSpace(r.Host)
	domain = cmp.Or(domain, s.identity.Name)
	registerURI := (&url.URL{
		Scheme: scheme,
		Host:   domain,
		Path:   types.PathSDKRegister,
	}).String()

	if req.UDPEnabled && !s.supportsUDP() {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUDPDisabled,
			"UDP transport is disabled on this relay")
		return "", types.RegisterChallengeResponse{}, false
	}
	if req.TCPEnabled && !s.supportsTCP() {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeTCPPortDisabled,
			"raw TCP transport is disabled on this relay")
		return "", types.RegisterChallengeResponse{}, false
	}

	resp, err := s.registry.issueRegisterChallenge(req, domain, registerURI, clientIP)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return req.Identity.Key(), types.RegisterChallengeResponse{}, false
	}

	return req.Identity.Key(), resp, true
}

func (s *Server) HandleRenew(w http.ResponseWriter, r *http.Request, clientIP string) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}

	req, ok := utils.DecodeJSONRequest[types.RenewRequest](w, r, defaultControlBodyLimit)
	if !ok {
		return
	}

	resp, endpointInput, err := s.registry.Renew(req, clientIP)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	resp.ReverseEndpoint, err = s.issueReverseEndpoint(endpointInput)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}

	utils.WriteAPIData(w, http.StatusOK, resp)
}

func (s *Server) HandleUnregister(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}

	req, ok := utils.DecodeJSONRequest[types.UnregisterRequest](w, r, defaultControlBodyLimit)
	if !ok {
		return
	}
	record, err := s.registry.Unregister(req)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	dnsCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), defaultClaimTimeout)
	record.deleteDNS(dnsCtx, s.acmeManager)
	cancel()

	utils.WriteAPIData(w, http.StatusOK, map[string]any{})
}

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

// serveReverseMux offers each stream the connector opens on session to the lease like
// any other reverse connection. The lease owns the session, so it ends with the lease.
func (s *Server) serveReverseMux(lease *leaseRecord, session *transport.ReverseMux, clientIP string) {
	release, err := lease.attachReverseMux(session)
	if err != nil {
		_ = session.Close()
		return
	}
	defer release()

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
		// Offer closes a stream it turns away, as when the ready queue is full.
		if err := lease.reverse.Offer(stream); err != nil {
			continue
		}
		s.registry.Touch(lease.Key(), clientIP, time.Now())
	}
}

func (s *Server) HandleConnect(w http.ResponseWriter, r *http.Request, clientIP string) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	if r.ProtoMajor != 1 {
		utils.WriteAPIError(w, http.StatusHTTPVersionNotSupported, types.APIErrorCodeHTTP11Only, "reverse connect requires HTTP/1.1")
		return
	}

	// The WebSocket carrier has its own credential grammar, and overlay routing only
	// speaks the raw carrier, so it is told apart before either is read.
	if transport.IsReverseMuxRequest(r) {
		lease, err := s.registry.admitReverseCapability(transport.ReverseMuxCapability(r))
		if err != nil {
			writeAPIErrorResponse(w, err)
			return
		}
		session, err := transport.AcceptReverseMux(w, r)
		if err != nil {
			return
		}
		s.serveReverseMux(lease, session, clientIP)
		return
	}

	capability := strings.TrimSpace(r.Header.Get(types.HeaderReverseCapability))
	if s.overlay != nil && s.overlay.Handles(capability) {
		client, gateway := s.overlay.HandleConnect(w, r, capability, clientIP)
		if client != nil {
			s.proxy.bridge(client, gateway, "", s.registry.bps)
		}
		return
	}

	lease, err := s.registry.admitReverseCapability(capability)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeHijackUnsupported, "hijacking is not supported")
		return
	}

	conn, rw, err := hijacker.Hijack()
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeHijackFailed, err.Error())
		return
	}

	if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: raw\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		_ = conn.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return
	}

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

	s.registry.Touch(lease.Key(), clientIP, time.Now())
	log.Info().
		Str("address", lease.Address).
		Str("lease_name", lease.Name).
		Str("remote_addr", remoteAddr).
		Int("ready", lease.reverse.ReadyCount()).
		Msg("sdk reverse connected")
}

func (s *Server) HandleStaticCache(w http.ResponseWriter, req *http.Request) {
	record, err := s.registry.admitLeaseByToken(req.Header.Get(types.HeaderAccessToken), false)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	// Capture before the access check: revocation either rejects admission
	// here or invalidates this generation before cache publication.
	generation := s.registry.cache.Generation(record.id)
	if !s.registry.isRoutable(record.Key()) {
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

// Tenant hosts never reach the relay control plane, including on a connection
// with a mismatched Host header. TLS termination here is explicit cache opt-in.
func (s *Server) serveCachedSite(w http.ResponseWriter, req *http.Request, host string) {
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
	if !ok || !s.registry.isRoutable(record.Key()) || !s.registry.cache.Eligible(record.id) {
		http.Error(w, "static origin unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
	defer cancel()
	httpTransport := &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// The relay is the TLS client on this fallback: no routed
			// client hello exists at issue time, so the binding starts
			// pending and is pinned to the relay's own ClientHello on
			// first write.
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
			roots := x509.NewCertPool()
			for _, cert := range s.apiServer.TLSConfig.Certificates {
				leaf, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					_ = upstream.Close()
					return nil, err
				}
				roots.AddCert(leaf)
			}
			conn := tls.Client(s.registry.bindings.FixHelloOnWrite(upstream, binding), &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12})
			if err := conn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("cache fallback TLS: %w", err)
			}
			return conn, nil
		},
	}
	defer httpTransport.CloseIdleConnections()
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "https", Host: host})
	proxy.Transport = httpTransport
	proxy.ServeHTTP(w, req.WithContext(ctx))
}
