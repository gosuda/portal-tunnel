package portal

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
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
	var keylessSignerHandler http.Handler
	if len(s.apiKeyPEM) > 0 {
		signer, err := keyless.NewSigner(s.apiKeyPEM, s.transcriptValidator())
		if err != nil {
			return nil, nil, fmt.Errorf("configure api signer: %w", err)
		}
		keylessSignerHandler = signer.Handler()
	}

	apiServer := &http.Server{
		Handler:           s.apiHandler(handler, keylessSignerHandler),
		ReadHeaderTimeout: 10 * time.Second,
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		TLSConfig:         apiTLS,
	}
	return apiServer, nil, nil
}

func (s *Server) apiHandler(base http.Handler, keylessSignerHandler http.Handler) http.Handler {
	// A nil *http.ServeMux reaches this handler as a typed-nil interface: it
	// compares non-nil, then panics on the first ServeHTTP call. Normalize it
	// so the root fallback below still covers Start(ctx, nil).
	if mux, ok := base.(*http.ServeMux); ok && mux == nil {
		base = nil
	}
	if base == nil {
		mux := http.NewServeMux()
		mux.HandleFunc("/{$}", s.handleRoot)
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
		if s.registry.cache != nil && host != s.identity.Name {
			s.serveCachedSite(w, r, host)
			return
		}
		if utils.HandleAPICORS(w, r) {
			return
		}
		switch strings.TrimSpace(r.URL.Path) {
		case types.PathHealthz:
			s.handleHealthz(w, r)
		case types.PathSDKDomain:
			if s.config().ApplicationOwnsDomainReport {
				base.ServeHTTP(w, r)
				return
			}
			s.handleDomain(w, r)
		case types.PathSDKRegisterChallenge:
			s.handleRegisterChallenge(w, r)
		case types.PathSDKRegister:
			s.handleRegister(w, r)
		case types.PathSDKRenew:
			s.handleRenew(w, r)
		case types.PathSDKReverse:
			s.handleReverseEndpoint(w, r)
		case types.PathSDKUnregister:
			s.handleUnregister(w, r)
		case types.PathSDKConnect:
			s.handleConnect(w, r)
		case types.PathSDKCache:
			s.handleStaticCache(w, r)
		case types.PathDiscovery:
			if !s.config().DiscoveryEnabled {
				base.ServeHTTP(w, r)
				return
			}
			s.handleRelayDiscovery(w, r)
		case types.PathDiscoveryAnnounce:
			if !s.config().DiscoveryEnabled {
				base.ServeHTTP(w, r)
				return
			}
			s.handleRelayDiscoveryAnnounce(w, r)
		case types.PathV1Sign:
			if keylessSignerHandler == nil {
				http.NotFound(w, r)
				return
			}
			leaseID, ok := s.registry.verifySigningAccessTokenLease(r)
			if !ok {
				writeAPIErrorResponse(w, errUnauthorized)
				return
			}
			keylessSignerHandler.ServeHTTP(w, r.WithContext(withSignLeaseID(r.Context(), leaseID)))
		default:
			base.ServeHTTP(w, r)
		}
	})
}

func (s *Server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	utils.WriteAPIData(w, http.StatusOK, map[string]any{
		"service": "portal-relay",
		"root":    s.identity.Name,
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	utils.WriteAPIData(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleRelayDiscovery(w http.ResponseWriter, r *http.Request) {
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
		ProtocolVersion:    types.DiscoveryVersion,
		GeneratedAt:        now,
		Relays:             s.relaySet.Descriptors(self),
		IncompatibleRelays: s.relaySet.KnownIncompatibleRelays(),
	})
}

func (s *Server) handleRelayDiscoveryAnnounce(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	if s.relaySet == nil {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "relay discovery disabled")
		return
	}
	clientIP := s.registry.policy.ExtractClientIP(r)
	if !s.admitPreAuth(w, r, clientIP, s.config().PreAuth.AnnounceCost) {
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

func (s *Server) handleDomain(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	utils.WriteAPIData(w, http.StatusOK, s.DomainReport())
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}

	clientIP := s.registry.policy.ExtractClientIP(r)
	if !s.admitPreAuth(w, r, clientIP, s.config().PreAuth.RegisterCost) {
		return
	}

	req, ok := utils.DecodeJSONRequest[types.RegisterRequest](w, r, defaultControlBodyLimit)
	if !ok {
		return
	}

	challenge, err := s.registry.consumeVerifiedRegisterChallenge(req)
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrRegisterChallengeInvalidSignature):
			utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, err.Error())
		default:
			utils.InvalidRequestError(err).Write(w)
		}
		return
	}

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
		return
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
		return
	}

	utils.WriteAPIData(w, http.StatusCreated, resp)
}

func (s *Server) handleRegisterChallenge(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}

	clientIP := s.registry.policy.ExtractClientIP(r)
	if !s.admitPreAuth(w, r, clientIP, s.config().PreAuth.ChallengeCost) {
		return
	}

	req, ok := utils.DecodeJSONRequest[types.RegisterChallengeRequest](w, r, defaultControlBodyLimit)
	if !ok {
		return
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
		return
	}
	if req.TCPEnabled && !s.supportsTCP() {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeTCPPortDisabled,
			"raw TCP transport is disabled on this relay")
		return
	}

	resp, err := s.registry.issueRegisterChallenge(req, domain, registerURI, clientIP)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}

	utils.WriteAPIData(w, http.StatusCreated, resp)
}

func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}

	clientIP := s.registry.policy.ExtractClientIP(r)

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

func (s *Server) handleUnregister(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleReverseEndpoint(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	if r.ProtoMajor != 1 {
		utils.WriteAPIError(w, http.StatusHTTPVersionNotSupported, types.APIErrorCodeHTTP11Only, "reverse connect requires HTTP/1.1")
		return
	}

	capability := strings.TrimSpace(r.Header.Get(types.HeaderReverseCapability))
	clientIP := s.registry.policy.ExtractClientIP(r)
	if s.overlay != nil && s.overlay.Handles(capability) {
		s.overlay.HandleConnect(w, r, capability, clientIP)
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
	if err := lease.stream.OfferConn(conn); err != nil {
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
		Int("ready", lease.stream.ReadyCount()).
		Msg("sdk reverse connected")
}

func (s *Server) handleStaticCache(w http.ResponseWriter, req *http.Request) {
	record, err := s.registry.admitLeaseByToken(req.Header.Get(types.HeaderAccessToken), false)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	s.registry.cache.Handle(w, req, record.id)
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
	if !ok || !s.registry.cache.Eligible(record.id) {
		http.Error(w, "static origin unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
	defer cancel()
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			upstream, err := record.stream.Claim(ctx, s.registry.bindings.issue(record.id))
			if err != nil {
				return nil, err
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
			conn := tls.Client(upstream, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12})
			if err := conn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("cache fallback TLS: %w", err)
			}
			return conn, nil
		},
	}
	defer transport.CloseIdleConnections()
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "https", Host: host})
	proxy.Transport = transport
	proxy.ServeHTTP(w, req.WithContext(ctx))
}

// Admission runs before decoding or signature work. Verified lease operations
// use identity policy and do not consume a shared NAT source budget.
func (s *Server) admitPreAuth(w http.ResponseWriter, r *http.Request, clientIP string, cost int) bool {
	retry, _ := s.preAuthLimiter.Allow(clientIP, cost)
	if retry == 0 {
		return true
	}
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retry.Seconds())))))
	utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "pre-auth request budget exhausted")
	return false
}
