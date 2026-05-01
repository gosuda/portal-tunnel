package portal

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type apiError struct {
	code   string
	msg    string
	status int
}

func (e *apiError) Error() string { return e.msg }

var (
	errFeatureUnavailable       = &apiError{types.APIErrorCodeFeatureUnavailable, "feature unavailable", http.StatusServiceUnavailable}
	errHostnameConflict         = &apiError{types.APIErrorCodeHostnameConflict, "hostname conflict", http.StatusConflict}
	errIPBanned                 = &apiError{types.APIErrorCodeIPBanned, "request denied because source IP is banned", http.StatusForbidden}
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

func (s *Server) newAPIServer(listener net.Listener, apiMux *http.ServeMux, apiTLS keyless.TLSMaterialConfig) (net.Listener, *http.Server, io.Closer, error) {
	var keylessSignerHandler http.Handler
	if len(apiTLS.KeyPEM) > 0 {
		signer, err := keyless.NewSigner(apiTLS.KeyPEM)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("configure api signer: %w", err)
		}
		keylessSignerHandler = signer.Handler()
	}

	apiServer := &http.Server{
		Handler:           s.apiHandler(apiMux, keylessSignerHandler),
		ReadHeaderTimeout: 10 * time.Second,
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	apiCloser, err := keyless.AttachToHTTPServer(apiServer, apiTLS)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("configure api tls: %w", err)
	}

	return tls.NewListener(listener, apiServer.TLSConfig), apiServer, apiCloser, nil
}

func (s *Server) apiHandler(base *http.ServeMux, keylessSignerHandler http.Handler) http.Handler {
	if base == nil {
		base = http.NewServeMux()
		base.HandleFunc("/{$}", s.handleRoot)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimSpace(r.URL.Path) {
		case types.PathHealthz:
			s.handleHealthz(w, r)
		case types.PathSDKDomain:
			s.handleDomain(w, r)
		case types.PathSDKRegisterChallenge:
			s.handleRegisterChallenge(w, r)
		case types.PathSDKRegister:
			s.handleRegister(w, r)
		case types.PathSDKRenew:
			s.handleRenew(w, r)
		case types.PathSDKUnregister:
			s.handleUnregister(w, r)
		case types.PathSDKHop:
			s.handleHop(w, r)
		case types.PathSDKConnect:
			s.handleConnect(w, r)
		case types.PathDiscovery:
			if !s.cfg.DiscoveryEnabled {
				base.ServeHTTP(w, r)
				return
			}
			s.handleRelayDiscovery(w, r)
		case types.PathDiscoveryAnnounce:
			if !s.cfg.DiscoveryEnabled {
				base.ServeHTTP(w, r)
				return
			}
			s.handleRelayDiscoveryAnnounce(w, r)
		case types.PathV1Sign:
			if keylessSignerHandler == nil {
				http.NotFound(w, r)
				return
			}
			keylessSignerHandler.ServeHTTP(w, r)
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
		ProtocolVersion: types.DiscoveryVersion,
		GeneratedAt:     now,
		Relays:          s.relaySet.Descriptors(self),
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
	clientIP, ok := s.extractAllowedClientIP(w, r)
	if !ok {
		return
	}
	if !s.announceLimiter.Allow(clientIP) {
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "announce rate limit exceeded")
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

	desc, err := utils.NormalizeDescriptor(req.Descriptor)
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
	if selfURL, err := utils.NormalizeRelayURL(s.cfg.PortalURL); err == nil && desc.APIHTTPSAddr == selfURL {
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
	if err := s.relaySet.InsertAnnounced(desc, now); err != nil {
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

func (s *Server) handleDomain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}

	utils.WriteAPIData(w, http.StatusOK, types.DomainResponse{
		ProtocolVersion: types.SDKVersion,
		ReleaseVersion:  types.ReleaseVersion,
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}

	clientIP, ok := s.extractAllowedClientIP(w, r)
	if !ok {
		return
	}

	req, ok := utils.DecodeJSONRequest[types.RegisterRequest](w, r, defaultControlBodyLimit)
	if !ok {
		return
	}

	challenge, err := s.registry.consumeVerifiedRegisterChallenge(req)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrRegisterChallengeInvalidSignature):
			utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, err.Error())
		default:
			utils.InvalidRequestError(err).Write(w)
		}
		return
	}

	record, resp, err := s.registry.Register(challenge.Request, clientIP, req.ReportedIP)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	if err := s.syncENSGaslessHostname(context.Background(), record); err != nil {
		removed, _ := s.registry.Unregister(types.UnregisterRequest{AccessToken: resp.AccessToken})
		if removed == nil {
			record.Close()
			removed = record
		}
		s.deleteENSGaslessHostname(context.Background(), removed, "delete lease ens gasless hostname after sync failure")
		writeAPIErrorResponse(w, err)
		return
	}

	utils.WriteAPIData(w, http.StatusCreated, resp)
}

func (s *Server) handleRegisterChallenge(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}

	clientIP, ok := s.extractAllowedClientIP(w, r)
	if !ok {
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
	if domain == "" {
		domain = s.identity.Name
	}
	registerURI := (&url.URL{
		Scheme: scheme,
		Host:   domain,
		Path:   types.PathSDKRegister,
	}).String()

	if strings.TrimSpace(req.HopToken) != "" && s.hopMux == nil {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, errFeatureUnavailable.Error())
		return
	}
	if req.UDPEnabled && (!s.cfg.UDPEnabled || s.group != nil && s.quicBackhaul == nil) {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, errFeatureUnavailable.Error())
		return
	}
	if req.TCPEnabled && !s.cfg.TCPEnabled {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, errFeatureUnavailable.Error())
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

	clientIP, ok := s.extractAllowedClientIP(w, r)
	if !ok {
		return
	}

	req, ok := utils.DecodeJSONRequest[types.RenewRequest](w, r, defaultControlBodyLimit)
	if !ok {
		return
	}

	resp, err := s.registry.Renew(req, clientIP)
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
	s.deleteENSGaslessHostname(context.Background(), record, "delete lease ens gasless hostname")

	utils.WriteAPIData(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleHop(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost, http.MethodDelete:
	default:
		utils.MethodNotAllowedError().Write(w)
		return
	}
	if s.hopMux == nil || s.overlay == nil || s.relaySet == nil {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, errFeatureUnavailable.Error())
		return
	}
	if _, ok := s.extractAllowedClientIP(w, r); !ok {
		return
	}

	route, ok := utils.DecodeJSONRequest[types.HopRoute](w, r, defaultControlBodyLimit)
	if !ok {
		return
	}
	route, err := auth.VerifyHopRoute(r.Method, route)
	if errors.Is(err, auth.ErrHopRouteSignatureInvalid) {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, "hop route signature is invalid")
		return
	}
	if err != nil {
		utils.InvalidRequestError(err).Write(w)
		return
	}
	if route.RelayURL != s.cfg.PortalURL {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, "hop route relay url does not match receiving relay")
		return
	}
	if r.Method == http.MethodDelete {
		record := s.registry.DeleteHopRoute(&route)
		s.deleteENSGaslessHostname(context.Background(), record, "delete hop route ens gasless hostname")
		utils.WriteAPIData(w, http.StatusOK, map[string]any{})
		return
	}

	now := time.Now().UTC()
	if !route.ExpiresAt.UTC().After(now) {
		utils.InvalidRequestError(errors.New("route expiry must be in the future")).Write(w)
		return
	}
	forwardRelay, err := auth.VerifyRelayDescriptor(route.ForwardRelay)
	if err != nil {
		utils.InvalidRequestError(fmt.Errorf("forward relay: %w", err)).Write(w)
		return
	}
	if !forwardRelay.HasOverlayPeer() {
		utils.InvalidRequestError(errors.New("forward relay wireguard overlay metadata is required")).Write(w)
		return
	}
	route.ForwardRelay = forwardRelay
	if err := s.relaySet.InsertAnnounced(forwardRelay, now); err != nil {
		utils.InvalidRequestError(fmt.Errorf("forward relay: %w", err)).Write(w)
		return
	}
	if err := s.overlay.Sync(s.relaySet.OverlayPeerStates()); err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, err.Error())
		return
	}
	record, err := s.registry.RegisterHopRoute(&route, now)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	if err := s.syncENSGaslessHostname(context.Background(), record); err != nil {
		removed := s.registry.DeleteHopRoute(&route)
		if removed == nil {
			removed = record
		}
		s.deleteENSGaslessHostname(context.Background(), removed, "delete hop route ens gasless hostname after sync failure")
		writeAPIErrorResponse(w, err)
		return
	}
	utils.WriteAPIData(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	if r.ProtoMajor != 1 {
		utils.WriteAPIError(w, http.StatusHTTPVersionNotSupported, types.APIErrorCodeHTTP11Only, "reverse connect requires HTTP/1.1")
		return
	}

	token := strings.TrimSpace(r.Header.Get(types.HeaderAccessToken))
	clientIP, ok := s.extractAllowedClientIP(w, r)
	if !ok {
		return
	}

	lease, err := s.registry.admitLeaseByToken(token, false)
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

	if _, err := rw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"); err != nil {
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

func (s *Server) extractAllowedClientIP(w http.ResponseWriter, r *http.Request) (string, bool) {
	clientIP := s.registry.policy.ExtractClientIP(r)
	if !s.registry.policy.IPFilter().IsIPBanned(clientIP) {
		return clientIP, true
	}
	utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeIPBanned, "request denied because source IP is banned")
	return "", false
}
