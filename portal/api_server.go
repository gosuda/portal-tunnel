package portal

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
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
	errFeatureUnavailable      = &apiError{types.APIErrorCodeFeatureUnavailable, "feature unavailable", http.StatusServiceUnavailable}
	errHostnameConflict        = &apiError{types.APIErrorCodeHostnameConflict, "hostname conflict", http.StatusConflict}
	errIPBanned                = &apiError{types.APIErrorCodeIPBanned, "request denied because source IP is banned", http.StatusForbidden}
	errLeaseNotFound           = &apiError{types.APIErrorCodeLeaseNotFound, "lease not found", http.StatusNotFound}
	errLeaseRejected           = &apiError{types.APIErrorCodeLeaseRejected, "lease is not approved for routing", http.StatusForbidden}
	errTransportMismatch       = &apiError{types.APIErrorCodeTransportMismatch, "transport mismatch", http.StatusConflict}
	errUnauthorized            = &apiError{types.APIErrorCodeUnauthorized, "unauthorized", http.StatusForbidden}
	errUDPDisabled             = &apiError{types.APIErrorCodeUDPDisabled, "udp disabled", http.StatusForbidden}
	errUDPCapacityExceeded     = &apiError{types.APIErrorCodeUDPCapacityExceeded, "udp capacity exceeded", http.StatusServiceUnavailable}
	errTCPPortDisabled         = &apiError{types.APIErrorCodeTCPPortDisabled, "tcp port disabled", http.StatusForbidden}
	errTCPPortCapacityExceeded = &apiError{types.APIErrorCodeTCPPortCapacityExceeded, "tcp port capacity exceeded", http.StatusServiceUnavailable}
	errTCPPortExhausted        = &apiError{types.APIErrorCodeTCPPortExhausted, "no tcp ports available", http.StatusServiceUnavailable}
)

var quicRejectTable = []struct {
	sentinel error
	code     string
	reason   string
}{
	{errLeaseNotFound, types.APIErrorCodeLeaseNotFound, "lease not found"},
	{errLeaseRejected, types.APIErrorCodeLeaseRejected, "lease rejected"},
	{errUnauthorized, types.APIErrorCodeUnauthorized, "unauthorized"},
	{errTransportMismatch, types.APIErrorCodeTransportMismatch, "transport mismatch"},
}

func writeAPIErrorResponse(w http.ResponseWriter, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
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

func (s *Server) extractAllowedClientIP(w http.ResponseWriter, r *http.Request) (string, bool) {
	clientIP := s.registry.policy.ExtractClientIP(r)
	if !s.registry.policy.IPFilter().IsIPBanned(clientIP) {
		return clientIP, true
	}
	utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeIPBanned, "request denied because source IP is banned")
	return "", false
}

func (s *Server) signedRelayDescriptor(now time.Time) (types.RelayDescriptor, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	activeConns := float64(s.proxy.activeConnectionCount())
	tcpTrafficBPS := s.proxy.currentTCPBPS(now)
	ingressAddr := s.identity.Name
	if s.cfg.SNIPort != 0 && s.cfg.SNIPort != 443 {
		ingressAddr = fmt.Sprintf("%s:%d", ingressAddr, s.cfg.SNIPort)
	}

	var wireGuardPublicKey, wireGuardEndpoint, overlayIPv4 string
	var overlayCIDRs []string
	if s.overlay != nil {
		cfg := s.overlay.Config()
		wireGuardPublicKey = cfg.PublicKey
		wireGuardEndpoint = cfg.Endpoint
		overlayIPv4 = cfg.OverlayIPv4
		overlayCIDRs = append([]string(nil), cfg.OverlayCIDRs...)
	}

	self := types.RelayDescriptor{
		Identity:            s.identity.Base(),
		RelayID:             s.cfg.PortalURL,
		OwnerAddress:        s.identity.Address,
		Version:             1,
		IssuedAt:            now,
		ExpiresAt:           now.Add(discovery.DiscoveryDescriptorTTL),
		APIHTTPSAddr:        s.cfg.PortalURL,
		Discovery:           s.cfg.DiscoveryEnabled,
		IngressTLSAddr:      ingressAddr,
		WireGuardPublicKey:  wireGuardPublicKey,
		WireGuardEndpoint:   wireGuardEndpoint,
		OverlayIPv4:         overlayIPv4,
		OverlayCIDRs:        overlayCIDRs,
		SupportsUDP:         s.cfg.UDPEnabled && s.quicTunnel != nil,
		SupportsTCP:         s.cfg.TCPEnabled,
		SupportsOverlayPeer: s.overlay != nil,
		Load:                activeConns,
		LoadScore:           tcpTrafficBPS,
		LastUpdated:         now.UnixMilli(),
	}

	signedSelf, err := auth.SignRelayDescriptor(self, s.identity.PrivateKey)
	if err != nil {
		return types.RelayDescriptor{}, err
	}
	return signedSelf, nil
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
	self, err := s.signedRelayDescriptor(now)
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

	desc := req.Descriptor
	// Self-announce guard: the relay's own URL is established locally, not
	// gossiped through the announce endpoint. Reject loopback / own-host
	// announces to prevent self-amplification or misconfiguration loops.
	announceURL, err := url.Parse(strings.TrimSpace(desc.APIHTTPSAddr))
	if err == nil && announceURL != nil {
		host := utils.NormalizeHostname(announceURL.Hostname())
		if utils.IsLocalRelayHost(host) {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest,
				fmt.Sprintf("self-announce rejected: host %q is local-only", host))
			return
		}
		if selfURL, err := utils.NormalizeRelayURL(s.cfg.PortalURL); err == nil {
			if announceRelayURL, err := utils.NormalizeRelayURL(desc.APIHTTPSAddr); err == nil && announceRelayURL == selfURL {
				utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest,
					fmt.Sprintf("self-announce rejected: %q matches receiving relay url", announceRelayURL))
				return
			}
		}
		if host != "" && host == utils.NormalizeHostname(s.identity.Name) {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest,
				fmt.Sprintf("self-announce rejected: host %q matches receiving relay host", host))
			return
		}
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

	resp, err := s.registerLease(challenge.Request, clientIP, req.ReportedIP)
	if err != nil {
		if errors.Is(err, transport.ErrPortExhausted) {
			utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeUDPPortExhausted, err.Error())
		} else {
			writeAPIErrorResponse(w, err)
		}
		return
	}

	utils.WriteAPIData(w, http.StatusCreated, resp)
}

func (s *Server) handleRegisterChallenge(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}

	if _, ok := s.extractAllowedClientIP(w, r); !ok {
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

	if req.UDPEnabled && (!s.cfg.UDPEnabled || s.group != nil && s.quicTunnel == nil) {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, errFeatureUnavailable.Error())
		return
	}
	if req.TCPEnabled && !s.cfg.TCPEnabled {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, errFeatureUnavailable.Error())
		return
	}

	resp, err := s.registry.issueRegisterChallenge(req, domain, registerURI)
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

	claims, err := auth.VerifyLeaseAccessToken(req.AccessToken, s.identity.PublicKey, s.cfg.PortalURL, time.Now().UTC())
	if err != nil {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, errUnauthorized.Error())
		return
	}

	ttl := defaultLeaseTTL
	if req.TTL > 0 {
		ttl = time.Duration(req.TTL) * time.Second
	}
	record, err := s.registry.Renew(claims.Identity, ttl, clientIP, utils.SanitizeReportedIP(req.ReportedIP))
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	nextAccessToken, _, err := auth.IssueLeaseAccessToken(s.identity.PrivateKey, s.identity.Address, s.cfg.PortalURL, record.Copy(), ttl)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, err.Error())
		return
	}

	utils.WriteAPIData(w, http.StatusOK, types.RenewResponse{
		ExpiresAt:   record.ExpiresAt,
		AccessToken: nextAccessToken,
	})
}

func (s *Server) handleUnregister(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}

	req, ok := utils.DecodeJSONRequest[types.UnregisterRequest](w, r, defaultControlBodyLimit)
	if !ok {
		return
	}
	claims, err := auth.VerifyLeaseAccessToken(req.AccessToken, s.identity.PublicKey, s.cfg.PortalURL, time.Now().UTC())
	if err != nil {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, errUnauthorized.Error())
		return
	}

	record, err := s.registry.Unregister(claims.Identity)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	deleteCtx, cancel := context.WithTimeout(context.Background(), defaultClaimTimeout)
	defer cancel()
	if err := s.acmeManager.DeleteENSGaslessHostname(deleteCtx, record.Hostname); err != nil {
		log.Warn().
			Err(err).
			Str("hostname", record.Hostname).
			Str("address", record.Address).
			Msg("delete lease ens gasless txt")
	}
	if record != nil {
		record.Close()
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

	lease, err := s.admitLeaseByToken(token, false)
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

	s.registry.Touch(lease.Copy(), clientIP, time.Now())
	log.Info().
		Str("address", lease.Address).
		Str("lease_name", lease.Name).
		Str("remote_addr", remoteAddr).
		Int("ready", lease.stream.ReadyCount()).
		Msg("sdk reverse connected")
}

func (s *Server) handleQUICTunnelConn(conn *quic.Conn) {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		_ = conn.CloseWithError(1, "stream accept failed")
		return
	}

	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	var msg types.QUICControlMessage
	if err := json.NewDecoder(io.LimitReader(stream, defaultControlBodyLimit)).Decode(&msg); err != nil {
		_ = conn.CloseWithError(1, "control read failed")
		return
	}
	_ = stream.SetReadDeadline(time.Time{})
	if strings.TrimSpace(msg.AccessToken) == "" {
		_ = json.NewEncoder(stream).Encode(types.QUICControlResponse{OK: false, Error: "invalid_control_message"})
		_ = conn.CloseWithError(1, "invalid control message")
		return
	}

	rejectConn := func(code, reason string) {
		_ = json.NewEncoder(stream).Encode(types.QUICControlResponse{OK: false, Error: code})
		_ = conn.CloseWithError(1, reason)
	}

	lease, err := s.admitLeaseByToken(msg.AccessToken, true)
	if err != nil {
		code, reason := types.APIErrorCodeInvalidRequest, "invalid control message"
		for _, entry := range quicRejectTable {
			if errors.Is(err, entry.sentinel) {
				code, reason = entry.code, entry.reason
				break
			}
		}
		rejectConn(code, reason)
		return
	}

	if err := lease.datagram.Register(conn); err != nil {
		_ = json.NewEncoder(stream).Encode(types.QUICControlResponse{OK: false, Error: "broker_closed"})
		_ = conn.CloseWithError(1, "broker closed")
		return
	}

	_ = json.NewEncoder(stream).Encode(types.QUICControlResponse{OK: true})
	s.registry.Touch(lease.Copy(), conn.RemoteAddr().String(), time.Now())
	log.Info().
		Str("component", "quic-tunnel-listener").
		Str("address", lease.Address).
		Str("lease_name", lease.Name).
		Str("remote_addr", conn.RemoteAddr().String()).
		Msg("quic tunnel connected")
}

func (s *Server) admitLeaseByToken(token string, requireDatagram bool) (*leaseRecord, error) {
	claims, err := auth.VerifyLeaseAccessToken(token, s.identity.PublicKey, s.cfg.PortalURL, time.Now().UTC())
	if err != nil {
		return nil, errUnauthorized
	}
	lease, err := s.registry.Find(claims.Identity)
	if err != nil {
		return nil, err
	}
	if !s.registry.policy.IsIdentityRoutable(lease.Key()) {
		return nil, errLeaseRejected
	}
	if lease.stream == nil || (requireDatagram && lease.datagram == nil) {
		return nil, errTransportMismatch
	}
	return lease, nil
}

func (s *Server) registerLease(req types.RegisterChallengeRequest, clientIP, reportedIP string) (types.RegisterResponse, error) {
	identity, err := utils.NormalizeIdentity(req.Identity)
	if err != nil {
		return types.RegisterResponse{}, err
	}
	if s.registry.policy.IPFilter().IsIPBanned(clientIP) {
		return types.RegisterResponse{}, errIPBanned
	}
	hostname, err := utils.LeaseHostname(identity.Name, s.identity.Name)
	if err != nil {
		return types.RegisterResponse{}, err
	}

	ttl := defaultLeaseTTL
	if req.TTL > 0 {
		ttl = time.Duration(req.TTL) * time.Second
	}

	if req.UDPEnabled {
		if !s.cfg.UDPEnabled || s.group != nil && s.quicTunnel == nil {
			return types.RegisterResponse{}, errFeatureUnavailable
		}
		if !s.registry.policy.IsUDPEnabled() {
			return types.RegisterResponse{}, errUDPDisabled
		}
		if max := s.registry.policy.UDPMaxLeases(); max > 0 && s.registry.countDatagramLeases() >= max {
			return types.RegisterResponse{}, errUDPCapacityExceeded
		}
	}
	if req.TCPEnabled {
		if !s.cfg.TCPEnabled {
			return types.RegisterResponse{}, errFeatureUnavailable
		}
		if !s.registry.policy.IsTCPPortEnabled() {
			return types.RegisterResponse{}, errTCPPortDisabled
		}
		if max := s.registry.policy.TCPPortMaxLeases(); max > 0 && s.registry.countTCPPortLeases() >= max {
			return types.RegisterResponse{}, errTCPPortCapacityExceeded
		}
	}
	accessToken, claims, err := auth.IssueLeaseAccessToken(s.identity.PrivateKey, s.identity.Address, s.cfg.PortalURL, identity, ttl)
	if err != nil {
		return types.RegisterResponse{}, err
	}
	issuedAt := claims.IssuedAt.Time().UTC()
	expiresAt := claims.Expiry.Time().UTC()
	identityKey := identity.Key()
	stream := transport.NewRelayStream(identityKey, defaultIdleKeepalive, defaultReadyQueueLimit)
	record := &leaseRecord{
		Identity:    identity,
		Hostname:    hostname,
		Metadata:    req.Metadata.Copy(),
		ExpiresAt:   expiresAt,
		FirstSeenAt: issuedAt,
		LastSeenAt:  issuedAt,
		ClientIP:    clientIP,
		ReportedIP:  utils.SanitizeReportedIP(reportedIP),
		UDPEnabled:  req.UDPEnabled,
		TCPEnabled:  req.TCPEnabled,
		stream:      stream,
	}
	if req.UDPEnabled {
		if s.udpPorts == nil {
			return types.RegisterResponse{}, errors.New("udp port allocation not available")
		}
		port, err := s.udpPorts.Allocate(identity.Name)
		if err != nil {
			return types.RegisterResponse{}, err
		}
		record.datagram = transport.NewRelayDatagram(identityKey, port)
		record.udpPorts = s.udpPorts
	}
	if req.TCPEnabled {
		if s.tcpPorts == nil {
			return types.RegisterResponse{}, errors.New("tcp port allocation not available")
		}
		port, err := s.tcpPorts.Allocate(identity.Name)
		if err != nil {
			if errors.Is(err, transport.ErrPortExhausted) {
				return types.RegisterResponse{}, errTCPPortExhausted
			}
			return types.RegisterResponse{}, err
		}
		record.tcpPort = transport.NewRelayTCPPort(identityKey, port, stream, func(left, right net.Conn) {
			s.proxy.bridge(left, right, identityKey, s.registry.policy.BPSManager())
		})
		record.tcpPorts = s.tcpPorts
	}

	if err := record.Start(); err != nil {
		record.Close()
		return types.RegisterResponse{}, err
	}

	if err := s.registry.Register(record); err != nil {
		record.Close()
		return types.RegisterResponse{}, err
	}
	syncCtx, cancel := context.WithTimeout(context.Background(), defaultClaimTimeout)
	defer cancel()
	if err := s.acmeManager.SyncENSGaslessHostname(syncCtx, record.Hostname, record.Address); err != nil {
		_, _ = s.registry.Unregister(record.Copy())
		record.Close()
		return types.RegisterResponse{}, err
	}

	resp := types.RegisterResponse{
		Identity:    record.Copy(),
		Hostname:    hostname,
		ExpiresAt:   expiresAt,
		AccessToken: accessToken,
		UDPEnabled:  record.UDPEnabled,
		TCPEnabled:  record.TCPEnabled,
	}
	if record.datagram != nil {
		resp.SNIPort = s.cfg.SNIPort
		resp.UDPAddr = fmt.Sprintf("%s:%d", s.identity.Name, record.datagram.UDPPort())
	}
	if record.tcpPort != nil {
		resp.TCPAddr = fmt.Sprintf("%s:%d", s.identity.Name, record.tcpPort.TCPPort())
	}

	return resp, nil
}

func (s *Server) runAPIServer() error {
	err := s.apiServer.Serve(s.apiListener)
	if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
