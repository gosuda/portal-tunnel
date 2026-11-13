package portal

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

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
	errLeaseTTLExceeded         = &apiError{types.APIErrorCodeInvalidRequest, "lease TTL exceeds 10 minutes", http.StatusBadRequest}
	errLeaseRejected            = &apiError{types.APIErrorCodeLeaseRejected, "lease is not approved for routing", http.StatusForbidden}
	errLeaseDenied              = &apiError{types.APIErrorCodeLeaseDenied, "lease is denied by the relay", http.StatusForbidden}
	errTransportMismatch        = &apiError{types.APIErrorCodeTransportMismatch, "transport mismatch", http.StatusConflict}
	errUnauthorized             = &apiError{types.APIErrorCodeUnauthorized, "unauthorized", http.StatusForbidden}
	errUDPDisabled              = &apiError{types.APIErrorCodeUDPDisabled, "udp disabled", http.StatusForbidden}
	errUDPCapacityExceeded      = &apiError{types.APIErrorCodeUDPCapacityExceeded, "udp capacity exceeded", http.StatusServiceUnavailable}
	errUDPPortExhausted         = &apiError{types.APIErrorCodeUDPPortExhausted, "no udp ports available", http.StatusServiceUnavailable}
	errTCPPortDisabled          = &apiError{types.APIErrorCodeTCPPortDisabled, "tcp port disabled", http.StatusForbidden}
	errTCPPortCapacityExceeded  = &apiError{types.APIErrorCodeTCPPortCapacityExceeded, "tcp port capacity exceeded", http.StatusServiceUnavailable}
	errTCPPortExhausted         = &apiError{types.APIErrorCodeTCPPortExhausted, "no tcp ports available", http.StatusServiceUnavailable}
	errRegisterChallengePending = &apiError{types.APIErrorCodeRateLimited, "too many pending register challenges", http.StatusTooManyRequests}
	errUnapprovedLeaseLimit     = &apiError{types.APIErrorCodeRateLimited, "too many unapproved leases from this source", http.StatusTooManyRequests}
)

const unapprovedLeaseRetryAfter = "300"

func writeAPIErrorResponse(w http.ResponseWriter, err error) {
	if ae, ok := errors.AsType[*apiError](err); ok {
		utils.WriteAPIError(w, ae.status, ae.code, ae.msg)
		return
	}
	utils.InvalidRequestError(err).Write(w)
}

func (s *Server) newAPIServer(handler http.Handler, apiTLS *tls.Config) (*http.Server, io.Closer, error) {
	if s.acmeManager.TLSMaterial() != nil {
		signer, err := keyless.NewSigner(s.registry.bindings, s.acmeManager.SigningKey)
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
	if mux, ok := base.(*http.ServeMux); ok && mux == nil {
		base = nil
	}
	if base == nil {
		mux := http.NewServeMux()
		mux.HandleFunc("/{$}", s.HandleRoot)
		base = mux
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := utils.NormalizeHostWithoutPort(r.Host)
		if r.TLS != nil && r.TLS.ServerName != "" && utils.NormalizeHostname(r.TLS.ServerName) != s.identity.Name {
			s.serveCachedSite(w, r, host)
			return
		}
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

	writeDiscoveryResponse(w, types.DiscoveryResponse{
		ProtocolVersion:      types.DiscoveryVersion,
		GeneratedAt:          now,
		Relays:               s.relaySet.Descriptors(self),
		IncompatibleRelays:   s.relaySet.KnownIncompatibleRelays(),
		ReleaseVersion:       types.ReleaseVersion,
		RelayReleaseVersions: s.relaySet.KnownRelayReleaseVersions(),
	})
}

func writeDiscoveryResponse(w http.ResponseWriter, response types.DiscoveryResponse) {
	response.Relays = response.Relays[:min(len(response.Relays), types.MaxDiscoveryEntries+1)]
	encoded, err := json.Marshal(types.APIEnvelope[types.DiscoveryResponse]{OK: true, Data: response})
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, err.Error())
		return
	}
	if int64(len(encoded)) > types.MaxDiscoveryResponseBytes {
		var ok bool
		encoded, ok = fitWriteDiscoveryResponse(w, response)
		if !ok {
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

func fitWriteDiscoveryResponse(w http.ResponseWriter, response types.DiscoveryResponse) ([]byte, bool) {
	response.IncompatibleRelays = nil
	response.RelayReleaseVersions = nil
	var encoded []byte
	for low, high := 1, len(response.Relays); low <= high; {
		count := low + (high-low)/2
		candidate := response
		candidate.Relays = response.Relays[:count]
		body, err := json.Marshal(types.APIEnvelope[types.DiscoveryResponse]{OK: true, Data: candidate})
		if err != nil {
			utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, err.Error())
			return nil, false
		}
		if int64(len(body)) > types.MaxDiscoveryResponseBytes {
			high = count - 1
		} else {
			encoded = body
			low = count + 1
		}
	}
	if encoded == nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "self descriptor exceeds discovery response limit")
		return nil, false
	}
	return encoded, true
}

func (s *Server) HandleRelayDiscoveryAnnounce(w http.ResponseWriter, r *http.Request, sourceAddr netip.Addr) {
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
	announceURL, err := url.Parse(desc.APIHTTPSAddr)
	if err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
		return
	}
	host := utils.NormalizeHostname(announceURL.Hostname())
	if s.rejectAnnounceSelf(w, desc, host) {
		return
	}

	now := time.Now().UTC()
	if err := s.relaySet.InsertCandidate(desc, now); err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
		return
	}
	sourceIP := "<unknown>"
	if sourceAddr.IsValid() {
		sourceIP = sourceAddr.String()
	}

	log.Info().
		Str("relay", desc.APIHTTPSAddr).
		Str("source_ip", sourceIP).
		Msg("relay discovery announce accepted")

	utils.WriteAPIData(w, http.StatusAccepted, types.DiscoveryAnnounceResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Accepted:        true,
	})
}

func (s *Server) rejectAnnounceSelf(w http.ResponseWriter, desc types.RelayDescriptor, host string) bool {
	cfg := s.config()
	if selfURL, err := utils.NormalizeRelayURL(cfg.PortalURL); err == nil && desc.APIHTTPSAddr == selfURL {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest,
			fmt.Sprintf("self-announce rejected: %q matches receiving relay url", desc.APIHTTPSAddr))
		return true
	}
	if host != "" && host == utils.NormalizeHostname(s.identity.Name) {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest,
			fmt.Sprintf("self-announce rejected: host %q matches receiving relay host", host))
		return true
	}
	return false
}

// DomainReport returns the relay-owned /sdk/domain payload. An
// application that sets ServerConfig.ApplicationOwnsDomainReport composes its
// own metadata onto this value and serves the result itself. x402
// facilitator metadata is owned by the application that mounts the
// facilitator (cmd/relay-server); this report stays x402-blind.
func (s *Server) DomainReport() types.DomainResponse {
	issuance := s.acmeManager != nil && s.config().TenantCertificates
	return types.DomainResponse{
		TenantCertificateIssuance: &issuance,
		Namespaces:                []string{types.LocalTLSNamespaceV1},
		Cache:                     s.registry.cache.Limits(),
		ProtocolVersion:           types.SDKVersion,
		ReleaseVersion:            types.ReleaseVersion,
		ENS:                       s.acmeManager.ENSStatus(),
	}
}

func (s *Server) HandleDomain(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	utils.WriteAPIData(w, http.StatusOK, s.DomainReport())
}

// HandleCertificateChain serves the public chain already presented by the relay's
// TLS endpoint to runtimes whose TLS stack does not expose peer certificates.
func (s *Server) HandleCertificateChain(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	material := s.acmeManager.TLSMaterial()
	if material == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(material.CertPEM)
}

// HandleRegister completes a verified registration without publishing the
// success response. The relay first applies the returned identity's access
// decision, then writes the response so the lease cannot become observable
// before its routability is known.
