package portal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// relayBinding is a lease-local attachment, not a path or a separately installed
// route. Replacement is atomic; the remote lease token bounds its lifetime.
type relayBinding struct {
	peer      types.RelayDescriptor
	token     string
	expiresAt time.Time
}

// handleRelayBinding requires the local lease's access token and proof of access
// to a remote lease with the same tenant identity. Binding never authorizes an
// arbitrary destination and does not create a second lease lifecycle.
func (s *Server) handleRelayBinding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodDelete {
		utils.MethodNotAllowedError().Write(w)
		return
	}
	if s.overlay == nil {
		writeAPIErrorResponse(w, errFeatureUnavailable)
		return
	}
	record, err := s.registry.admitLeaseByToken(strings.TrimSpace(r.Header.Get(types.HeaderAccessToken)), false)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	if r.Method == http.MethodDelete {
		record.relayBinding.Store(nil)
		utils.WriteAPIData(w, http.StatusOK, map[string]bool{"attached": false})
		return
	}
	binding, ok := utils.DecodeJSONRequest[types.RelayBinding](w, r, 16<<10)
	if !ok {
		return
	}
	if binding.Relay.APIHTTPSAddr == s.config().PortalURL || binding.Relay.IVNPDestination == s.overlay.Destination() || strings.TrimSpace(binding.AccessToken) == "" {
		utils.InvalidRequestError(errors.New("a distinct relay and remote lease token are required")).Write(w)
		return
	}
	if record.datagram != nil || record.tcpPort != nil {
		utils.InvalidRequestError(errors.New("relay binding supports SNI streams only")).Write(w)
		return
	}
	remote, err := s.overlay.InspectLease(r.Context(), binding.Relay, binding.AccessToken)
	if err != nil {
		utils.InvalidRequestError(errors.New("remote lease is unavailable or unauthorized")).Write(w)
		return
	}
	if remote.Identity.Key() != record.Key() || !remote.ExpiresAt.After(time.Now()) {
		writeAPIErrorResponse(w, errUnauthorized)
		return
	}
	s.registry.mu.Lock()
	if s.registry.recordByKey(record.Key(), time.Now()) != record {
		s.registry.mu.Unlock()
		writeAPIErrorResponse(w, errLeaseNotFound)
		return
	}
	record.relayBinding.Store(&relayBinding{peer: binding.Relay, token: binding.AccessToken, expiresAt: remote.ExpiresAt})
	s.registry.mu.Unlock()
	utils.WriteAPIData(w, http.StatusOK, map[string]any{"attached": true, "expires_at": remote.ExpiresAt})
}

// handleOverlay runs only behind the I2P destination/Portal identity gate.
func (s *Server) handleOverlay(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case types.PathDiscovery:
		s.handleRelayDiscovery(w, r)
	case types.PathRelayLease, types.PathRelayConnect:
		method := http.MethodGet
		if r.URL.Path == types.PathRelayConnect {
			method = http.MethodConnect
		}
		if !utils.RequireMethod(w, r, method) {
			return
		}
		token := strings.TrimSpace(r.Header.Get(types.HeaderAccessToken))
		record, err := s.registry.admitLeaseByToken(token, false)
		if err != nil {
			writeAPIErrorResponse(w, err)
			return
		}
		// Inbound overlay streams always terminate at a local reverse backhaul.
		// They must never recurse through another binding, even during a concurrent update.
		if record.relayBinding.Load() != nil || record.datagram != nil || record.tcpPort != nil {
			writeAPIErrorResponse(w, errTransportMismatch)
			return
		}
		if r.URL.Path == types.PathRelayLease {
			claims, err := auth.VerifyLeaseAccessToken(token, s.authority.Identity().PublicKey, s.registry.tokenIssuer, time.Now())
			if err != nil {
				writeAPIErrorResponse(w, errUnauthorized)
				return
			}
			s.registry.mu.RLock()
			expiry := record.ExpiresAt
			s.registry.mu.RUnlock()
			if claims.Expiry.Time().Before(expiry) {
				expiry = claims.Expiry.Time()
			}
			utils.WriteAPIData(w, http.StatusOK, types.RelayLeaseResponse{Identity: record.Identity.Copy(), ExpiresAt: expiry})
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			writeAPIErrorResponse(w, errFeatureUnavailable)
			return
		}
		conn, rw, err := hijacker.Hijack()
		if err != nil {
			return
		}
		// The connector waits for acceptance before sending tenant bytes.
		if rw.Reader.Buffered() != 0 {
			_ = conn.Close()
			return
		}
		if _, err = fmt.Fprintf(rw, "HTTP/1.1 200 Connection Established\r\n%s: %s\r\n\r\n", types.HeaderRelayDescriptor, w.Header().Get(types.HeaderRelayDescriptor)); err != nil {
			_ = conn.Close()
			return
		}
		if err = rw.Flush(); err != nil {
			_ = conn.Close()
			return
		}
		_ = conn.SetDeadline(time.Time{})
		if err := s.bridgeLocalLeaseConn(r.Context(), conn, record); err != nil {
			_ = conn.Close()
		}
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) bridgeLeaseConn(ctx context.Context, conn net.Conn, record *leaseRecord) error {
	binding := record.relayBinding.Load()
	if binding == nil {
		return s.bridgeLocalLeaseConn(ctx, conn, record)
	}
	if record.isExpired(time.Now()) || !binding.expiresAt.After(time.Now()) {
		return errLeaseNotFound
	}
	if !s.registry.policy.IsIdentityRoutable(record.Key()) {
		return errLeaseRejected
	}
	if s.overlay == nil {
		return errFeatureUnavailable
	}
	remote, err := s.overlay.OpenStream(ctx, binding.peer, binding.token)
	if err != nil {
		return fmt.Errorf("open relay stream: %w", err)
	}
	s.proxy.bridge(conn, remote, record.Key(), s.registry.policy.BPSManager())
	return nil
}
