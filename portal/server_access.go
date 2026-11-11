package portal

import (
	"slices"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func (s *Server) SetServiceIdentityAccess(key types.ServiceIdentityKey, access types.LeaseAccess, revision uint64) bool {
	if s == nil || s.registry == nil {
		return true
	}
	return s.registry.setIdentityAccess(key, access, revision)
}

// DiscoveryEnabled and ApplicationOwnsDomainReport report the routing flags
// the relay's composed route table dispatches on.
func (s *Server) DiscoveryEnabled() bool {
	return s.config().DiscoveryEnabled
}

func (s *Server) ApplicationOwnsDomainReport() bool {
	return s.config().ApplicationOwnsDomainReport
}

// BPSManager is the portal-owned per-identity traffic shaper configured by
// the relay's operator surface.
func (s *Server) BPSManager() *BPSManager {
	if s == nil || s.registry == nil {
		return nil
	}
	return s.registry.bps
}

func (s *Server) PortalURL() string {
	if s == nil {
		return ""
	}
	return s.config().PortalURL
}

func (s *Server) PublicLeases() []types.Lease {
	if s == nil || s.registry == nil {
		return nil
	}
	return s.registry.PublicLeases(time.Now())
}

func (s *Server) PolicyLeases() []types.PolicyLease {
	if s == nil || s.registry == nil {
		return nil
	}
	return s.registry.PolicyLeases(time.Now())
}

// ServerStats is a point-in-time operational snapshot. Active leases exclude
// expired registrations; active connections count currently bridged HTTP/SNI
// and raw TCP streams, including overlay streams. ActiveUDPFlows counts tracked
// flows on active leases, including idle flows until their normal expiry.
// ForwardedBytes counts successful HTTP/SNI and raw TCP stream writes in both
// directions (including overlay), excluding UDP payloads. It is cumulative
// for this Server instance and resets when a new Server is created.
// Fields are read independently, so concurrent traffic may advance between
// reads; the snapshot is not an atomic transaction.
type ServerStats struct {
	ActiveLeases      int64
	ActiveConnections int64
	ActiveUDPFlows    int64
	ForwardedBytes    int64
}

// Stats returns bounded, aggregate relay state without tenant identifiers.
// A nil or uninitialized Server has zero stats.
func (s *Server) Stats() ServerStats {
	if s == nil {
		return ServerStats{}
	}
	var stats ServerStats
	if s.registry != nil {
		stats.ActiveLeases, stats.ActiveUDPFlows = s.registry.stats(time.Now())
	}
	stats.ActiveConnections = s.proxy.activeConnectionCount()
	stats.ForwardedBytes = s.proxy.tcpBytes.Load()
	return stats
}

// AccessProjectionKeys returns identities whose live lease or retained cache
// content needs the relay's current access decision.
func (s *Server) AccessProjectionKeys() []types.ServiceIdentityKey {
	if s == nil || s.registry == nil {
		return nil
	}
	keys := make(map[types.ServiceIdentityKey]struct{})
	now := time.Now()
	s.registry.mu.RLock()
	for _, record := range s.registry.records {
		if record != nil && record.reverse != nil && !record.isExpired(now) {
			keys[record.ServiceKey()] = struct{}{}
		}
	}
	s.registry.mu.RUnlock()
	for _, owner := range s.registry.cache.Owners() {
		keys[owner] = struct{}{}
	}
	out := make([]types.ServiceIdentityKey, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	slices.SortFunc(out, func(a, b types.ServiceIdentityKey) int {
		return strings.Compare(a.String(), b.String())
	})
	return out
}

func (s *Server) RelayIdentity() identity.RelayIdentity {
	if s == nil {
		return identity.RelayIdentity{}
	}
	return s.identity
}
