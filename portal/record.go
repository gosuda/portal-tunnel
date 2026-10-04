package portal

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
)

type leaseRecord struct {
	types.Identity
	id                string
	ExpiresAt         time.Time
	FirstSeenAt       time.Time
	LastSeenAt        time.Time
	ClientIP          string
	ReportedIP        string
	Hostname          string
	CanonicalHostname string
	Metadata          types.LeaseMetadata
	Overlay           bool

	registerChallenge *identity.RegisterChallenge

	datagram *transport.RelayDatagram
	udpPorts *transport.PortAllocator
	tcpPort  *transport.RelayTCPPort
	tcpPorts *transport.PortAllocator
	stream   *transport.RelayStream
}

// cacheLease adapts registry facts to the cache's canonical hostname key while
// the caller holds the registry lock.
func (r *leaseRecord) cacheLease() cache.Lease {
	return cache.Lease{ID: r.id, Owner: r.Key(), Hostname: r.CanonicalHostname, ExpiresAt: r.ExpiresAt, LastSeenAt: r.LastSeenAt}
}

func (r *leaseRecord) isPublicEntry() bool {
	return r != nil && r.CanonicalHostname != ""
}

func (r *leaseRecord) hostnames() []string {
	if !r.isPublicEntry() {
		return nil
	}
	hostnames := []string{r.CanonicalHostname}
	if r.Hostname != "" {
		hostnames = append(hostnames, r.Hostname)
	}
	return hostnames
}

func (r *leaseRecord) isExpired(now time.Time) bool {
	return r != nil && !now.IsZero() && !now.Before(r.ExpiresAt)
}

func (r *leaseRecord) Start() error {
	if r.datagram != nil {
		if err := r.datagram.Start(context.Background()); err != nil {
			return err
		}
	}
	if r.tcpPort != nil {
		return r.tcpPort.Start()
	}
	return nil
}

func (r *leaseRecord) Close() {
	if r == nil {
		return
	}
	if r.stream != nil {
		r.stream.Close()
	}
	if r.datagram != nil {
		port := r.datagram.UDPPort()
		r.datagram.Close()
		if port > 0 && r.udpPorts != nil {
			r.udpPorts.Release(port)
		}
	}
	if r.tcpPort != nil {
		port := r.tcpPort.TCPPort()
		r.tcpPort.Close()
		if port > 0 && r.tcpPorts != nil {
			r.tcpPorts.Release(port)
		}
	}
}

func (r *leaseRecord) syncENSGaslessDNS(ctx context.Context, manager *acme.Manager) error {
	if r == nil || manager == nil {
		return nil
	}
	for _, hostname := range r.hostnames() {
		if err := manager.SyncENSGaslessHostname(ctx, hostname, r.Address); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) syncLeaseDNS(ctx context.Context, record *leaseRecord) error {
	if s == nil || record == nil || s.registry == nil {
		return nil
	}
	registry := s.registry
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	// Queue DNS sync while the lease is still the current live record. A
	// concurrent unregister/expiry must either happen after this enqueue or
	// make this stale sync a no-op.
	if !registry.containsLiveRecordLocked(record, time.Now()) {
		return nil
	}
	return record.syncENSGaslessDNS(ctx, s.acmeManager)
}

func (s *Server) deleteLeaseDNS(ctx context.Context, record *leaseRecord) {
	if s == nil || record == nil || s.acmeManager == nil || s.registry == nil {
		return
	}
	registry := s.registry
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	now := time.Now()

	for _, hostname := range record.hostnames() {
		if registry.ownsHostnameLocked(hostname, now) {
			continue
		}
		// Delete is an enqueue-only operation. Keeping the registry read lock
		// through the enqueue orders this command against lease registration's
		// write lock and its later DNS sync enqueue.
		err := s.acmeManager.DeleteENSGaslessHostname(ctx, hostname)
		if err != nil {
			log.Warn().
				Err(err).
				Str("hostname", hostname).
				Str("address", record.Address).
				Msg("delete ens gasless hostname")
		}
	}
}
