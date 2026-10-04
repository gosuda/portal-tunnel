package portal

import (
	"context"
	"net"
	"net/netip"
	"sync"
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
	sourceAddr        netip.Addr
	ReportedIP        string
	Hostname          string
	CanonicalHostname string
	Metadata          types.LeaseMetadata
	Overlay           bool

	registerChallenge *identity.RegisterChallenge

	datagram    *transport.RelayDatagram
	tcpPort     int
	tcpListener net.Listener
	reverse     *transport.ReversePool

	mu         sync.Mutex
	closed     bool
	reverseMux *transport.ReverseMux
}

// cacheLease adapts registry facts to the cache's canonical hostname key while
// the caller holds the registry lock.
func (r *leaseRecord) cacheLease() cache.Lease {
	return cache.Lease{ID: r.id, Owner: r.ServiceKey(), Hostname: r.CanonicalHostname, ExpiresAt: r.ExpiresAt, LastSeenAt: r.LastSeenAt}
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
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return net.ErrClosed
	}
	if r.datagram != nil {
		if err := r.datagram.Start(); err != nil {
			return err
		}
	}
	if r.tcpPort > 0 && r.tcpListener == nil {
		listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: r.tcpPort})
		if err != nil {
			return err
		}
		r.tcpListener = listener
	}
	return nil
}

func (r *leaseRecord) Close() {
	if r == nil {
		return
	}
	// Serialize the entire close so registry cleanup cannot release ports
	// while another caller is still shutting down their sockets.
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	mux := r.reverseMux
	r.reverseMux = nil
	listener := r.tcpListener
	if listener != nil {
		_ = listener.Close()
	}
	if mux != nil {
		_ = mux.Close()
	}
	if r.reverse != nil {
		r.reverse.Close()
	}
	if r.datagram != nil {
		r.datagram.Close()
	}
}

// attachReverseMux replaces the lease's carrier without letting a late release
// from the old handler detach the replacement. A closed lease refuses ownership.
func (r *leaseRecord) attachReverseMux(mux *transport.ReverseMux) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	previous := r.reverseMux
	r.reverseMux = mux
	r.mu.Unlock()
	if previous != nil && previous != mux {
		_ = previous.Close()
	}
	return nil
}

func (r *leaseRecord) detachReverseMux(mux *transport.ReverseMux) {
	r.mu.Lock()
	if r.reverseMux == mux {
		r.reverseMux = nil
	}
	r.mu.Unlock()
	_ = mux.Close()
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
	if registry.recordByLease(record.ServiceKey(), record.id, time.Now()) != record {
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
		owned := false
		for _, current := range registry.records {
			if current == nil || current.isExpired(now) {
				continue
			}
			for _, currentHostname := range current.hostnames() {
				if currentHostname == hostname {
					owned = true
					break
				}
			}
			if owned {
				break
			}
		}
		if owned {
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
