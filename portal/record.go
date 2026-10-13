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
	closeDone  chan struct{}
	reverseMux *transport.ReverseMux
	bridges    map[*leaseBridge]struct{}
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
	r.mu.Lock()
	if r.closed {
		done := r.closeDone
		r.mu.Unlock()
		if done != nil {
			<-done
		}
		return
	}
	r.closed = true
	r.closeDone = make(chan struct{})
	r.revokeBridgesLocked()
	bridges := make([]*leaseBridge, 0, len(r.bridges))
	for bridge := range r.bridges {
		bridges = append(bridges, bridge)
	}
	mux := r.reverseMux
	r.reverseMux = nil
	listener := r.tcpListener
	r.mu.Unlock()
	// Socket shutdown must not hold the registry or record mutex. Concurrent
	// Close callers wait for completion before the registry reuses the ports.
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
	for _, bridge := range bridges {
		r.releaseBridge(bridge)
	}
	close(r.closeDone)
}

// leaseBridge owns a public connection from reverse acquisition through the
// active bridge. The record mutex protects its endpoints and membership.
type leaseBridge struct {
	ctx     context.Context
	cancel  context.CancelFunc
	inbound net.Conn
	reverse net.Conn
}

func (r *leaseRecord) releaseBridge(bridge *leaseBridge) {
	r.mu.Lock()
	bridge.cancel()
	inbound, reverse := bridge.inbound, bridge.reverse
	r.mu.Unlock()
	_ = inbound.SetDeadline(time.Now())
	_ = inbound.Close()
	if reverse != nil {
		_ = reverse.SetDeadline(time.Now())
		_ = reverse.Close()
	}
	r.mu.Lock()
	delete(r.bridges, bridge)
	r.mu.Unlock()
}

// Keep revoked workers counted until they finish; allowing the identity again
// admits only new reservations, never revives a canceled bridge. Deadlines
// interrupt current I/O, but a subsequent framing write can replace its write
// deadline with the helper's five-second limit. Workers close endpoints outside
// these locks and cannot copy application data with the canceled context.
func (r *leaseRecord) revokeBridgesLocked() {
	for bridge := range r.bridges {
		bridge.cancel()
		_ = bridge.inbound.SetDeadline(time.Now())
		if bridge.reverse != nil {
			_ = bridge.reverse.SetDeadline(time.Now())
		}
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
