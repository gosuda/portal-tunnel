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
	"github.com/gosuda/portal-tunnel/v2/portal/namespace"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
)

type leaseRecord struct {
	types.Identity
	id                      string
	ExpiresAt               time.Time
	FirstSeenAt             time.Time
	LastSeenAt              time.Time
	sourceAddr              netip.Addr
	registerSource          netip.Addr
	ReportedIP              string
	Hostname                string
	Namespace               string
	LegacyCanonicalHostname string
	CanonicalHostname       string
	localTLSNotAfter        time.Time
	Metadata                types.LeaseMetadata
	Overlay                 bool
	pinnedChain             []byte
	verifiedChain           []byte

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

func (r *leaseRecord) cacheLeaseLocked() cache.Lease {
	hostname := r.CanonicalHostname
	if r.Namespace == types.LocalTLSNamespaceV1 {
		hostname = r.LegacyCanonicalHostname
	}
	return cache.Lease{ID: r.id, Owner: r.ServiceKey(), Hostname: hostname, ExpiresAt: r.ExpiresAt, LastSeenAt: r.LastSeenAt}
}

func (r *leaseRecord) isPublicEntry() bool {
	return r != nil && r.CanonicalHostname != ""
}

func (r *leaseRecord) hostnames() []string {
	if !r.isPublicEntry() {
		return nil
	}
	hostnames := []string{r.CanonicalHostname}
	if r.LegacyCanonicalHostname != "" {
		hostnames = append(hostnames, r.LegacyCanonicalHostname)
	}
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

func (r *leaseRecord) revokeBridgesLocked() {
	for bridge := range r.bridges {
		bridge.cancel()
		_ = bridge.inbound.SetDeadline(time.Now())
		if bridge.reverse != nil {
			_ = bridge.reverse.SetDeadline(time.Now())
		}
	}
}

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
		if err := manager.SyncLeaseHostname(ctx, hostname, r.Address); err != nil {
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

	if registry.recordByLease(record.ServiceKey(), record.id, time.Now()) != record {
		return nil
	}
	return record.syncENSGaslessDNS(ctx, s.acmeManager)
}

// dnsAddressParent is shared by Local TLS services using the same wallet.
// It is not a routed hostname unless an unnamed lease owns it.
func (r *leaseRecord) dnsAddressParent() string {
	if r == nil || r.Namespace != types.LocalTLSNamespaceV1 {
		return ""
	}
	return namespace.AddressParent(r.CanonicalHostname)
}

func (s *Server) isDNSHostnameOwnedLocked(hostname string, now time.Time) bool {
	for _, current := range s.registry.records {
		if current == nil || current.isExpired(now) {
			continue
		}
		if current.dnsAddressParent() == hostname {
			return true
		}
		for _, currentHostname := range current.hostnames() {
			if currentHostname == hostname {
				return true
			}
		}
	}
	return false
}

func (s *Server) deleteLeaseDNS(ctx context.Context, record *leaseRecord) {
	if s == nil || record == nil || s.acmeManager == nil || s.registry == nil {
		return
	}
	registry := s.registry
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	now := time.Now()

	hostnames := record.hostnames()
	if parent := record.dnsAddressParent(); parent != "" && parent != record.LegacyCanonicalHostname {
		hostnames = append(hostnames, parent)
	}
	for _, hostname := range hostnames {
		if s.isDNSHostnameOwnedLocked(hostname, now) {
			continue
		}
		// Delete is an enqueue-only operation. Keeping the registry read lock
		// through the enqueue orders this command against lease registration's
		// write lock and its later DNS sync enqueue.
		err := s.acmeManager.DeleteLeaseHostname(ctx, hostname)
		if err != nil {
			log.Warn().
				Err(err).
				Str("hostname", hostname).
				Str("address", record.Address).
				Msg("delete ens gasless hostname")
		}
	}
}
