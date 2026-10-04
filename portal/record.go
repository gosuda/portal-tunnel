package portal

import (
	"context"
	"net"
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
	id          string
	ExpiresAt   time.Time
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	ClientIP    string
	ReportedIP  string
	Hostname    string
	Metadata    types.LeaseMetadata
	Overlay     bool

	registerChallenge *identity.RegisterChallenge

	datagram    *transport.RelayDatagram
	udpPorts    *portPool
	tcpPort     int
	tcpListener net.Listener
	tcpPorts    *portPool
	reverse     *transport.ReversePool

	mu         sync.Mutex
	closed     bool
	reverseMux *transport.ReverseMux
}

// cacheLease copies registry facts while the caller holds the registry lock.
func (r *leaseRecord) cacheLease() cache.Lease {
	return cache.Lease{ID: r.id, Owner: r.Key(), Hostname: r.Hostname, ExpiresAt: r.ExpiresAt, LastSeenAt: r.LastSeenAt}
}

func (r *leaseRecord) isPublicEntry() bool {
	return r != nil && r.Hostname != ""
}

func (r *leaseRecord) ensGaslessDNSHostname() string {
	if !r.isPublicEntry() {
		return ""
	}
	return r.Hostname
}

func (r *leaseRecord) routesOverlap(other *leaseRecord) bool {
	if r == nil || other == nil {
		return false
	}
	if r.Hostname != "" && other.Hostname != "" && r.Hostname == other.Hostname {
		return true
	}
	return false
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
		r.mu.Unlock()
		return
	}
	r.closed = true
	mux := r.reverseMux
	r.reverseMux = nil
	listener := r.tcpListener
	r.mu.Unlock()
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
		port := r.datagram.UDPPort()
		r.datagram.Close()
		if port > 0 && r.udpPorts != nil {
			r.udpPorts.release(port)
		}
	}
	if r.tcpPort > 0 && r.tcpPorts != nil {
		r.tcpPorts.release(r.tcpPort)
	}
}

// attachReverseMux replaces the lease's carrier without letting a late release
// from the old handler detach the replacement. A closed lease refuses ownership.
func (r *leaseRecord) attachReverseMux(mux *transport.ReverseMux) (func(), error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, net.ErrClosed
	}
	previous := r.reverseMux
	r.reverseMux = mux
	r.mu.Unlock()
	if previous != nil && previous != mux {
		_ = previous.Close()
	}
	return func() {
		r.mu.Lock()
		if r.reverseMux == mux {
			r.reverseMux = nil
		}
		r.mu.Unlock()
		_ = mux.Close()
	}, nil
}

func (r *leaseRecord) syncENSGaslessDNS(ctx context.Context, manager *acme.Manager) error {
	if r == nil || manager == nil {
		return nil
	}
	if ensHostname := r.ensGaslessDNSHostname(); ensHostname != "" {
		if err := manager.SyncENSGaslessHostname(ctx, ensHostname, r.Address); err != nil {
			return err
		}
	}
	return nil
}

func (r *leaseRecord) deleteDNS(ctx context.Context, manager *acme.Manager) {
	if r == nil || manager == nil {
		return
	}
	if ensHostname := r.ensGaslessDNSHostname(); ensHostname != "" {
		err := manager.DeleteENSGaslessHostname(ctx, ensHostname)
		if err != nil {
			log.Warn().
				Err(err).
				Str("hostname", ensHostname).
				Str("address", r.Address).
				Msg("delete ens gasless hostname")
		}
	}
}
