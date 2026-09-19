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

	datagram *transport.RelayDatagram
	udpPorts *transport.PortAllocator
	tcpPort  *transport.RelayTCPPort
	tcpPorts *transport.PortAllocator
	stream   *transport.RelayStream
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
	if r.datagram != nil {
		if err := r.datagram.Start(context.Background()); err != nil {
			return err
		}
	}
	if r.tcpPort != nil {
		return r.tcpPort.Start(context.Background())
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
