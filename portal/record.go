package portal

import (
	"context"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
	"github.com/rs/zerolog/log"
)

type leaseRecord struct {
	types.Identity
	ExpiresAt      time.Time
	FirstSeenAt    time.Time
	LastSeenAt     time.Time
	ClientIP       string
	ReportedIP     string
	Hostname       string
	HostnameHash   string
	ECHConfigList  []byte
	ECHDNSHostname string
	Metadata       types.LeaseMetadata

	hopToken           string
	hopNextOverlayIPv4 string
	hopNextToken       string
	registerChallenge  *auth.RegisterChallenge

	datagram *transport.RelayDatagram
	udpPorts *transport.PortAllocator
	tcpPort  *transport.RelayTCPPort
	tcpPorts *transport.PortAllocator
	stream   *transport.RelayStream
}

func (r *leaseRecord) isPublicEntry() bool {
	return r != nil && r.hopToken == "" && r.Hostname != ""
}

func (r *leaseRecord) ensGaslessDNSHostname() string {
	if !r.isPublicEntry() {
		return ""
	}
	if len(r.ECHConfigList) > 0 && r.ECHDNSHostname != "" {
		return r.ECHDNSHostname
	}
	if r.HostnameHash == "" {
		return r.Hostname
	}
	return ""
}

func (r *leaseRecord) hasECHDNSRecord() bool {
	return r.isPublicEntry() && len(r.ECHConfigList) > 0 && r.ECHDNSHostname != ""
}

func (r *leaseRecord) isHopMiddle() bool {
	_, _, hasNextHop := r.nextHop()
	return r != nil && r.Hostname == "" && r.hopToken != "" && hasNextHop
}

func (r *leaseRecord) isHopExit() bool {
	_, _, hasNextHop := r.nextHop()
	return r != nil && r.hopToken != "" && !hasNextHop
}

func (r *leaseRecord) routesOverlap(other *leaseRecord) bool {
	if r == nil || other == nil {
		return false
	}
	if r.Hostname != "" && other.Hostname != "" && r.Hostname == other.Hostname {
		return true
	}
	if r.HostnameHash != "" && other.HostnameHash != "" && r.HostnameHash == other.HostnameHash {
		return true
	}
	if r.Hostname != "" && other.HostnameHash != "" && utils.HostnameHash(r.Hostname) == other.HostnameHash {
		return true
	}
	return other.Hostname != "" && r.HostnameHash != "" && utils.HostnameHash(other.Hostname) == r.HostnameHash
}

func (r *leaseRecord) nextHop() (string, string, bool) {
	if r == nil {
		return "", "", false
	}
	overlayIPv4 := r.hopNextOverlayIPv4
	forwardToken := r.hopNextToken
	return overlayIPv4, forwardToken, overlayIPv4 != "" || forwardToken != ""
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

func (r *leaseRecord) syncECHDNS(ctx context.Context, manager *acme.Manager, sniPort int) error {
	if r == nil || manager == nil || !r.hasECHDNSRecord() {
		return nil
	}
	return manager.SyncECHConfig(ctx, r.ECHDNSHostname, r.ECHConfigList, sniPort)
}

func (r *leaseRecord) deleteECHDNS(ctx context.Context, manager *acme.Manager) {
	if r == nil || manager == nil || !r.hasECHDNSRecord() {
		return
	}
	err := manager.DeleteECHConfig(ctx, r.ECHDNSHostname)
	if err != nil {
		log.Warn().
			Err(err).
			Str("hostname", r.ECHDNSHostname).
			Str("route_hostname", r.Hostname).
			Str("address", r.Address).
			Msg("delete ech dns record")
	}
}

func (r *leaseRecord) deleteDNS(ctx context.Context, manager *acme.Manager, includeECH bool) {
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
	if includeECH {
		r.deleteECHDNS(ctx, manager)
	}
}
