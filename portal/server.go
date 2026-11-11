package portal

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/overlay"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errDefaultIdentityBPSMustNonNegative         = errors.New("default identity bps must be non-negative")
	errHTTPRedirectRequiresPortalURLAbsolute     = errors.New("http redirect requires PORTAL_URL to be an absolute HTTPS URL without credentials")
	errHTTPRedirectPortalURLPortMust             = errors.New("http redirect PORTAL_URL port must be between 1 and 65535")
	errHTTPRedirectHTTPRedirectAddrHas           = errors.New("http redirect HTTP_REDIRECT_ADDR has an invalid host")
	errHTTPRedirectHTTPRedirectAddrPort          = errors.New("http redirect HTTP_REDIRECT_ADDR port must be between 0 and 65535")
	errRelayOverlayRequiresDiscovery             = errors.New("relay overlay requires discovery")
	errStateDirectoryIsRequired                  = errors.New("state directory is required")
	errRootHostIsRequired                        = errors.New("root host is required")
	errTransportMaxLeasesMustNonNegative         = errors.New("transport max leases must be non-negative")
	errUnapprovedLeaseLimitNegative              = errors.New("unapproved leases per source must be non-negative")
	errTransportEnablementRequiresLeasePortRange = errors.New("transport enablement requires a lease port range")
	errEnablingUDPRequiresRelayRestart           = errors.New("enabling udp requires a relay restart")
	errServerAlreadyStarted                      = errors.New("server already started")
	errJanitorIntervalMustBePositive             = errors.New("janitor interval must be positive")
)

type Server struct {
	cancel       context.CancelFunc
	group        *errgroup.Group
	shutdownOnce sync.Once

	ingressCtx        context.Context
	ingressMu         sync.Mutex
	ingressClosed     bool
	ingressConns      map[net.Conn]struct{}
	ingressInspecting int
	ingressTenants    int
	ingressWorkers    sync.WaitGroup

	cfg         *utils.Snapshot[ServerConfig]
	identity    identity.RelayIdentity
	authority   identity.Authority
	acmeManager *acme.Manager
	proxy       proxy
	signer      *keyless.Signer

	apiHandoff       *handoffListener
	sniListener      net.Listener
	apiServer        *http.Server
	apiTLSClose      io.Closer
	redirectListener net.Listener
	redirectServer   *http.Server
	quicBackhaul     *quic.Listener
	quicBackhaulDone chan struct{}

	relaySet *discovery.RelaySet
	registry *leaseRegistry
	overlay  *overlay.Runtime
}

func (s *Server) config() ServerConfig {
	return s.cfg.Load()
}

// SetTransportPolicy applies relay-owned transport enablement and capacity
// values to lease enforcement. Disabling UDP takes effect immediately: the
// QUIC backhaul listener keeps serving live transports, but the registry
// stops admitting new UDP leases. Enabling UDP at runtime is refused when no
// backhaul listener exists, since a listener cannot be created post-start.
func (s *Server) SetTransportPolicy(udpEnabled bool, udpMaxLeases int, tcpEnabled bool, tcpMaxLeases int) error {
	if err := s.ValidateTransportPolicy(udpEnabled, udpMaxLeases, tcpEnabled, tcpMaxLeases); err != nil {
		return err
	}
	s.registry.setTransportPolicy(udpEnabled, udpMaxLeases, tcpEnabled, tcpMaxLeases)
	return nil
}

// ValidateTransportPolicy checks whether a policy can be applied without
// changing enforcement. The relay can reject unsupported settings before
// persisting them. Runtime UDP availability is fixed once the server starts.
func (s *Server) ValidateTransportPolicy(udpEnabled bool, udpMaxLeases int, tcpEnabled bool, tcpMaxLeases int) error {
	cfg := s.config()
	if err := cfg.ValidateTransportPolicy(udpEnabled, udpMaxLeases, tcpEnabled, tcpMaxLeases); err != nil {
		return err
	}
	if s.group != nil && udpEnabled && s.quicBackhaul == nil {
		return errEnablingUDPRequiresRelayRestart
	}
	return nil
}

func (s *Server) supportsUDP() bool {
	enabled, _ := s.registry.udpPolicy()
	if !enabled {
		return false
	}
	return s.group == nil || s.quicBackhaul != nil
}

func (s *Server) supportsTCP() bool {
	enabled, _ := s.registry.tcpPortPolicy()
	return enabled
}
