package portal

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/keyless_tls/relay/l4"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/overlay"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
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

const (
	defaultClaimTimeout          = 10 * time.Second
	replicaWaitSlice             = 250 * time.Millisecond
	defaultClientHelloWait       = 2 * time.Second
	defaultControlBodyLimit      = 4 << 20
	reverseOfferAdmissionWorkers = 16
	quicBackhaulPendingLimit     = 64
	quicBackhaulAuthTimeout      = 3 * time.Second
	quicBackhaulPerSourceLimit   = 4
	publicIngressLimit           = 1024
	publicInspectionLimit        = 128
)

type backhaulPendingSources struct {
	mu     sync.Mutex
	counts map[netip.Prefix]int
}

func newBackhaulPendingSources() *backhaulPendingSources {
	return &backhaulPendingSources{counts: make(map[netip.Prefix]int)}
}

func (p *backhaulPendingSources) acquire(remote net.Addr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	prefix, ok := backhaulSourcePrefix(remote)
	if !ok {
		return true
	}
	if p.counts[prefix] >= quicBackhaulPerSourceLimit {
		return false
	}
	p.counts[prefix]++
	return true
}

func (p *backhaulPendingSources) release(remote net.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	prefix, ok := backhaulSourcePrefix(remote)
	if !ok {
		return
	}
	if p.counts[prefix]--; p.counts[prefix] <= 0 {
		delete(p.counts, prefix)
	}
}

func backhaulSourcePrefix(remote net.Addr) (netip.Prefix, bool) {
	addrPort, err := netip.ParseAddrPort(remote.String())
	if err != nil {
		return netip.Prefix{}, false
	}
	addr := addrPort.Addr().Unmap()
	if addr.Is4() {
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	return netip.PrefixFrom(addr, 64).Masked(), true
}

const DefaultHTTPRedirectAddr = ":80"

// HTTPRedirectConfig controls the optional canonical-portal HTTP listener.
// The zero value disables redirects and HSTS; an empty Addr defaults to :80.
type HTTPRedirectConfig struct {
	Enabled bool
	Addr    string
	HSTS    bool
}

type ServerConfig struct {
	Cache            cache.Config
	IVNPConfigPath   string
	PortalURL        string
	StateDir         string
	Bootstraps       []string
	DiscoveryEnabled bool
	SNIPort          int
	HTTPRedirect     HTTPRedirectConfig
	SNIListenAddr    string
	MinPort          int
	MaxPort          int
	ACME             acme.Config
	// UnapprovedLeasesPerSource bounds the leases one source can hold without
	// being routable. Zero disables the bound.
	UnapprovedLeasesPerSource int
	// DefaultIdentityBPS is the stream budget in bytes/second for identities
	// without an operator override. Zero permits unlimited traffic.
	DefaultIdentityBPS int

	// ApplicationOwnsDomainReport delegates types.PathSDKDomain to the
	// application handler, which can compose Server.DomainReport() itself.
	ApplicationOwnsDomainReport bool
}

// NormalizeHTTPRedirectConfig validates redirect settings without resolving names
// or binding sockets. Listener availability is checked only when the server starts.
func NormalizeHTTPRedirectConfig(cfg HTTPRedirectConfig, portalURL string) (HTTPRedirectConfig, error) {
	if !cfg.Enabled {
		return cfg, nil
	}
	target, err := url.Parse(strings.TrimSpace(portalURL))
	if err != nil {
		return HTTPRedirectConfig{}, fmt.Errorf("%w: %w", errHTTPRedirectRequiresPortalURLAbsolute, err)
	}
	hasHTTPSOrigin := target.Scheme == "https" && utils.NormalizeHostname(target.Hostname()) != "" && target.Opaque == ""
	if !hasHTTPSOrigin || target.User != nil || strings.HasSuffix(target.Host, ":") {
		return HTTPRedirectConfig{}, errHTTPRedirectRequiresPortalURLAbsolute
	}
	if port := target.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil {
			return HTTPRedirectConfig{}, fmt.Errorf("%w: %w", errHTTPRedirectPortalURLPortMust, err)
		}
		if n < 1 || n > 65535 {
			return HTTPRedirectConfig{}, errHTTPRedirectPortalURLPortMust
		}
	}
	cfg.Addr = cmp.Or(strings.TrimSpace(cfg.Addr), DefaultHTTPRedirectAddr)
	host, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return HTTPRedirectConfig{}, fmt.Errorf("http redirect HTTP_REDIRECT_ADDR must be a host:port address: %w", err)
	}
	if strings.ContainsAny(host, " \t\r\n/#?@\\") {
		return HTTPRedirectConfig{}, errHTTPRedirectHTTPRedirectAddrHas
	}
	if strings.Contains(host, ":") {
		if _, err := netip.ParseAddr(host); err != nil {
			return HTTPRedirectConfig{}, fmt.Errorf("http redirect HTTP_REDIRECT_ADDR has an invalid IP address: %w", err)
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return HTTPRedirectConfig{}, fmt.Errorf("%w: %w", errHTTPRedirectHTTPRedirectAddrPort, err)
	}
	if n < 0 || n > 65535 {
		return HTTPRedirectConfig{}, errHTTPRedirectHTTPRedirectAddrPort
	}
	return cfg, nil
}

// ValidateServerConfig normalizes server configuration and checks the
// side-effect-free invariants required before runtime resources are created.
func ValidateServerConfig(cfg ServerConfig) (ServerConfig, error) {
	if cfg.DefaultIdentityBPS < 0 {
		return ServerConfig{}, errDefaultIdentityBPSMustNonNegative
	}
	if cfg.UnapprovedLeasesPerSource < 0 {
		return ServerConfig{}, errUnapprovedLeaseLimitNegative
	}
	cfg.IVNPConfigPath = strings.TrimSpace(cfg.IVNPConfigPath)
	if cfg.IVNPConfigPath != "" && !cfg.DiscoveryEnabled {
		return ServerConfig{}, errRelayOverlayRequiresDiscovery
	}
	cfg.PortalURL = strings.TrimSuffix(strings.TrimSpace(cfg.PortalURL), "/")
	cfg.StateDir = strings.TrimSpace(cfg.StateDir)
	if cfg.StateDir == "" {
		return ServerConfig{}, errStateDirectoryIsRequired
	}
	if strings.TrimSpace(cfg.ACME.KeyDir) == "" {
		cfg.ACME.KeyDir = cfg.StateDir
	}
	caDirURL, err := acme.NormalizeCADirURL(cfg.ACME.CADirURL)
	if err != nil {
		return ServerConfig{}, err
	}
	cfg.ACME.CADirURL = caDirURL
	if err := cfg.Cache.Validate(); err != nil {
		return ServerConfig{}, err
	}

	redirect, err := NormalizeHTTPRedirectConfig(cfg.HTTPRedirect, cfg.PortalURL)
	if err != nil {
		return ServerConfig{}, err
	}
	cfg.HTTPRedirect = redirect

	selfRelayURL, err := utils.NormalizeRelayURL(cfg.PortalURL)
	if err != nil {
		return ServerConfig{}, fmt.Errorf("normalize portal url: %w", err)
	}
	if utils.PortalRootHost(selfRelayURL) == "" {
		return ServerConfig{}, errRootHostIsRequired
	}

	bootstraps, err := utils.NormalizeRelayURLs(cfg.Bootstraps...)
	if err != nil {
		return ServerConfig{}, fmt.Errorf("normalize bootstraps: %w", err)
	}
	cfg.PortalURL = selfRelayURL
	cfg.Bootstraps = bootstraps
	cfg.Bootstraps = removeRelayURL(cfg.Bootstraps, selfRelayURL)

	if cfg.SNIPort == 0 {
		cfg.SNIPort = DefaultSNIPort(cfg.PortalURL)
	}
	cfg.SNIPort = utils.IntOrDefault(cfg.SNIPort, 443)
	cfg.SNIListenAddr = cmp.Or(cfg.SNIListenAddr, fmt.Sprintf(":%d", cfg.SNIPort))
	return cfg, nil
}

// DefaultSNIPort returns the local SNI listener port for a deployment that
// leaves SNI_PORT unset: the explicit PORTAL_URL port when the canonical
// origin names one, otherwise 443.
func DefaultSNIPort(portalURL string) int {
	normalized, err := utils.NormalizeRelayURL(portalURL)
	if err != nil {
		return 443
	}
	parsed, err := url.Parse(normalized)
	if err != nil || parsed.Port() == "" {
		return 443
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return 443
	}
	return port
}

func (cfg ServerConfig) snapshot() ServerConfig {
	cfg.Bootstraps = slices.Clone(cfg.Bootstraps)
	return cfg
}

// ValidateTransportPolicy checks policy limits and the configured lease port range.
// Runtime availability is checked by Server.ValidateTransportPolicy.
func (cfg ServerConfig) ValidateTransportPolicy(udpEnabled bool, udpMaxLeases int, tcpEnabled bool, tcpMaxLeases int) error {
	if udpMaxLeases < 0 || tcpMaxLeases < 0 {
		return errTransportMaxLeasesMustNonNegative
	}
	if udpEnabled || tcpEnabled {
		minInRange := cfg.MinPort > 0 && cfg.MinPort <= 65535
		maxInRange := cfg.MaxPort > 0 && cfg.MaxPort <= 65535
		if !minInRange || !maxInRange || cfg.MinPort > cfg.MaxPort {
			return errTransportEnablementRequiresLeasePortRange
		}
	}
	return nil
}

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

func NewServer(cfg ServerConfig) (*Server, error) {
	cfg, err := ValidateServerConfig(cfg)
	if err != nil {
		return nil, err
	}
	identityPath := filepath.Join(cfg.StateDir, types.RelayIdentityFilename)
	relayIdentity, err := identity.LoadOrCreateRelayIdentity(identityPath, utils.PortalRootHost(cfg.PortalURL))
	if err != nil {
		return nil, fmt.Errorf("load relay identity: %w", err)
	}
	relayAuthority := identity.NewLocalAuthority(relayIdentity.Identity)
	registry, err := newLeaseRegistry(cfg.MinPort, cfg.MaxPort, relayIdentity.Name, relayAuthority, cfg.PortalURL, int64(cfg.DefaultIdentityBPS))
	if err != nil {
		return nil, err
	}
	registry.unapprovedPerSource = cfg.UnapprovedLeasesPerSource
	var relaySet *discovery.RelaySet
	if cfg.DiscoveryEnabled {
		cfg.Bootstraps, err = discovery.ResolveRelayURLs(cfg.Bootstraps, true)
		if err != nil {
			return nil, fmt.Errorf("resolve discovery bootstraps: %w", err)
		}
		cfg.Bootstraps = removeRelayURL(cfg.Bootstraps, cfg.PortalURL)
		relaySet = discovery.NewRelaySet(cfg.Bootstraps)
	}

	server := &Server{
		cfg:       utils.NewSnapshot(cfg, ServerConfig.snapshot),
		identity:  relayIdentity,
		authority: relayAuthority,
		registry:  registry,
		relaySet:  relaySet,
	}
	if cfg.IVNPConfigPath != "" {
		server.overlay, err = overlay.New(overlay.Config{
			ConfigPath: cfg.IVNPConfigPath,
			Authority:  relayAuthority,
		})
		if err != nil {
			return nil, err
		}
		registry.overlay = server.overlay
	}
	return server, nil
}

func (s *Server) config() ServerConfig {
	return s.cfg.Load()
}

func (s *Server) overlayIssueDescriptors(now time.Time) (types.RelayDescriptor, []types.RelayDescriptor, error) {
	if s.overlay == nil || s.relaySet == nil {
		return types.RelayDescriptor{}, nil, nil
	}
	self, err := s.newSelfDescriptor(now)
	if err != nil {
		return types.RelayDescriptor{}, nil, fmt.Errorf("build self overlay descriptor: %w", err)
	}
	return self, s.relaySet.Descriptors(types.RelayDescriptor{}), nil
}

func (s *Server) issueReverseEndpoint(input reverseEndpointInput) (types.ReverseEndpoint, error) {
	var self types.RelayDescriptor
	var descriptors []types.RelayDescriptor
	if input.useOverlay {
		var err error
		self, descriptors, err = s.overlayIssueDescriptors(time.Now().UTC())
		if err != nil {
			log.Warn().Err(err).Str("lease", input.leaseIdentity.Key()).Msg("relay overlay descriptors unavailable; using direct reverse transport")
			input.useOverlay = false
		}
	}
	endpoint, err := s.registry.issueReverseEndpoint(input, self, descriptors)
	if err != nil {
		if errors.Is(err, errUnauthorized) || errors.Is(err, errLeaseNotFound) {
			return types.ReverseEndpoint{}, err
		}
		return types.ReverseEndpoint{}, &apiError{types.APIErrorCodeInternal, err.Error(), http.StatusInternalServerError}
	}
	return endpoint, nil
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

// Serve runs the complete relay lifecycle around the composed handler: the
// relay's route table (see the relay package), admin API, and application
// routes all arrive as one handler.
func (s *Server) Serve(ctx context.Context, handler http.Handler) error {
	if err := s.start(ctx, handler); err != nil {
		return fmt.Errorf("start relay server: %w", err)
	}
	return s.Wait()
}

// Start starts the relay and returns after its listeners are ready. Serve is
// the normal lifecycle entry point; Start and Wait remain available to callers
// that need explicit lifecycle control.
func (s *Server) Start(ctx context.Context, handler http.Handler) error {
	return s.start(ctx, handler)
}

func (s *Server) start(ctx context.Context, apiHandler http.Handler) error {
	if s.group != nil {
		return errServerAlreadyStarted
	}
	cfg := s.config()
	cacheManager, cacheErr := cache.New(cfg.Cache, filepath.Join(cfg.StateDir, "static-cache"))
	if cacheErr != nil {
		log.Warn().Err(cacheErr).Msg("relay cache unavailable; using origin tunnels")
	}
	s.registry.cache = cacheManager
	apiTLS, err := s.prepareAPITLS(ctx)
	if err != nil {
		return err
	}

	serverCtx, cancel := context.WithCancel(ctx)
	started := false
	var sniListener net.Listener
	var apiServer *http.Server
	var apiCloser io.Closer
	var redirectListener net.Listener
	var redirectServer *http.Server
	var quicBackhaul *quic.Listener
	defer func() {
		if started {
			return
		}
		cancel()
		if s.overlay != nil {
			s.overlay.Close()
		}
		_ = s.acmeManager.Stop(ctx)
		if apiServer != nil {
			_ = apiServer.Close()
		}
		if redirectServer != nil {
			_ = redirectServer.Close()
		}
		if redirectListener != nil {
			_ = redirectListener.Close()
		}
		if quicBackhaul != nil {
			_ = quicBackhaul.Close()
		}
		if apiCloser != nil {
			_ = apiCloser.Close()
		}
		if sniListener != nil {
			_ = sniListener.Close()
		}
	}()
	var listenConfig net.ListenConfig

	sniListener, err = listenConfig.Listen(serverCtx, "tcp", cfg.SNIListenAddr)
	if err != nil {
		return fmt.Errorf("listen sni: %w", err)
	}

	group, groupCtx := errgroup.WithContext(serverCtx)
	apiServer, apiCloser, err = s.newAPIServer(apiHandler, apiTLS)
	if err != nil {
		return err
	}
	if cfg.HTTPRedirect.Enabled {
		redirectListener, err = listenConfig.Listen(serverCtx, "tcp", cfg.HTTPRedirect.Addr)
		if err != nil {
			return fmt.Errorf("listen http redirect: %w", err)
		}
		redirectServer = &http.Server{
			DisableGeneralOptionsHandler: true,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if cfg.HTTPRedirect.HSTS {
					w.Header().Set("Strict-Transport-Security", "max-age=31536000")
				}
				http.Redirect(w, r, cfg.PortalURL, http.StatusMovedPermanently)
			}),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
	}

	if udpEnabled, _ := s.registry.udpPolicy(); udpEnabled {
		quicBackhaul, err = s.newQUICBackhaulListener(apiTLS)
		if err != nil {
			return fmt.Errorf("listen quic backhaul: %w", err)
		}
	}
	if s.overlay != nil {
		if err := s.overlay.Start(serverCtx); err != nil {
			return fmt.Errorf("start relay overlay: %w", err)
		}
	}

	s.apiHandoff = &handoffListener{addr: sniListener.Addr(), conns: make(chan net.Conn), done: make(chan struct{})}
	s.sniListener = sniListener
	s.apiServer = apiServer
	s.apiTLSClose = apiCloser
	s.redirectListener = redirectListener
	s.redirectServer = redirectServer
	s.ingressCtx = serverCtx
	s.cancel = cancel
	s.group = group
	s.quicBackhaul = quicBackhaul
	started = true

	group.Go(func() error {
		err := s.apiServer.Serve(tls.NewListener(s.apiHandoff, s.apiServer.TLSConfig))
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	})
	if s.redirectServer != nil {
		group.Go(func() error {
			err := s.redirectServer.Serve(s.redirectListener)
			if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		})
	}
	group.Go(func() error { return s.runPublicIngress(groupCtx) })
	if s.quicBackhaul != nil {
		s.quicBackhaulDone = make(chan struct{})
		group.Go(func() error {
			defer close(s.quicBackhaulDone)
			return s.runQUICBackhaulListener(groupCtx)
		})
	}
	group.Go(func() error { return s.runRegistryJanitor(groupCtx, 5*time.Second) })
	if cacheManager != nil {
		group.Go(func() error { return cacheManager.Run(groupCtx) })
	}
	if cfg.DiscoveryEnabled {
		group.Go(func() error { return s.runRelayDiscoveryLoop(groupCtx) })
	}
	if s.overlay != nil {
		group.Go(func() error {
			if err := s.overlay.Run(groupCtx); err != nil && groupCtx.Err() == nil {
				log.Error().Err(err).Msg("relay overlay stopped; direct reverse transport remains available")
				s.overlay.Close()
			}
			return nil
		})
		for range reverseOfferAdmissionWorkers {
			group.Go(func() error {
				for {
					select {
					case <-groupCtx.Done():
						return nil
					case offer := <-s.overlay.ReverseOffers():
						s.admitReverseOffer(offer)
					}
				}
			})
		}
	}
	s.acmeManager.Start(serverCtx)
	group.Go(func() error {
		<-groupCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.Shutdown(shutdownCtx)
	})

	logEvent := log.Info().
		Str("sni_addr", s.sniListener.Addr().String()).
		Str("root_host", s.identity.Name).
		Str("acme_dns_provider", cfg.ACME.DNSProvider).
		Int("min_port", cfg.MinPort).
		Int("max_port", cfg.MaxPort).
		Bool("discovery_enabled", cfg.DiscoveryEnabled).
		Bool("udp_enabled", s.quicBackhaul != nil).
		Bool("tcp_enabled", s.supportsTCP())
	if s.redirectListener != nil {
		logEvent = logEvent.Str("http_redirect_addr", s.redirectListener.Addr().String())
	}
	if s.quicBackhaul != nil {
		logEvent = logEvent.Str("internal_quic_backhaul_addr", s.quicBackhaul.Addr().String())
	}
	logEvent.Msg("relay server started")

	return nil
}

func (s *Server) Wait() error {
	if s.group == nil {
		return nil
	}
	err := s.group.Wait()
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (s *Server) admitReverseOffer(offer overlay.ReverseOffer) {
	lease, err := s.registry.admitLeaseIdentity(offer.ServiceIdentity, offer.LeaseID, time.Now().UTC(), false)
	if err != nil {
		switch {
		case errors.Is(err, errLeaseRejected):
			offer.RejectPending()
		case errors.Is(err, errLeaseDenied):
			offer.RejectDenied()
		default:
			offer.RejectUnavailable()
		}
		offer.Close()
		return
	}

	reservation, err := lease.reverse.ReserveOffer(offer.Connection())
	if err != nil {
		offer.RejectCapacity()
		offer.Close()
		return
	}
	defer reservation.Cancel()
	if err := offer.Accept(); err != nil {
		offer.Close()
		return
	}
	_ = offer.Connection().SetDeadline(time.Time{})
	if err := reservation.Commit(); err != nil {
		offer.Close()
		return
	}
}

func (s *Server) serveTCP(record *leaseRecord) {
	for {
		inbound, err := record.tcpListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if !s.admitIngress(inbound, false) {
			_ = inbound.Close()
			continue
		}
		bridge, err := s.registry.admitBridge(s.ingressCtx, record, inbound)
		if err != nil {
			_ = inbound.Close()
			s.releaseIngress(inbound, false)
			continue
		}
		go func() {
			defer s.releaseIngress(inbound, false)
			defer record.releaseBridge(bridge)
			s.bridgeTCPConn(record, bridge, inbound)
		}()
	}
}

func (s *Server) bridgeTCPConn(record *leaseRecord, bridge *leaseBridge, inbound net.Conn) {
	ctx, cancel := context.WithTimeout(bridge.ctx, defaultClaimTimeout)
	defer cancel()
	for {
		reverse, err := record.reverse.Acquire(ctx)
		if err != nil {
			return
		}
		if err := s.registry.activateBridge(record, bridge, reverse, inbound); err != nil {
			_ = reverse.Close()
			return
		}
		if err := transport.WriteRawStart(reverse); err != nil {
			_ = reverse.Close()
			continue
		}
		s.proxy.bridge(bridge.ctx, inbound, reverse, record.ServiceKey(), s.registry.bps)
		return
	}
}

// SetServiceIdentityAccess applies the relay's current access decision for one
// identity to the portal data path. The relay owns the decision; this only
// carries the result across the boundary, including revoking cached content.
// False means a newer relay snapshot has already reached Portal: the caller
// must reload the committed snapshot before retrying. Stale values never apply.
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

func (s *Server) Shutdown(ctx context.Context) error {
	var shutdownErr error
	s.shutdownOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		s.closeIngress()
		if s.overlay != nil {
			s.overlay.Close()
		}

		if s.quicBackhaul != nil {
			_ = s.quicBackhaul.Close()
		}
		if s.quicBackhaulDone != nil {
			<-s.quicBackhaulDone
		}

		records := s.registry.CloseAll()
		s.ingressWorkers.Wait()
		for _, record := range records {
			s.deleteLeaseDNS(ctx, record)
		}

		if s.apiHandoff != nil {
			_ = s.apiHandoff.Close()
		}
		if s.sniListener != nil {
			if err := s.sniListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				shutdownErr = err
			}
		}
		if s.apiServer != nil {
			if err := s.apiServer.Shutdown(ctx); err != nil && shutdownErr == nil {
				shutdownErr = err
			}
		}
		if s.redirectServer != nil {
			if err := s.redirectServer.Shutdown(ctx); err != nil {
				_ = s.redirectServer.Close()
				if shutdownErr == nil {
					shutdownErr = err
				}
			}
			_ = s.redirectListener.Close()
		}
		if s.apiTLSClose != nil {
			_ = s.apiTLSClose.Close()
		}
		if s.acmeManager != nil {
			if err := s.acmeManager.Stop(ctx); err != nil && shutdownErr == nil {
				shutdownErr = fmt.Errorf("stop acme manager: %w", err)
			}
		}
	})
	return shutdownErr
}

func (s *Server) prepareAPITLS(ctx context.Context) (*tls.Config, error) {
	cfg := s.config()
	acmeCfg := cfg.ACME
	if baseDomain := utils.NormalizeHostname(acmeCfg.BaseDomain); baseDomain != "" && baseDomain != s.identity.Name {
		return nil, fmt.Errorf("acme base domain %q does not match portal root host %q", acmeCfg.BaseDomain, s.identity.Name)
	}
	acmeCfg.BaseDomain = s.identity.Name
	if strings.TrimSpace(acmeCfg.ENSGaslessAddress) == "" {
		acmeCfg.ENSGaslessAddress = s.identity.Address
	}

	manager, err := acme.NewManager(acmeCfg)
	if err != nil {
		return nil, fmt.Errorf("create acme manager: %w", err)
	}

	if err := manager.EnsureTLSMaterial(ctx); err != nil {
		_ = manager.Stop(ctx)
		return nil, fmt.Errorf("ensure relay certificate: %w", err)
	}
	s.acmeManager = manager

	apiTLS := &tls.Config{
		GetCertificate: manager.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.1"},
	}
	return apiTLS, nil
}

func (s *Server) admitIngress(conn net.Conn, inspecting bool) bool {
	s.ingressMu.Lock()
	defer s.ingressMu.Unlock()
	if s.ingressClosed {
		return false
	}
	if inspecting {
		if s.ingressInspecting >= publicInspectionLimit {
			return false
		}
	} else if s.ingressTenants >= publicIngressLimit {
		return false
	}
	if s.ingressConns == nil {
		s.ingressConns = make(map[net.Conn]struct{})
	}
	s.ingressConns[conn] = struct{}{}
	if inspecting {
		s.ingressInspecting++
	} else {
		s.ingressTenants++
	}
	s.ingressWorkers.Add(1)
	return true
}

func (s *Server) promoteIngress() bool {
	s.ingressMu.Lock()
	defer s.ingressMu.Unlock()
	if s.ingressClosed || s.ingressTenants >= publicIngressLimit {
		return false
	}
	s.ingressInspecting--
	s.ingressTenants++
	return true
}

func (s *Server) releaseIngress(conn net.Conn, inspecting bool) {
	s.ingressMu.Lock()
	delete(s.ingressConns, conn)
	if inspecting {
		s.ingressInspecting--
	} else {
		s.ingressTenants--
	}
	s.ingressMu.Unlock()
	s.ingressWorkers.Done()
}

func (s *Server) closeIngress() {
	s.ingressMu.Lock()
	s.ingressClosed = true
	conns := make([]net.Conn, 0, len(s.ingressConns))
	for conn := range s.ingressConns {
		conns = append(conns, conn)
	}
	s.ingressMu.Unlock()
	if s.sniListener != nil {
		_ = s.sniListener.Close()
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (s *Server) runPublicIngress(ctx context.Context) error {
	for {
		conn, err := s.sniListener.Accept()
		switch {
		case err == nil:
			if !s.admitIngress(conn, true) {
				_ = conn.Close()
				continue
			}
			go func(conn net.Conn) {
				inspecting := true
				defer func() { s.releaseIngress(conn, inspecting) }()
				clientHello, wrappedConn, err := l4.InspectClientHello(conn, defaultClientHelloWait)
				if err != nil {
					if wrappedConn != nil {
						_ = wrappedConn.Close()
					} else {
						_ = conn.Close()
					}
					return
				}
				helloSpan := clientHello.HandshakeMessage

				serverName := utils.NormalizeHostname(clientHello.ServerName)
				if serverName == "" || serverName == s.identity.Name || s.registry.cache.Has(serverName) {
					select {
					case s.apiHandoff.conns <- wrappedConn:
					case <-s.apiHandoff.done:
						_ = wrappedConn.Close()
					case <-ctx.Done():
						_ = wrappedConn.Close()
					}
					return
				}

				if !s.promoteIngress() {
					_ = wrappedConn.Close()
					return
				}
				inspecting = false
				record, ok := s.registry.Lookup(serverName)
				if !ok {
					log.Warn().
						Str("server_name", serverName).
						Str("remote_addr", wrappedConn.RemoteAddr().String()).
						Msg("unknown public ingress hostname")
					_ = wrappedConn.Close()
					return
				}
				if err := s.bridgeLeaseConn(ctx, wrappedConn, record, helloSpan); err != nil {
					log.Warn().Err(err).Msg("bridge public ingress")
					_ = wrappedConn.Close()
					return
				}
			}(conn)
		case errors.Is(err, net.ErrClosed):
			return nil
		default:
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("accept sni connection: %w", err)
		}
	}
}

func (s *Server) bridgeLeaseConn(ctx context.Context, conn net.Conn, record *leaseRecord, helloSpan []byte) error {
	deadline := time.Now().Add(defaultClaimTimeout)
	key, replica := record.ServiceKey(), record.replica
	var tried map[string]bool
	if replica {
		tried = make(map[string]bool)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
		// waitUntil is zero while ready replicas are tried without waiting.
		var waitUntil time.Time
		if replica {
			next := s.registry.selectReplica(key, tried, true)
			if next == nil {
				// No untried replica is ready. Wait one slice on a live replica,
				// then rescan all of them: a crashed client keeps its lease until
				// expiry, so one wait target must not hold the whole deadline.
				if next = s.registry.selectReplica(key, nil, false); next == nil {
					return errLeaseNotFound
				}
				clear(tried)
				waitUntil = time.Now().Add(replicaWaitSlice)
				if waitUntil.After(deadline) {
					waitUntil = deadline
				}
			}
			record = next
			tried[record.id] = true
		}
		// Until framing succeeds, only this function owns the inbound connection.
		// Losing one candidate must leave it available to another replica.
		bridge, err := s.registry.admitBridge(ctx, record, nil)
		if err != nil {
			if !replica {
				return err
			}
			// A failed wait still lasts its slice, so an unusable wait
			// target cannot turn the rescan into a busy loop.
			if !waitUntil.IsZero() && !utils.SleepOrDone(ctx, time.Until(waitUntil)) {
				return ctx.Err()
			}
			continue
		}
		claimDeadline := deadline
		if attempt := time.Now().Add(replicaWaitSlice); replica && attempt.Before(claimDeadline) {
			claimDeadline = attempt
		}
		if !waitUntil.IsZero() {
			claimDeadline = waitUntil
		}
		claimCtx, cancel := context.WithDeadline(bridge.ctx, claimDeadline)
		var session net.Conn
		if replica && waitUntil.IsZero() {
			session, err = record.reverse.TryAcquire(claimCtx)
		} else {
			session, err = record.reverse.Acquire(claimCtx)
		}
		cancel()
		if err != nil || session == nil {
			record.releaseBridge(bridge)
			if !replica {
				return fmt.Errorf("acquire lease connection: %w", err)
			}
			if !waitUntil.IsZero() && !utils.SleepOrDone(ctx, time.Until(waitUntil)) {
				return ctx.Err()
			}
			continue
		}
		binding := s.registry.bindings.Issue(record.id, helloSpan)
		err = s.registry.activateBridge(record, bridge, session, nil)
		if err == nil {
			err = transport.WriteTLSStart(session, binding, claimDeadline)
		}
		if err == nil && !time.Now().Before(deadline) {
			err = context.DeadlineExceeded
		}
		if err == nil {
			err = s.registry.activateBridge(record, bridge, session, conn)
		}
		if err != nil {
			s.registry.bindings.Discard(binding)
			_ = session.Close()
			record.releaseBridge(bridge)
			continue
		}
		s.proxy.bridge(bridge.ctx, conn, session, record.ServiceKey(), s.registry.bps)
		s.registry.bindings.Discard(binding)
		record.releaseBridge(bridge)
		return nil
	}
}

func (s *Server) runRegistryJanitor(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return errJanitorIntervalMustBePositive
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			now := time.Now()
			records := s.registry.cleanupExpired(now)
			s.registry.bindings.SweepExpired(now)
			for _, record := range records {
				s.deleteLeaseDNS(ctx, record)
			}
		}
	}
}

func (s *Server) newQUICBackhaulListener(apiTLS *tls.Config) (*quic.Listener, error) {
	if apiTLS.GetCertificate == nil {
		return nil, fmt.Errorf("quic backhaul requires api tls certificate")
	}
	return transport.ListenQUICBackhaul(s.config().SNIListenAddr, apiTLS.GetCertificate)
}

func (s *Server) runQUICBackhaulListener(ctx context.Context) error {
	if s.quicBackhaul == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	var handlers sync.WaitGroup
	defer func() {
		cancel()
		handlers.Wait()
	}()
	pending := make(chan struct{}, quicBackhaulPendingLimit)
	sources := newBackhaulPendingSources()
	for {
		conn, err := s.quicBackhaul.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, quic.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !sources.acquire(conn.RemoteAddr()) {
			_ = conn.CloseWithError(1, "backhaul authentication busy")
			continue
		}
		select {
		case pending <- struct{}{}:
			remote := conn.RemoteAddr()
			authCtx, authCancel := context.WithTimeout(ctx, quicBackhaulAuthTimeout)
			handlers.Go(func() {
				defer authCancel()
				defer sources.release(remote)
				defer func() { <-pending }()
				s.handleQUICBackhaulConn(authCtx, conn)
			})
		default:
			sources.release(conn.RemoteAddr())
			_ = conn.CloseWithError(1, "backhaul authentication busy")
		}
	}
}

func (s *Server) handleQUICBackhaulConn(ctx context.Context, conn *quic.Conn) {
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.CloseWithError(1, "backhaul authentication canceled")
		close(closed)
	})
	authenticated := false
	defer func() {
		if !authenticated && !stop() {
			<-closed
		}
	}()
	control, err := transport.AcceptQUICBackhaulControl(ctx, conn)
	if err != nil {
		_ = conn.CloseWithError(1, "control read failed")
		return
	}

	lease, err := s.registry.admitLeaseByToken(control.AccessToken, true)
	if err != nil {
		code, reason := types.APIErrorCodeInvalidRequest, "invalid control message"
		switch {
		case errors.Is(err, errLeaseNotFound):
			code, reason = types.APIErrorCodeLeaseNotFound, "lease not found"
		case errors.Is(err, errLeaseRejected), errors.Is(err, errLeaseDenied):
			code, reason = types.APIErrorCodeLeaseRejected, "lease rejected"
		case errors.Is(err, errUnauthorized):
			code, reason = types.APIErrorCodeUnauthorized, "unauthorized"
		case errors.Is(err, errTransportMismatch):
			code, reason = types.APIErrorCodeTransportMismatch, "transport mismatch"
		}
		_ = control.Reject(code, reason)
		return
	}

	if err := lease.datagram.BindBackhaul(conn); err != nil {
		_ = control.Reject("broker_closed", "broker closed")
		return
	}

	if err := control.Accept(); err != nil {
		_ = conn.CloseWithError(1, "control response failed")
		return
	}
	if !stop() {
		<-closed
		return
	}
	authenticated = true
	sourceAddr := netip.Addr{}
	if remote := conn.RemoteAddr(); remote != nil {
		if addrPort, err := netip.ParseAddrPort(remote.String()); err == nil {
			sourceAddr = addrPort.Addr().Unmap()
		}
	}
	s.registry.Touch(lease.ServiceKey(), lease.id, sourceAddr, time.Now())
	log.Info().
		Str("component", "quic-backhaul-listener").
		Str("address", lease.Address).
		Str("lease_name", lease.Name).
		Str("remote_addr", conn.RemoteAddr().String()).
		Msg("quic backhaul connected")
}

func (s *Server) runRelayDiscoveryLoop(ctx context.Context) error {
	if s.relaySet == nil {
		<-ctx.Done()
		return nil
	}
	refresher := discovery.NewRefresher(s.relaySet)
	ticker := time.NewTicker(discovery.DiscoveryPollInterval)
	defer ticker.Stop()

	for {
		now := time.Now().UTC()
		self, err := s.newSelfDescriptor(now)
		if err != nil {
			return fmt.Errorf("build relay discovery descriptor: %w", err)
		}
		if err := refresher.Refresh(ctx, &self); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if ctx.Err() != nil {
			return nil
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (s *Server) newSelfDescriptor(now time.Time) (types.RelayDescriptor, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	cfg := s.config()

	ivnpDestination := ""
	if s.overlay != nil {
		ivnpDestination = s.overlay.Destination()
	}
	return discovery.SignRelayDescriptor(types.RelayDescriptor{
		Address:           s.identity.Address,
		Version:           types.DiscoveryVersion,
		IssuedAt:          now,
		ExpiresAt:         now.Add(discovery.DiscoveryDescriptorTTL),
		APIHTTPSAddr:      cfg.PortalURL,
		IVNPDestination:   ivnpDestination,
		SupportsUDP:       s.supportsUDP(),
		SupportsTCP:       s.supportsTCP(),
		ActiveConnections: s.proxy.activeConnectionCount(),
		TCPBPS:            s.proxy.currentTCPBPS(now),
	}, s.authority)
}

func removeRelayURL(inputs []string, target string) []string {
	var filtered []string
	for _, input := range inputs {
		if input != target {
			filtered = append(filtered, input)
		}
	}
	return filtered
}
