package portal

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/overlay"
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

func (s *Server) closeSNIServer() error {
	if s.sniListener == nil {
		return nil
	}
	if err := s.sniListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func (s *Server) shutdownRedirectServer(ctx context.Context) error {
	if s.redirectServer == nil {
		return nil
	}
	err := s.redirectServer.Shutdown(ctx)
	if err != nil {
		_ = s.redirectServer.Close()
	}
	_ = s.redirectListener.Close()
	return err
}

func (s *Server) stopShutdownACME(ctx context.Context) error {
	if s.acmeManager == nil {
		return nil
	}
	if err := s.acmeManager.Stop(ctx); err != nil {
		return fmt.Errorf("stop acme manager: %w", err)
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	var shutdownErr error
	s.shutdownOnce.Do(func() {
		records := s.haltRelayTransports(ctx)
		s.deleteHaltedLeaseDNS(ctx, records)
		if err := s.closeRelayServers(ctx); err != nil {
			shutdownErr = err
		}
		if err := s.stopShutdownACME(ctx); err != nil && shutdownErr == nil {
			shutdownErr = err
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

func resolveRelaySet(cfg ServerConfig) (ServerConfig, *discovery.RelaySet, error) {
	if !cfg.DiscoveryEnabled {
		return cfg, nil, nil
	}
	bootstraps, err := discovery.ResolveRelayURLs(cfg.Bootstraps, true)
	if err != nil {
		return ServerConfig{}, nil, fmt.Errorf("resolve discovery bootstraps: %w", err)
	}
	cfg.Bootstraps = bootstraps
	cfg.Bootstraps = removeRelayURL(cfg.Bootstraps, cfg.PortalURL)
	return cfg, discovery.NewRelaySet(cfg.Bootstraps), nil
}

func attachOverlay(server *Server, cfg ServerConfig, relayAuthority identity.Authority) error {
	if cfg.IVNPConfigPath == "" {
		return nil
	}
	overlayRuntime, err := overlay.New(overlay.Config{
		ConfigPath: cfg.IVNPConfigPath,
		Authority:  relayAuthority,
	})
	if err != nil {
		return err
	}
	server.overlay = overlayRuntime
	server.registry.overlay = overlayRuntime
	return nil
}

func completeNewServer(cfg ServerConfig, registry *leaseRegistry, relayIdentity identity.RelayIdentity, relayAuthority identity.Authority) (*Server, error) {
	resolved, relaySet, err := resolveRelaySet(cfg)
	if err != nil {
		return nil, err
	}
	server := &Server{
		cfg:       utils.NewSnapshot(resolved, ServerConfig.snapshot),
		identity:  relayIdentity,
		authority: relayAuthority,
		registry:  registry,
		relaySet:  relaySet,
	}
	if err := attachOverlay(server, resolved, relayAuthority); err != nil {
		return nil, err
	}
	return server, nil
}

func NewServer(cfg ServerConfig) (*Server, error) {
	validated, err := ValidateServerConfig(cfg)
	if err != nil {
		return nil, err
	}
	identityPath := filepath.Join(validated.StateDir, types.RelayIdentityFilename)
	relayIdentity, err := identity.LoadOrCreateRelayIdentity(identityPath, utils.PortalRootHost(validated.PortalURL))
	if err != nil {
		return nil, fmt.Errorf("load relay identity: %w", err)
	}
	relayAuthority := identity.NewLocalAuthority(relayIdentity.Identity)
	registry, err := newLeaseRegistry(validated.MinPort, validated.MaxPort, relayIdentity.Name, relayAuthority, validated.PortalURL, int64(validated.DefaultIdentityBPS))
	if err != nil {
		return nil, err
	}
	registry.unapprovedPerSource = validated.UnapprovedLeasesPerSource
	return completeNewServer(validated, registry, relayIdentity, relayAuthority)
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

const (
	defaultClaimTimeout          = 10 * time.Second
	defaultClientHelloWait       = 2 * time.Second
	defaultControlBodyLimit      = 4 << 20
	reverseOfferAdmissionWorkers = 16
	quicBackhaulPendingLimit     = 64
	quicBackhaulAuthTimeout      = 3 * time.Second
	quicBackhaulPerSourceLimit   = 4
	publicIngressLimit           = 1024
	publicInspectionLimit        = 128
)

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

func (s *Server) installStartBundle(serverCtx context.Context, bundle serverStartBundle, cancel context.CancelFunc) {
	s.apiHandoff = &handoffListener{addr: bundle.sniListener.Addr(), conns: make(chan net.Conn), done: make(chan struct{})}
	s.sniListener = bundle.sniListener
	s.apiServer = bundle.apiServer
	s.apiTLSClose = bundle.apiCloser
	s.redirectListener = bundle.redirectListener
	s.redirectServer = bundle.redirectServer
	s.ingressCtx = serverCtx
	s.cancel = cancel
	s.group = bundle.group
	s.quicBackhaul = bundle.quicBackhaul
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
	var bundle serverStartBundle
	defer func() {
		if started {
			return
		}
		cancel()
		s.abortStartBundle(ctx, bundle)
	}()
	collected, err := s.collectStartBundle(serverCtx, cfg, apiHandler, apiTLS)
	bundle = collected
	if err != nil {
		return err
	}
	s.installStartBundle(serverCtx, bundle, cancel)
	started = true
	s.serveStartListeners(bundle)
	s.serveStartBackground(serverCtx, bundle, cfg)
	s.emitStartLog(cfg)
	return nil
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
			go s.servePublicIngressConn(ctx, conn)
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
	lease, ok := s.admitBackhaulLease(ctx, conn)
	if !ok {
		return
	}
	if !stop() {
		<-closed
		return
	}
	authenticated = true
	s.noteBackhaulConnected(conn, lease)
}

func (s *Server) haltRelayTransports(ctx context.Context) []*leaseRecord {
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
	return records
}

func (s *Server) deleteHaltedLeaseDNS(ctx context.Context, records []*leaseRecord) {
	for _, record := range records {
		s.deleteLeaseDNS(ctx, record)
	}
}

func (s *Server) closeRelayServers(ctx context.Context) error {
	var firstErr error
	if s.apiHandoff != nil {
		_ = s.apiHandoff.Close()
	}
	if err := s.closeSNIServer(); err != nil && firstErr == nil {
		firstErr = err
	}
	if s.apiServer != nil {
		if err := s.apiServer.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := s.shutdownRedirectServer(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	if s.apiTLSClose != nil {
		_ = s.apiTLSClose.Close()
	}
	return firstErr
}

type serverStartBundle struct {
	sniListener      net.Listener
	apiServer        *http.Server
	apiCloser        io.Closer
	redirectListener net.Listener
	redirectServer   *http.Server
	quicBackhaul     *quic.Listener
	group            *errgroup.Group
	groupCtx         context.Context
}

func (s *Server) buildRedirectServerStart(serverCtx context.Context, cfg ServerConfig) (net.Listener, *http.Server, error) {
	if !cfg.HTTPRedirect.Enabled {
		return nil, nil, nil
	}
	var listenConfig net.ListenConfig
	redirectListener, err := listenConfig.Listen(serverCtx, "tcp", cfg.HTTPRedirect.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen http redirect: %w", err)
	}
	redirectServer := &http.Server{
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
	return redirectListener, redirectServer, nil
}

func (s *Server) buildQUICBackhaulStart(apiTLS *tls.Config) (*quic.Listener, error) {
	udpEnabled, _ := s.registry.udpPolicy()
	if !udpEnabled {
		return nil, nil
	}
	quicBackhaul, err := s.newQUICBackhaulListener(apiTLS)
	if err != nil {
		return nil, fmt.Errorf("listen quic backhaul: %w", err)
	}
	return quicBackhaul, nil
}

func (s *Server) enterOverlayStart(serverCtx context.Context) error {
	if s.overlay == nil {
		return nil
	}
	if err := s.overlay.Start(serverCtx); err != nil {
		return fmt.Errorf("start relay overlay: %w", err)
	}
	return nil
}

func (s *Server) fillBundleFrontListeners(serverCtx context.Context, cfg ServerConfig, apiHandler http.Handler, apiTLS *tls.Config, bundle *serverStartBundle) error {
	var listenConfig net.ListenConfig
	sniListener, err := listenConfig.Listen(serverCtx, "tcp", cfg.SNIListenAddr)
	if err != nil {
		return fmt.Errorf("listen sni: %w", err)
	}
	bundle.sniListener = sniListener
	bundle.group, bundle.groupCtx = errgroup.WithContext(serverCtx)
	apiServer, apiCloser, err := s.newAPIServer(apiHandler, apiTLS)
	if err != nil {
		return err
	}
	bundle.apiServer = apiServer
	bundle.apiCloser = apiCloser
	return nil
}

func (s *Server) fillBundleBackListeners(serverCtx context.Context, cfg ServerConfig, apiTLS *tls.Config, bundle *serverStartBundle) error {
	redirectListener, redirectServer, err := s.buildRedirectServerStart(serverCtx, cfg)
	if err != nil {
		return err
	}
	bundle.redirectListener = redirectListener
	bundle.redirectServer = redirectServer
	quicBackhaul, err := s.buildQUICBackhaulStart(apiTLS)
	if err != nil {
		return err
	}
	bundle.quicBackhaul = quicBackhaul
	if err := s.enterOverlayStart(serverCtx); err != nil {
		return err
	}
	return nil
}

func (s *Server) collectStartBundle(serverCtx context.Context, cfg ServerConfig, apiHandler http.Handler, apiTLS *tls.Config) (serverStartBundle, error) {
	var bundle serverStartBundle
	if err := s.fillBundleFrontListeners(serverCtx, cfg, apiHandler, apiTLS, &bundle); err != nil {
		return bundle, err
	}
	if err := s.fillBundleBackListeners(serverCtx, cfg, apiTLS, &bundle); err != nil {
		return bundle, err
	}
	return bundle, nil
}

func (s *Server) abortStartBundle(ctx context.Context, bundle serverStartBundle) {
	if s.overlay != nil {
		s.overlay.Close()
	}
	_ = s.acmeManager.Stop(ctx)
	if bundle.apiServer != nil {
		_ = bundle.apiServer.Close()
	}
	if bundle.redirectServer != nil {
		_ = bundle.redirectServer.Close()
	}
	if bundle.redirectListener != nil {
		_ = bundle.redirectListener.Close()
	}
	if bundle.quicBackhaul != nil {
		_ = bundle.quicBackhaul.Close()
	}
	if bundle.apiCloser != nil {
		_ = bundle.apiCloser.Close()
	}
	if bundle.sniListener != nil {
		_ = bundle.sniListener.Close()
	}
}

func (s *Server) serveStartListeners(bundle serverStartBundle) {
	bundle.group.Go(func() error {
		err := s.apiServer.Serve(tls.NewListener(s.apiHandoff, s.apiServer.TLSConfig))
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	})
	if s.redirectServer != nil {
		bundle.group.Go(func() error {
			err := s.redirectServer.Serve(s.redirectListener)
			if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		})
	}
	bundle.group.Go(func() error { return s.runPublicIngress(bundle.groupCtx) })
	if s.quicBackhaul != nil {
		s.quicBackhaulDone = make(chan struct{})
		bundle.group.Go(func() error {
			defer close(s.quicBackhaulDone)
			return s.runQUICBackhaulListener(bundle.groupCtx)
		})
	}
}

func (s *Server) serveStartBackground(serverCtx context.Context, bundle serverStartBundle, cfg ServerConfig) {
	bundle.group.Go(func() error { return s.runRegistryJanitor(bundle.groupCtx, 5*time.Second) })
	if s.registry.cache != nil {
		bundle.group.Go(func() error { return s.registry.cache.Run(bundle.groupCtx) })
	}
	if cfg.DiscoveryEnabled {
		bundle.group.Go(func() error { return s.runRelayDiscoveryLoop(bundle.groupCtx) })
	}
	if s.overlay != nil {
		s.serveStartOverlay(bundle)
	}
	s.acmeManager.Start(serverCtx)
	bundle.group.Go(func() error {
		<-bundle.groupCtx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		return s.Shutdown(shutdownCtx)
	})
}

func (s *Server) serveStartOverlay(bundle serverStartBundle) {
	bundle.group.Go(func() error {
		if err := s.overlay.Run(bundle.groupCtx); err != nil && bundle.groupCtx.Err() == nil {
			log.Error().Err(err).Msg("relay overlay stopped; direct reverse transport remains available")
			s.overlay.Close()
		}
		return nil
	})
	for range reverseOfferAdmissionWorkers {
		bundle.group.Go(func() error {
			for {
				select {
				case <-bundle.groupCtx.Done():
					return nil
				case offer := <-s.overlay.ReverseOffers():
					s.admitReverseOffer(offer)
				}
			}
		})
	}
}

func (s *Server) emitStartLog(cfg ServerConfig) {
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
}
