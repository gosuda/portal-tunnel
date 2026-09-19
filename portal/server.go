package portal

import (
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
	"strconv"
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
	"github.com/gosuda/portal-tunnel/v2/portal/overlay"
	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultClaimTimeout     = 10 * time.Second
	defaultClientHelloWait  = 2 * time.Second
	defaultControlBodyLimit = 4 << 20
)

type ServerConfig struct {
	PreAuth           types.PreAuthConfig
	Cache             cache.Config
	IVNPConfigPath    string
	PortalURL         string
	StateDir          string
	Bootstraps        []string
	DiscoveryEnabled  bool
	SNIPort           int
	HTTPRedirect      types.HTTPRedirectConfig
	SNIListenAddr     string
	TrustProxyHeaders bool
	TrustedProxyCIDRs string
	UDPEnabled        bool
	TCPEnabled        bool
	MinPort           int
	MaxPort           int
	ACME              acme.Config

	// ApplicationOwnsDomainReport delegates types.PathSDKDomain to the
	// application handler, which can compose Server.DomainReport() itself.
	ApplicationOwnsDomainReport bool
}

// NormalizeHTTPRedirectConfig validates redirect settings without resolving names
// or binding sockets. Listener availability is checked only when the server starts.
func NormalizeHTTPRedirectConfig(cfg types.HTTPRedirectConfig, portalURL string) (types.HTTPRedirectConfig, error) {
	if !cfg.Enabled {
		return cfg, nil
	}
	target, err := url.Parse(strings.TrimSpace(portalURL))
	if err != nil {
		return types.HTTPRedirectConfig{}, errors.New("http redirect requires PORTAL_URL to be an absolute HTTPS URL without credentials")
	}
	hasHTTPSOrigin := target.Scheme == "https" && utils.NormalizeHostname(target.Hostname()) != "" && target.Opaque == ""
	if !hasHTTPSOrigin || target.User != nil || strings.HasSuffix(target.Host, ":") {
		return types.HTTPRedirectConfig{}, errors.New("http redirect requires PORTAL_URL to be an absolute HTTPS URL without credentials")
	}
	if port := target.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return types.HTTPRedirectConfig{}, errors.New("http redirect PORTAL_URL port must be between 1 and 65535")
		}
	}
	cfg.Addr = utils.StringOrDefault(strings.TrimSpace(cfg.Addr), types.DefaultHTTPRedirectAddr)
	host, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return types.HTTPRedirectConfig{}, fmt.Errorf("http redirect HTTP_REDIRECT_ADDR must be a host:port address: %w", err)
	}
	if strings.ContainsAny(host, " \t\r\n/#?@\\") {
		return types.HTTPRedirectConfig{}, errors.New("http redirect HTTP_REDIRECT_ADDR has an invalid host")
	}
	if strings.Contains(host, ":") {
		if _, err := netip.ParseAddr(host); err != nil {
			return types.HTTPRedirectConfig{}, fmt.Errorf("http redirect HTTP_REDIRECT_ADDR has an invalid IP address: %w", err)
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return types.HTTPRedirectConfig{}, errors.New("http redirect HTTP_REDIRECT_ADDR port must be between 0 and 65535")
	}
	return cfg, nil
}

// ValidateServerConfig normalizes server configuration and checks the
// side-effect-free invariants required before runtime resources are created.
func ValidateServerConfig(cfg ServerConfig) (ServerConfig, error) {
	if err := policy.NormalizePreAuthConfig(&cfg.PreAuth); err != nil {
		return ServerConfig{}, err
	}
	cfg.IVNPConfigPath = strings.TrimSpace(cfg.IVNPConfigPath)
	if cfg.IVNPConfigPath != "" && !cfg.DiscoveryEnabled {
		return ServerConfig{}, errors.New("relay overlay requires discovery")
	}
	cfg.PortalURL = strings.TrimSuffix(strings.TrimSpace(cfg.PortalURL), "/")
	cfg.StateDir = strings.TrimSpace(cfg.StateDir)
	if cfg.StateDir == "" {
		return ServerConfig{}, errors.New("state directory is required")
	}
	if strings.TrimSpace(cfg.ACME.KeyDir) == "" {
		cfg.ACME.KeyDir = cfg.StateDir
	}
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
		return ServerConfig{}, errors.New("root host is required")
	}

	bootstraps, err := utils.NormalizeRelayURLs(cfg.Bootstraps...)
	if err != nil {
		return ServerConfig{}, fmt.Errorf("normalize bootstraps: %w", err)
	}
	cfg.PortalURL = selfRelayURL
	cfg.Bootstraps = bootstraps
	cfg.Bootstraps = utils.RemoveRelayURL(cfg.Bootstraps, selfRelayURL)

	if cfg.SNIPort == 0 {
		// SNI_PORT owns only the local bind. When PORTAL_URL names an explicit
		// port, an unoverridden listener follows it so a single-setting
		// deployment serves the port it advertises; mapping a different public
		// port onto the local listener still sets SNI_PORT explicitly.
		cfg.SNIPort = DefaultSNIPort(cfg.PortalURL)
	}
	cfg.SNIPort = utils.IntOrDefault(cfg.SNIPort, 443)
	cfg.SNIListenAddr = utils.StringOrDefault(cfg.SNIListenAddr, fmt.Sprintf(":%d", cfg.SNIPort))
	// The runtime parses the proxy CIDR allowlist in policy.NewRuntime before
	// serving; validate it here so the config report and startup agree on the
	// same parse instead of the report calling an invalid list valid.
	if _, err := utils.ParseCIDRs(cfg.TrustedProxyCIDRs); err != nil {
		return ServerConfig{}, fmt.Errorf("parse trusted proxy cidrs: %w", err)
	}
	hasPortRange := cfg.MinPort > 0 && cfg.MaxPort > 0
	if cfg.UDPEnabled || cfg.TCPEnabled {
		switch {
		case !hasPortRange:
			return ServerConfig{}, errors.New("udp and tcp relay transport require a valid min port and max port range")
		case cfg.MinPort > 65535 || cfg.MaxPort > 65535:
			return ServerConfig{}, errors.New("min port and max port must be between 1 and 65535")
		case cfg.MinPort > cfg.MaxPort:
			return ServerConfig{}, errors.New("min port must be less than or equal to max port")
		}
	}

	cfg.UDPEnabled = cfg.UDPEnabled && cfg.hasLeasePortRange()
	cfg.TCPEnabled = cfg.TCPEnabled && cfg.hasLeasePortRange()
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
	cfg.Bootstraps = utils.CloneSlice(cfg.Bootstraps)
	return cfg
}

func (cfg ServerConfig) hasLeasePortRange() bool {
	return cfg.MinPort > 0 && cfg.MaxPort > 0 && cfg.MinPort <= 65535 && cfg.MaxPort <= 65535 && cfg.MinPort <= cfg.MaxPort
}

type Server struct {
	cancel       context.CancelFunc
	group        *errgroup.Group
	shutdownOnce sync.Once
	publicPort   int

	cfg         *utils.Snapshot[ServerConfig]
	identity    identity.RelayIdentity
	authority   identity.Authority
	acmeManager *acme.Manager
	proxy       proxy
	apiKeyPEM   []byte

	apiHandoff       *handoffListener
	sniListener      net.Listener
	apiServer        *http.Server
	apiTLSClose      io.Closer
	redirectListener net.Listener
	redirectServer   *http.Server
	quicBackhaul     *quic.Listener

	relaySet       *discovery.RelaySet
	preAuthLimiter *policy.SourceLimiter
	registry       *leaseRegistry
	overlay        *overlay.Runtime
}

func NewServer(cfg ServerConfig) (*Server, error) {
	cfg, err := ValidateServerConfig(cfg)
	if err != nil {
		return nil, err
	}
	portalURL, err := url.Parse(cfg.PortalURL)
	if err != nil {
		return nil, fmt.Errorf("parse normalized portal url: %w", err)
	}
	publicPort := 443
	if port := portalURL.Port(); port != "" {
		publicPort, err = strconv.Atoi(port)
		if err != nil || publicPort < 1 || publicPort > 65535 {
			return nil, errors.New("PORTAL_URL port must be between 1 and 65535")
		}
	}

	identityPath := filepath.Join(cfg.StateDir, types.RelayIdentityFilename)
	relayIdentity, err := identity.LoadOrCreateRelayIdentity(identityPath, utils.PortalRootHost(cfg.PortalURL))
	if err != nil {
		return nil, fmt.Errorf("load relay identity: %w", err)
	}
	relayAuthority := identity.NewLocalAuthority(relayIdentity.Identity)
	registry, err := newLeaseRegistry(cfg.UDPEnabled, cfg.TCPEnabled, cfg.MinPort, cfg.MaxPort, relayIdentity.Name, publicPort, relayAuthority, cfg.PortalURL, cfg.TrustProxyHeaders, cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	var relaySet *discovery.RelaySet
	if cfg.DiscoveryEnabled {
		cfg.Bootstraps, err = discovery.ResolveRelayURLs(cfg.Bootstraps, true)
		if err != nil {
			return nil, fmt.Errorf("resolve discovery bootstraps: %w", err)
		}
		cfg.Bootstraps = utils.RemoveRelayURL(cfg.Bootstraps, cfg.PortalURL)
		relaySet = discovery.NewRelaySet(cfg.Bootstraps)
	}

	server := &Server{
		cfg:            utils.NewSnapshot(cfg, ServerConfig.snapshot),
		identity:       relayIdentity,
		authority:      relayAuthority,
		publicPort:     publicPort,
		registry:       registry,
		relaySet:       relaySet,
		preAuthLimiter: policy.NewSourceLimiter(cfg.PreAuth.SourcePerMinute, cfg.PreAuth.SourceBurst, cfg.PreAuth.GlobalPerMinute, cfg.PreAuth.GlobalBurst),
	}
	server.registry.proxy = &server.proxy
	if cfg.IVNPConfigPath != "" {
		server.overlay, err = overlay.New(overlay.Config{
			ConfigPath: cfg.IVNPConfigPath,
			Authority:  relayAuthority,
			OfferReverse: func(identityKey, leaseID string, conn net.Conn, ready func() error) error {
				lease, err := registry.admitLeaseIdentity(identityKey, leaseID, time.Now().UTC(), false)
				if err != nil {
					return fmt.Errorf("%w: %w", overlay.ErrLeaseUnavailable, err)
				}
				return lease.stream.OfferConnReady(conn, ready)
			},
			Bridge: func(left, right net.Conn) {
				server.proxy.bridge(left, right, "", registry.policy.BPSManager())
			},
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

func (s *Server) SetUDPPolicy(enabled bool, maxLeases int) {
	if enabled && !s.config().hasLeasePortRange() {
		enabled = false
	}
	if runtime := s.PolicyRuntime(); runtime != nil {
		runtime.SetUDPPolicy(enabled, maxLeases)
	}
	s.cfg.UpdateCopy(func(cfg *ServerConfig) {
		cfg.UDPEnabled = enabled
	})
}

func (s *Server) SetTCPPortPolicy(enabled bool, maxLeases int) {
	if enabled && !s.config().hasLeasePortRange() {
		enabled = false
	}
	if runtime := s.PolicyRuntime(); runtime != nil {
		runtime.SetTCPPortPolicy(enabled, maxLeases)
	}
	s.cfg.UpdateCopy(func(cfg *ServerConfig) {
		cfg.TCPEnabled = enabled
	})
}

func (s *Server) supportsUDP() bool {
	runtime := s.PolicyRuntime()
	if runtime == nil || !runtime.IsUDPEnabled() {
		return false
	}
	return s.group == nil || s.quicBackhaul != nil
}

func (s *Server) supportsTCP() bool {
	runtime := s.PolicyRuntime()
	return runtime != nil && runtime.IsTCPPortEnabled()
}

// Serve runs the complete relay lifecycle around the application handler.
func (s *Server) Serve(ctx context.Context, handler http.Handler) error {
	mux := http.NewServeMux()
	if handler == nil {
		mux.HandleFunc("/{$}", s.handleRoot)
	} else {
		mux.Handle("/", handler)
	}
	if err := s.start(ctx, mux); err != nil {
		return fmt.Errorf("start relay server: %w", err)
	}
	return s.Wait()
}

// Start starts the relay and returns after its listeners are ready. Serve is
// the normal lifecycle entry point; Start and Wait remain available to callers
// that need explicit lifecycle control.
func (s *Server) Start(ctx context.Context, apiMux *http.ServeMux) error {
	return s.start(ctx, apiMux)
}

func (s *Server) start(ctx context.Context, apiHandler http.Handler) error {
	if s.group != nil {
		return errors.New("server already started")
	}
	cfg := s.config()
	cacheManager, cacheErr := cache.New(cfg.Cache, filepath.Join(cfg.StateDir, "static-cache"), s.registry.policy)
	if cacheErr != nil {
		log.Warn().Err(cacheErr).Msg("relay cache unavailable; using origin tunnels")
	}
	s.registry.cache = cacheManager
	apiTLS, acmeManager, err := s.prepareAPITLS(ctx)
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
		_ = acmeManager.Stop(ctx)
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
				// Canonical portal only: never forward request hosts, paths, or queries.
				http.Redirect(w, r, cfg.PortalURL, http.StatusMovedPermanently)
			}),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
	}

	if cfg.UDPEnabled {
		quicBackhaul, err = s.newQUICBackhaulListener(apiTLS)
		if err != nil {
			log.Warn().Err(err).Msg("quic backhaul listener disabled")
			quicBackhaul = nil
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
	s.acmeManager = acmeManager
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
		group.Go(s.runQUICBackhaulListener)
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

func (s *Server) PolicyRuntime() *policy.Runtime {
	if s == nil || s.registry == nil {
		return nil
	}
	return s.registry.policy
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

func (s *Server) RelayIdentity() identity.RelayIdentity {
	if s == nil {
		return identity.RelayIdentity{}
	}
	return s.identity.Copy()
}

func (s *Server) Shutdown(ctx context.Context) error {
	var shutdownErr error
	s.shutdownOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.overlay != nil {
			s.overlay.Close()
		}

		records := s.registry.CloseAll()
		for _, record := range records {
			record.deleteDNS(ctx, s.acmeManager)
		}

		if s.quicBackhaul != nil {
			_ = s.quicBackhaul.Close()
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
			// Shutdown can precede the Serve goroutine registering its listener.
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

func (s *Server) prepareAPITLS(ctx context.Context) (*tls.Config, *acme.Manager, error) {
	cfg := s.config()
	acmeCfg := cfg.ACME
	if baseDomain := utils.NormalizeHostname(acmeCfg.BaseDomain); baseDomain != "" && baseDomain != s.identity.Name {
		return nil, nil, fmt.Errorf("acme base domain %q does not match portal root host %q", acmeCfg.BaseDomain, s.identity.Name)
	}
	acmeCfg.BaseDomain = s.identity.Name
	if strings.TrimSpace(acmeCfg.ENSGaslessAddress) == "" {
		acmeCfg.ENSGaslessAddress = s.identity.Address
	}

	manager, err := acme.NewManager(acmeCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("create acme manager: %w", err)
	}

	certPEM, keyPEM, err := manager.EnsureTLSMaterial(ctx)
	if err != nil {
		_ = manager.Stop(ctx)
		return nil, nil, fmt.Errorf("ensure relay certificate: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		_ = manager.Stop(ctx)
		return nil, nil, fmt.Errorf("parse relay api keypair: %w", err)
	}
	// The /v1/sign transcript signer shares the API listener key; newAPIServer
	// reads the PEM to build its handler.
	s.apiKeyPEM = keyPEM

	apiTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	return apiTLS, manager, nil
}

func (s *Server) runPublicIngress(ctx context.Context) error {
	for {
		conn, err := s.sniListener.Accept()
		switch {
		case err == nil:
			go func(conn net.Conn) {
				// Reassemble the ClientHello before routing so its exact
				// handshake bytes can be pinned into the binding.
				helloSpan, wrappedConn, err := captureClientHello(conn, defaultClientHelloWait)
				if err != nil {
					_ = conn.Close()
					return
				}
				serverName, err := clientHelloServerName(helloSpan)
				if err != nil {
					_ = wrappedConn.Close()
					return
				}

				serverName = utils.NormalizeHostname(serverName)
				// Go omits the SNI extension for IP-literal hosts and tenant
				// hostnames are always DNS names, so a connection without a server
				// name targets the canonical root origin; route it there instead
				// of failing the handshake for IP-literal PORTAL_URL deployments.
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
	if record.isExpired(time.Now()) {
		return errLeaseNotFound
	}
	if record.stream == nil {
		return errors.New("lease stream is not ready")
	}
	if !s.registry.policy.IsIdentityRoutable(record.Key()) {
		return errLeaseRejected
	}
	claimCtx, cancel := context.WithTimeout(ctx, defaultClaimTimeout)
	binding := s.registry.bindings.Issue(record.id, helloSpan)
	session, err := record.stream.Claim(claimCtx, binding)
	cancel()
	if err != nil {
		// The binding will never be presented after a failed claim; drop
		// it instead of leaving a live entry until the TTL sweep.
		s.registry.bindings.Discard(binding)
		return fmt.Errorf("claim lease stream: %w", err)
	}
	s.proxy.bridge(conn, session, record.Key(), s.registry.policy.BPSManager())
	return nil
}

func (s *Server) runRegistryJanitor(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("janitor interval must be positive")
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
				record.deleteDNS(ctx, s.acmeManager)
			}
		}
	}
}

func (s *Server) newQUICBackhaulListener(apiTLS *tls.Config) (*quic.Listener, error) {
	if len(apiTLS.Certificates) == 0 {
		return nil, fmt.Errorf("quic backhaul requires api tls certificate")
	}
	return transport.ListenQUICBackhaul(s.config().SNIListenAddr, apiTLS.Certificates[0])
}

func (s *Server) runQUICBackhaulListener() error {
	if s.quicBackhaul == nil {
		return nil
	}
	for {
		conn, err := s.quicBackhaul.Accept(context.Background())
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleQUICBackhaulConn(conn)
	}
}

func (s *Server) handleQUICBackhaulConn(conn *quic.Conn) {
	control, err := transport.AcceptQUICBackhaulControl(context.Background(), conn)
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
		case errors.Is(err, errLeaseRejected):
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

	_ = control.Accept()
	s.registry.Touch(lease.Key(), conn.RemoteAddr().String(), time.Now())
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
