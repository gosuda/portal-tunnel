package portal

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/keyless_tls/relay/l4"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/overlay"
	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultLeaseTTL         = 30 * time.Second
	defaultClaimTimeout     = 10 * time.Second
	defaultIdleKeepalive    = 15 * time.Second
	defaultReadyQueueLimit  = 8
	defaultClientHelloWait  = 2 * time.Second
	defaultControlBodyLimit = 4 << 20
	defaultHopOpenRetryWait = 250 * time.Millisecond
)

type ServerConfig struct {
	PortalURL         string
	IdentityPath      string
	Bootstraps        []string
	DiscoveryEnabled  bool
	WireGuardPort     int
	APIPort           int
	SNIPort           int
	APIListenAddr     string
	SNIListenAddr     string
	TrustProxyHeaders bool
	TrustedProxyCIDRs string
	UDPEnabled        bool
	TCPEnabled        bool
	MinPort           int
	MaxPort           int
	ACME              acme.Config
}

func normalizeServerConfig(cfg ServerConfig) (ServerConfig, error) {
	cfg.PortalURL = strings.TrimSuffix(strings.TrimSpace(cfg.PortalURL), "/")
	cfg.IdentityPath = utils.ResolveRelayStateDir(cfg.IdentityPath)
	if cfg.IdentityPath == "" {
		return ServerConfig{}, errors.New("identity path is required")
	}

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

	cfg.APIPort = utils.IntOrDefault(cfg.APIPort, 4017)
	cfg.SNIPort = utils.IntOrDefault(cfg.SNIPort, 443)
	cfg.WireGuardPort = utils.IntOrDefault(cfg.WireGuardPort, overlay.DefaultListenPort)
	cfg.APIListenAddr = utils.StringOrDefault(cfg.APIListenAddr, fmt.Sprintf(":%d", cfg.APIPort))
	cfg.SNIListenAddr = utils.StringOrDefault(cfg.SNIListenAddr, fmt.Sprintf(":%d", cfg.SNIPort))

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

	cfg.UDPEnabled = cfg.UDPEnabled && hasPortRange
	cfg.TCPEnabled = cfg.TCPEnabled && hasPortRange
	return cfg, nil
}

type Server struct {
	cancel       context.CancelFunc
	group        *errgroup.Group
	shutdownOnce sync.Once

	cfg         ServerConfig
	identity    types.RelayIdentity
	acmeManager *acme.Manager
	proxy       proxy

	descriptorIPFamiliesMu sync.RWMutex
	descriptorSupportsIPv4 bool
	descriptorSupportsIPv6 bool
	descriptorIPFamiliesAt time.Time

	apiListener net.Listener
	sniListener net.Listener
	apiServer   *http.Server
	apiTLSClose io.Closer
	quicTunnel  *quic.Listener

	overlay         *overlay.Overlay
	hopMux          *overlay.HopMux
	relaySet        *discovery.RelaySet
	announceLimiter *discovery.AnnounceLimiter
	registry        *leaseRegistry
	udpPorts        *transport.PortAllocator
	tcpPorts        *transport.PortAllocator
}

func NewServer(cfg ServerConfig) (*Server, error) {
	cfg, err := normalizeServerConfig(cfg)
	if err != nil {
		return nil, err
	}

	identity, err := utils.LoadOrCreateRelayIdentity(cfg.IdentityPath, utils.PortalRootHost(cfg.PortalURL), cfg.DiscoveryEnabled)
	if err != nil {
		return nil, fmt.Errorf("load relay identity: %w", err)
	}
	registry, err := newLeaseRegistry(cfg.UDPEnabled, cfg.TCPEnabled, cfg.TrustProxyHeaders, cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	var relaySet *discovery.RelaySet
	if cfg.DiscoveryEnabled {
		cfg.Bootstraps, err = utils.ResolvePortalRelayURLs(context.Background(), cfg.Bootstraps, true)
		if err != nil {
			return nil, fmt.Errorf("resolve discovery bootstraps: %w", err)
		}
		cfg.Bootstraps = utils.RemoveRelayURL(cfg.Bootstraps, cfg.PortalURL)
		relaySet = discovery.NewRelaySet(cfg.Bootstraps)
	}

	return &Server{
		cfg:             cfg,
		identity:        identity,
		registry:        registry,
		relaySet:        relaySet,
		announceLimiter: discovery.NewAnnounceLimiter(0, 0),
		udpPorts:        transport.NewPortAllocator(cfg.MinPort, cfg.MaxPort, 5*time.Minute),
		tcpPorts:        transport.NewPortAllocator(cfg.MinPort, cfg.MaxPort, 5*time.Minute),
	}, nil
}

func (s *Server) Start(ctx context.Context, apiMux *http.ServeMux) error {
	if s.group != nil {
		return errors.New("server already started")
	}
	apiTLS, acmeManager, err := s.prepareAPITLS(ctx)
	if err != nil {
		return err
	}

	serverCtx, cancel := context.WithCancel(ctx)
	started := false
	var apiListener net.Listener
	var sniListener net.Listener
	var apiServer *http.Server
	var apiCloser io.Closer
	var hopMux *overlay.HopMux
	var ov *overlay.Overlay
	var quicTunnel *quic.Listener
	defer func() {
		if started {
			return
		}
		acmeManager.Stop()
		if hopMux != nil {
			_ = hopMux.Close()
		}
		if ov != nil {
			_ = ov.Shutdown(context.Background())
		}
		if apiServer != nil {
			_ = apiServer.Close()
		}
		if apiCloser != nil {
			_ = apiCloser.Close()
		}
		if sniListener != nil {
			_ = sniListener.Close()
		}
		if apiListener != nil {
			_ = apiListener.Close()
		}
		cancel()
	}()
	var listenConfig net.ListenConfig

	apiListener, err = listenConfig.Listen(serverCtx, "tcp", s.cfg.APIListenAddr)
	if err != nil {
		return fmt.Errorf("listen api: %w", err)
	}
	sniListener, err = listenConfig.Listen(serverCtx, "tcp", s.cfg.SNIListenAddr)
	if err != nil {
		return fmt.Errorf("listen sni: %w", err)
	}

	group, groupCtx := errgroup.WithContext(serverCtx)
	wrappedAPIListener, apiServer, apiCloser, err := s.newAPIServer(apiListener, apiMux, apiTLS)
	if err != nil {
		return err
	}

	if s.relaySet != nil && strings.TrimSpace(s.identity.WireGuardPrivateKey) != "" {
		ov, err = s.startOverlay()
		if err != nil {
			return err
		}
		hopMux, err = overlay.NewHopMux(ov)
		if err != nil {
			return err
		}
	}
	if s.cfg.UDPEnabled {
		quicTunnel, err = s.newQUICTunnelListener(apiTLS)
		if err != nil {
			log.Warn().Err(err).Msg("quic tunnel listener disabled")
			quicTunnel = nil
		}
	}

	s.apiListener = wrappedAPIListener
	s.sniListener = sniListener
	s.apiServer = apiServer
	s.apiTLSClose = apiCloser
	s.acmeManager = acmeManager
	s.cancel = cancel
	s.group = group
	s.overlay = ov
	s.hopMux = hopMux
	s.quicTunnel = quicTunnel
	started = true

	group.Go(s.runAPIServer)
	group.Go(func() error { return s.runPublicIngress(groupCtx) })
	if s.overlay != nil {
		group.Go(s.overlay.Serve)
		if s.hopMux != nil {
			group.Go(func() error { return s.runOverlayIngress(groupCtx) })
		}
	}
	if s.quicTunnel != nil {
		group.Go(s.runQUICTunnelListener)
	}
	group.Go(func() error { return s.runRegistryJanitor(groupCtx, 5*time.Second) })
	if s.cfg.DiscoveryEnabled {
		group.Go(func() error { return s.runRelayDiscoveryLoop(groupCtx) })
	}
	s.acmeManager.Start(serverCtx)
	group.Go(func() error {
		<-groupCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.Shutdown(shutdownCtx)
	})

	logEvent := log.Info().
		Str("api_addr", utils.HostPortOrLoopback(s.apiListener.Addr().String())).
		Str("sni_addr", s.sniListener.Addr().String()).
		Str("root_host", s.identity.Name).
		Str("acme_dns_provider", s.cfg.ACME.DNSProvider).
		Int("min_port", s.cfg.MinPort).
		Int("max_port", s.cfg.MaxPort).
		Bool("discovery_enabled", s.cfg.DiscoveryEnabled).
		Bool("wireguard_enabled", s.overlay != nil).
		Bool("multihop_enabled", s.hopMux != nil).
		Bool("udp_enabled", s.quicTunnel != nil).
		Bool("tcp_enabled", s.cfg.TCPEnabled)
	if s.quicTunnel != nil {
		logEvent = logEvent.Str("internal_quic_tunnel_addr", s.quicTunnel.Addr().String())
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
	return s.cfg.PortalURL
}

func (s *Server) PublicLeases() []types.Lease {
	if s == nil || s.registry == nil {
		return nil
	}
	return s.registry.PublicLeases(time.Now())
}

func (s *Server) AdminLeases() []types.AdminLease {
	if s == nil || s.registry == nil {
		return nil
	}
	return s.registry.AdminLeases(time.Now())
}

func (s *Server) RelayIdentity() types.RelayIdentity {
	if s == nil {
		return types.RelayIdentity{}
	}
	return s.identity.Copy()
}

func (s *Server) Shutdown(ctx context.Context) error {
	var shutdownErr error
	s.shutdownOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}

		for _, lease := range s.registry.CloseAll() {
			s.cleanupRemovedRecord(ctx, lease, "delete lease remote state during shutdown")
		}

		if s.quicTunnel != nil {
			_ = s.quicTunnel.Close()
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
		if s.hopMux != nil {
			if err := s.hopMux.Close(); err != nil && shutdownErr == nil && !errors.Is(err, net.ErrClosed) {
				shutdownErr = err
			}
		}
		if s.overlay != nil {
			if err := s.overlay.Shutdown(ctx); err != nil && shutdownErr == nil {
				shutdownErr = err
			}
		}
		if s.apiTLSClose != nil {
			_ = s.apiTLSClose.Close()
		}
		if s.acmeManager != nil {
			s.acmeManager.Stop()
		}
	})
	return shutdownErr
}

func (s *Server) prepareAPITLS(ctx context.Context) (keyless.TLSMaterialConfig, *acme.Manager, error) {
	acmeCfg := s.cfg.ACME
	if baseDomain := utils.NormalizeHostname(acmeCfg.BaseDomain); baseDomain != "" && baseDomain != s.identity.Name {
		return keyless.TLSMaterialConfig{}, nil, fmt.Errorf("acme base domain %q does not match portal root host %q", acmeCfg.BaseDomain, s.identity.Name)
	}
	acmeCfg.BaseDomain = s.identity.Name
	if strings.TrimSpace(acmeCfg.ENSGaslessAddress) == "" {
		acmeCfg.ENSGaslessAddress = s.identity.Address
	}

	manager, err := acme.NewManager(acmeCfg)
	if err != nil {
		return keyless.TLSMaterialConfig{}, nil, fmt.Errorf("create acme manager: %w", err)
	}

	certPEM, keyPEM, err := manager.EnsureTLSMaterial(ctx)
	if err != nil {
		manager.Stop()
		return keyless.TLSMaterialConfig{}, nil, fmt.Errorf("ensure relay certificate: %w", err)
	}

	apiTLS := keyless.TLSMaterialConfig{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}
	if len(apiTLS.CertPEM) == 0 {
		manager.Stop()
		return keyless.TLSMaterialConfig{}, nil, errors.New("api tls certificate is required")
	}
	if len(apiTLS.KeyPEM) == 0 && apiTLS.Keyless == nil {
		manager.Stop()
		return keyless.TLSMaterialConfig{}, nil, errors.New("api tls key or keyless signer is required")
	}

	return apiTLS, manager, nil
}

func (s *Server) runPublicIngress(ctx context.Context) error {
	for {
		conn, err := s.sniListener.Accept()
		switch {
		case err == nil:
			go func(conn net.Conn) {
				clientHello, wrappedConn, err := l4.InspectClientHello(conn, defaultClientHelloWait)
				if err != nil {
					if wrappedConn != nil {
						_ = wrappedConn.Close()
					} else {
						_ = conn.Close()
					}
					return
				}

				serverName := utils.NormalizeHostname(clientHello.ServerName)
				if serverName == "" {
					_ = wrappedConn.Close()
					return
				}

				if serverName == s.identity.Name {
					if s.apiListener == nil {
						_ = wrappedConn.Close()
						return
					}
					dialer := &net.Dialer{Timeout: 5 * time.Second}
					upstream, err := dialer.DialContext(ctx, "tcp", utils.HostPortOrLoopback(s.apiListener.Addr().String()))
					if err != nil {
						_ = wrappedConn.Close()
						return
					}
					s.proxy.bridge(wrappedConn, upstream, "", nil)
					return
				}

				record, ok := s.registry.Lookup(serverName)
				if !ok {
					_ = wrappedConn.Close()
					return
				}
				if err := s.bridgeLeaseConn(ctx, wrappedConn, record); err != nil {
					log.Warn().Err(err).Str("server_name", serverName).Msg("bridge public ingress")
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

func (s *Server) runOverlayIngress(ctx context.Context) error {
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error { return s.hopMux.Serve(groupCtx) })
	group.Go(func() error {
		for {
			stream, err := s.hopMux.Accept(groupCtx)
			if err != nil {
				if ctxErr := groupCtx.Err(); ctxErr != nil {
					return ctxErr
				}
				return err
			}
			go func(stream overlay.HopStream) {
				record, ok := s.registry.RecordByHopToken(stream.Token, time.Now())
				if !ok {
					log.Warn().Str("remote_addr", stream.RemoteAddr).Msg("hop stream rejected")
					_ = stream.Conn.Close()
					return
				}
				hopRole := "exit"
				if record.isHopMiddle() {
					hopRole = "middle"
				}
				log.Info().Str("remote_addr", stream.RemoteAddr).Str("hop_role", hopRole).Msg("hop stream received")

				if err := s.bridgeLeaseConn(groupCtx, stream.Conn, record); err != nil {
					log.Warn().Err(err).Str("remote_addr", stream.RemoteAddr).Msg("hop stream bridge failed")
					_ = stream.Conn.Close()
				}
			}(stream)
		}
	})
	return group.Wait()
}

func (s *Server) bridgeLeaseConn(ctx context.Context, conn net.Conn, record *leaseRecord) error {
	if record.isExpired(time.Now()) {
		return errLeaseNotFound
	}
	if overlayIPv4, forwardToken, hasNextHop := record.nextHop(); hasNextHop {
		switch {
		case overlayIPv4 == "":
			return errors.New("next hop overlay ipv4 is required")
		case forwardToken == "":
			return errors.New("next hop token is required")
		}

		openCtx, cancel := context.WithTimeout(ctx, defaultClaimTimeout)
		defer cancel()
		var next net.Conn
		var lastErr error
		for {
			var err error
			next, err = s.hopMux.OpenStream(openCtx, overlayIPv4, forwardToken)
			if err == nil {
				break
			}
			lastErr = err
			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("open next hop stream: %w", err)
			}
			if !utils.SleepOrDone(openCtx, defaultHopOpenRetryWait) {
				return fmt.Errorf("open next hop stream within %s: %w", defaultClaimTimeout, errors.Join(lastErr, openCtx.Err()))
			}
		}
		s.proxy.bridge(conn, next, "", nil)
		return nil
	}
	if record.stream == nil {
		return errors.New("lease stream is not ready")
	}
	if !s.registry.policy.IsIdentityRoutable(record.Key()) {
		return errLeaseRejected
	}
	claimCtx, cancel := context.WithTimeout(ctx, defaultClaimTimeout)
	session, err := record.stream.Claim(claimCtx)
	cancel()
	if err != nil {
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
			for _, lease := range s.registry.cleanupExpired(time.Now()) {
				s.cleanupRemovedRecord(context.Background(), lease, "delete expired lease remote state")
			}
		}
	}
}

func (s *Server) newQUICTunnelListener(apiTLS keyless.TLSMaterialConfig) (*quic.Listener, error) {
	if len(apiTLS.KeyPEM) == 0 {
		return nil, fmt.Errorf("quic tunnel requires api tls key")
	}
	tlsCert, err := tls.X509KeyPair(apiTLS.CertPEM, apiTLS.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse quic tls keypair: %w", err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"portal-tunnel"},
		MinVersion:   tls.VersionTLS13,
	}
	quicConf := &quic.Config{
		EnableDatagrams:    true,
		KeepAlivePeriod:    15 * time.Second,
		MaxIdleTimeout:     60 * time.Second,
		MaxIncomingStreams: 16,
	}

	listener, err := quic.ListenAddr(s.cfg.SNIListenAddr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("listen quic: %w", err)
	}
	return listener, nil
}

func (s *Server) runQUICTunnelListener() error {
	if s.quicTunnel == nil {
		return nil
	}
	for {
		conn, err := s.quicTunnel.Accept(context.Background())
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleQUICTunnelConn(conn)
	}
}

func (s *Server) startOverlay() (*overlay.Overlay, error) {
	peerMux := http.NewServeMux()
	peerMux.HandleFunc(types.PathRoot, s.handleRoot)
	peerMux.HandleFunc(types.PathHealthz, s.handleHealthz)
	if s.cfg.DiscoveryEnabled {
		peerMux.HandleFunc(types.PathDiscovery, s.handleRelayDiscovery)
	}

	overlay, err := overlay.NewOverlay(overlay.Config{
		PrivateKey: s.identity.WireGuardPrivateKey,
		PublicKey:  s.identity.WireGuardPublicKey,
		ListenPort: s.cfg.WireGuardPort,
	}, peerMux)
	if err != nil {
		return nil, fmt.Errorf("start wireguard overlay: %w", err)
	}

	if err := overlay.Sync(s.relaySet.OverlayPeerStates()); err != nil {
		_ = overlay.Shutdown(context.Background())
		return nil, fmt.Errorf("sync wireguard peers: %w", err)
	}

	return overlay, nil
}

func (s *Server) runRelayDiscoveryLoop(ctx context.Context) error {
	if s.relaySet == nil {
		<-ctx.Done()
		return nil
	}
	refresher := discovery.NewRefresher(s.relaySet, s.overlay)
	ticker := time.NewTicker(discovery.DiscoveryPollInterval)
	defer ticker.Stop()

	for {
		now := time.Now().UTC()
		self, err := s.signedRelayDescriptor(now)
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
