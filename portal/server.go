package portal

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/keyless_tls/relay/l4"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
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
	defaultHopOpenRetryWait = 250 * time.Millisecond
	DefaultPProfListenAddr  = "127.0.0.1:6060"
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
	PProfEnabled      bool
	PProfListenAddr   string
	ACME              acme.Config
}

func normalizeServerConfig(cfg ServerConfig) (ServerConfig, error) {
	cfg.PortalURL = strings.TrimSuffix(strings.TrimSpace(cfg.PortalURL), "/")
	cfg.IdentityPath = identity.ResolveRelayStateDir(cfg.IdentityPath)
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
	if cfg.PProfEnabled {
		cfg.PProfListenAddr = utils.StringOrDefault(strings.TrimSpace(cfg.PProfListenAddr), DefaultPProfListenAddr)
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

	cfg         *utils.Snapshot[ServerConfig]
	identity    types.RelayIdentity
	authority   identity.Authority
	acmeManager *acme.Manager
	proxy       proxy

	apiListener   net.Listener
	sniListener   net.Listener
	apiServer     *http.Server
	apiTLSClose   io.Closer
	pprofListener net.Listener
	pprofServer   *http.Server
	quicBackhaul  *quic.Listener

	overlay         *overlay.Overlay
	relaySet        *discovery.RelaySet
	announceLimiter *discovery.AnnounceLimiter
	registry        *leaseRegistry
}

func NewServer(cfg ServerConfig) (*Server, error) {
	cfg, err := normalizeServerConfig(cfg)
	if err != nil {
		return nil, err
	}

	relayIdentity, err := identity.LoadOrCreateRelayIdentity(cfg.IdentityPath, utils.PortalRootHost(cfg.PortalURL), cfg.DiscoveryEnabled)
	if err != nil {
		return nil, fmt.Errorf("load relay identity: %w", err)
	}
	relayAuthority, err := identity.NewLocalAuthority(relayIdentity.Identity)
	if err != nil {
		return nil, fmt.Errorf("load relay authority: %w", err)
	}
	registry, err := newLeaseRegistry(cfg.UDPEnabled, cfg.TCPEnabled, cfg.MinPort, cfg.MaxPort, relayIdentity.Name, cfg.SNIPort, relayAuthority, cfg.PortalURL, cfg.TrustProxyHeaders, cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	var relaySet *discovery.RelaySet
	if cfg.DiscoveryEnabled {
		cfg.Bootstraps, err = utils.ResolvePortalRelayURLs(cfg.Bootstraps, true)
		if err != nil {
			return nil, fmt.Errorf("resolve discovery bootstraps: %w", err)
		}
		cfg.Bootstraps = utils.RemoveRelayURL(cfg.Bootstraps, cfg.PortalURL)
		relaySet = discovery.NewRelaySet(cfg.Bootstraps)
	}

	server := &Server{
		cfg:             utils.NewSnapshot(cfg, ServerConfig.snapshot),
		identity:        relayIdentity,
		authority:       relayAuthority,
		registry:        registry,
		relaySet:        relaySet,
		announceLimiter: discovery.NewAnnounceLimiter(0, 0),
	}
	server.registry.proxy = &server.proxy
	return server, nil
}

func (s *Server) config() ServerConfig {
	return s.cfg.Load()
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

func (s *Server) Start(ctx context.Context, apiMux *http.ServeMux) error {
	if s.group != nil {
		return errors.New("server already started")
	}
	cfg := s.config()
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
	var pprofListener net.Listener
	var pprofServer *http.Server
	var ov *overlay.Overlay
	var quicBackhaul *quic.Listener
	defer func() {
		if started {
			return
		}
		acmeManager.Stop()
		if ov != nil {
			_ = ov.Shutdown(context.Background())
		}
		if apiServer != nil {
			_ = apiServer.Close()
		}
		if pprofServer != nil {
			_ = pprofServer.Close()
		}
		if pprofListener != nil {
			_ = pprofListener.Close()
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

	apiListener, err = listenConfig.Listen(serverCtx, "tcp", cfg.APIListenAddr)
	if err != nil {
		return fmt.Errorf("listen api: %w", err)
	}
	sniListener, err = listenConfig.Listen(serverCtx, "tcp", cfg.SNIListenAddr)
	if err != nil {
		return fmt.Errorf("listen sni: %w", err)
	}

	group, groupCtx := errgroup.WithContext(serverCtx)
	wrappedAPIListener, apiServer, apiCloser, err := s.newAPIServer(apiListener, apiMux, apiTLS)
	if err != nil {
		return err
	}
	if cfg.PProfEnabled {
		pprofListener, err = listenConfig.Listen(serverCtx, "tcp", cfg.PProfListenAddr)
		if err != nil {
			return fmt.Errorf("listen pprof: %w", err)
		}
		pprofMux := http.NewServeMux()
		pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
		pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		pprofServer = &http.Server{
			Handler:           pprofMux,
			ReadHeaderTimeout: 10 * time.Second,
		}
	}

	if s.relaySet != nil && strings.TrimSpace(s.identity.WireGuardPrivateKey) != "" {
		ov, err = s.startOverlay()
		if err != nil {
			return err
		}
	}
	if cfg.UDPEnabled {
		quicBackhaul, err = s.newQUICBackhaulListener(apiTLS)
		if err != nil {
			log.Warn().Err(err).Msg("quic backhaul listener disabled")
			quicBackhaul = nil
		}
	}

	s.apiListener = wrappedAPIListener
	s.sniListener = sniListener
	s.apiServer = apiServer
	s.apiTLSClose = apiCloser
	s.pprofListener = pprofListener
	s.pprofServer = pprofServer
	s.acmeManager = acmeManager
	s.cancel = cancel
	s.group = group
	s.overlay = ov
	s.quicBackhaul = quicBackhaul
	started = true

	group.Go(s.runAPIServer)
	if s.pprofServer != nil {
		group.Go(s.runPProfServer)
	}
	group.Go(func() error { return s.runPublicIngress(groupCtx) })
	if s.overlay != nil {
		group.Go(func() error { return s.overlay.Serve(groupCtx) })
	}
	if s.quicBackhaul != nil {
		group.Go(s.runQUICBackhaulListener)
	}
	group.Go(func() error { return s.runRegistryJanitor(groupCtx, 5*time.Second) })
	if cfg.DiscoveryEnabled {
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
		Str("acme_dns_provider", cfg.ACME.DNSProvider).
		Int("min_port", cfg.MinPort).
		Int("max_port", cfg.MaxPort).
		Bool("discovery_enabled", cfg.DiscoveryEnabled).
		Bool("wireguard_enabled", s.overlay != nil).
		Bool("multihop_enabled", s.overlay != nil).
		Bool("udp_enabled", s.quicBackhaul != nil).
		Bool("tcp_enabled", s.supportsTCP()).
		Bool("api_ech_enabled", len(apiTLS.EncryptedClientHelloKeys) > 0).
		Bool("pprof_enabled", s.pprofServer != nil)
	if s.pprofListener != nil {
		logEvent = logEvent.Str("pprof_addr", utils.HostPortOrLoopback(s.pprofListener.Addr().String()))
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

		records := s.registry.CloseAll()
		for _, record := range records {
			record.deleteDNS(ctx, s.acmeManager, true)
		}

		if s.quicBackhaul != nil {
			_ = s.quicBackhaul.Close()
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
		if s.pprofServer != nil {
			if err := s.pprofServer.Shutdown(ctx); err != nil && shutdownErr == nil {
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
	cfg := s.config()
	acmeCfg := cfg.ACME
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
	echSeed, err := identity.DeriveToken(
		s.identity.Identity,
		"relay-ech",
		s.identity.EncryptedClientHelloSeed,
		s.identity.Name,
	)
	if err != nil {
		manager.Stop()
		return keyless.TLSMaterialConfig{}, nil, fmt.Errorf("derive relay ech seed: %w", err)
	}
	echKeys, echConfigList, err := keyless.EncryptedClientHelloMaterials(echSeed, s.identity.Name)
	if err != nil {
		manager.Stop()
		return keyless.TLSMaterialConfig{}, nil, fmt.Errorf("prepare ech materials: %w", err)
	}
	if len(echKeys) > 0 {
		apiTLS.EncryptedClientHelloKeys = echKeys
		if err := manager.SyncECHConfig(ctx, s.identity.Name, echConfigList, cfg.SNIPort); err != nil {
			log.Warn().
				Err(err).
				Str("hostname", s.identity.Name).
				Msg("publish relay ech dns record")
		}
	}

	return apiTLS, manager, nil
}

func (s *Server) runAPIServer() error {
	err := s.apiServer.Serve(s.apiListener)
	if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) runPProfServer() error {
	err := s.pprofServer.Serve(s.pprofListener)
	if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
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

func (s *Server) bridgeLeaseConn(ctx context.Context, conn net.Conn, record *leaseRecord) error {
	if record.isExpired(time.Now()) {
		return errLeaseNotFound
	}
	if overlayIPv4, forwardToken, hasNextHop := record.nextHop(); hasNextHop {
		switch {
		case s.overlay == nil:
			return errors.New("relay overlay is unavailable")
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
			next, err = s.overlay.OpenHopStream(openCtx, overlayIPv4, forwardToken)
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
			records := s.registry.cleanupExpired(time.Now())
			for _, record := range records {
				record.deleteDNS(ctx, s.acmeManager, true)
			}
		}
	}
}

func (s *Server) newQUICBackhaulListener(apiTLS keyless.TLSMaterialConfig) (*quic.Listener, error) {
	if len(apiTLS.KeyPEM) == 0 {
		return nil, fmt.Errorf("quic backhaul requires api tls key")
	}
	tlsCert, err := tls.X509KeyPair(apiTLS.CertPEM, apiTLS.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse quic backhaul tls keypair: %w", err)
	}
	return transport.ListenQUICBackhaul(s.config().SNIListenAddr, tlsCert)
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

func (s *Server) startOverlay() (*overlay.Overlay, error) {
	cfg := s.config()
	peerMux := http.NewServeMux()
	peerMux.HandleFunc(types.PathRoot, s.handleRoot)
	peerMux.HandleFunc(types.PathHealthz, s.handleHealthz)
	if cfg.DiscoveryEnabled {
		peerMux.HandleFunc(types.PathDiscovery, s.handleRelayDiscovery)
	}

	ov, err := overlay.NewOverlay(overlay.Config{
		PrivateKey: s.identity.WireGuardPrivateKey,
		PublicKey:  s.identity.WireGuardPublicKey,
		ListenPort: cfg.WireGuardPort,
	}, peerMux, nil)
	if err != nil {
		return nil, fmt.Errorf("start wireguard overlay: %w", err)
	}

	ov.SetStreamHandler(func(ctx context.Context, stream overlay.HopStream) {
		s.registry.mu.RLock()
		record := s.registry.recordByHopToken(stream.Token, time.Now())
		s.registry.mu.RUnlock()
		if record == nil {
			log.Warn().Str("remote_addr", stream.RemoteAddr).Msg("hop stream rejected")
			_ = stream.Conn.Close()
			return
		}
		hopRole := "exit"
		if record.isHopMiddle() {
			hopRole = "middle"
		}
		log.Info().Str("remote_addr", stream.RemoteAddr).Str("hop_role", hopRole).Msg("hop stream received")

		if err := s.bridgeLeaseConn(ctx, stream.Conn, record); err != nil {
			log.Warn().Err(err).Str("remote_addr", stream.RemoteAddr).Msg("hop stream bridge failed")
			_ = stream.Conn.Close()
		}
	})

	if err := ov.Sync(s.relaySet.OverlayPeerDescriptor()); err != nil {
		_ = ov.Shutdown(context.Background())
		return nil, fmt.Errorf("sync wireguard peers: %w", err)
	}

	return ov, nil
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

	var wireGuardPublicKey string
	var wireGuardPort int
	supportsOverlay := false
	if s.overlay != nil {
		cfg := s.overlay.Config()
		wireGuardPublicKey = cfg.PublicKey
		wireGuardPort = cfg.ListenPort
		supportsOverlay = true
	}

	return auth.SignRelayDescriptor(types.RelayDescriptor{
		Address:            s.identity.Address,
		Version:            types.DiscoveryVersion,
		IssuedAt:           now,
		ExpiresAt:          now.Add(discovery.DiscoveryDescriptorTTL),
		APIHTTPSAddr:       cfg.PortalURL,
		WireGuardPublicKey: wireGuardPublicKey,
		WireGuardPort:      wireGuardPort,
		SupportsOverlay:    supportsOverlay,
		SupportsUDP:        s.supportsUDP(),
		SupportsTCP:        s.supportsTCP(),
		ActiveConnections:  s.proxy.activeConnectionCount(),
		TCPBPS:             s.proxy.currentTCPBPS(now),
	}, s.authority)
}
