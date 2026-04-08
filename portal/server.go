package portal

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"hash/crc32"
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
	"github.com/gosuda/portal-tunnel/v2/utils/thumbnail"
)

const (
	defaultLeaseTTL         = 30 * time.Second
	defaultClaimTimeout     = 10 * time.Second
	defaultIdleKeepalive    = 15 * time.Second
	defaultReadyQueueLimit  = 8
	defaultClientHelloWait  = 2 * time.Second
	defaultControlBodyLimit = 4 << 20
)

type ServerConfig struct {
	PortalURL         string
	IdentityPath      string
	Bootstraps        []string
	ACME              acme.Config
	APIPort           int
	SNIPort           int
	APIListenAddr     string
	SNIListenAddr     string
	TrustedProxyCIDRs string
	TrustProxyHeaders bool
	DiscoveryEnabled  bool
	MaxRouting        int
	OverlayEnabled    bool
	OverlayMaxHops    int
	OverlayCongestion float64
	MinPort           int
	MaxPort           int
	UDPEnabled        bool
	TCPEnabled        bool
	HeadlessShellURL  string
}

type Server struct {
	sniListener       net.Listener
	apiListener       net.Listener
	apiServer         *http.Server
	apiTLSClose       io.Closer
	acmeManager       *acme.Manager
	quicTunnel        *quic.Listener
	cancel            context.CancelFunc
	group             *errgroup.Group
	registry          *leaseRegistry
	ports             *transport.PortAllocator
	tcpPorts          *transport.PortAllocator
	loadMgr           *policy.LoadManager
	weightMgr         *policy.WeightManager
	identity          types.Identity
	cfg               ServerConfig
	trustedProxyCIDRs []*net.IPNet
	discoveryMgr      *discovery.Manager
	overlayPolicy     *overlay.RoutePolicy
	overlayRoute      []uint32
	overlayRouteMu    sync.RWMutex
	thumbnails        *thumbnail.Service
	shutdownOnce      sync.Once
}

func NewServer(cfg ServerConfig) (*Server, error) {
	cfg.PortalURL = strings.TrimSuffix(strings.TrimSpace(cfg.PortalURL), "/")
	cfg.APIPort = utils.IntOrDefault(cfg.APIPort, 4017)
	cfg.SNIPort = utils.IntOrDefault(cfg.SNIPort, 443)
	cfg.APIListenAddr = utils.StringOrDefault(cfg.APIListenAddr, fmt.Sprintf(":%d", cfg.APIPort))
	cfg.SNIListenAddr = utils.StringOrDefault(cfg.SNIListenAddr, fmt.Sprintf(":%d", cfg.SNIPort))
	rootHost := utils.PortalRootHost(cfg.PortalURL)
	if rootHost == "" {
		return nil, errors.New("root host is required")
	}
	trustedProxyCIDRs, err := utils.ParseCIDRs(cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, fmt.Errorf("parse trusted proxy cidrs: %w", err)
	}
	bootstraps, err := utils.NormalizeRelayURLs(cfg.Bootstraps...)
	if err != nil {
		return nil, fmt.Errorf("normalize bootstraps: %w", err)
	}
	selfRelayURL := ""
	if trimmedPortalURL := strings.TrimSpace(cfg.PortalURL); trimmedPortalURL != "" {
		normalizedPortalURL, err := utils.NormalizeRelayURL(trimmedPortalURL)
		if err != nil {
			return nil, fmt.Errorf("normalize portal url: %w", err)
		}
		selfRelayURL = normalizedPortalURL
	}
	if len(bootstraps) > 0 {
		filtered := bootstraps[:0]
		for _, relayURL := range bootstraps {
			if selfRelayURL != "" && relayURL == selfRelayURL {
				continue
			}
			filtered = append(filtered, relayURL)
		}
		bootstraps = filtered
	}
	cfg.Bootstraps = bootstraps
	if cfg.OverlayMaxHops < 0 {
		return nil, errors.New("overlay max hops must be >= 0")
	}
	if cfg.OverlayMaxHops > 10 {
		return nil, errors.New("overlay max hops must be <= 10")
	}
	if cfg.OverlayCongestion <= 0 {
		cfg.OverlayCongestion = 120
	}
	cfg.OverlayEnabled = cfg.OverlayEnabled && cfg.OverlayMaxHops > 0
	transportEnabled := cfg.UDPEnabled || cfg.TCPEnabled
	hasPortRange := cfg.MinPort > 0 && cfg.MaxPort > 0
	if transportEnabled {
		switch {
		case !hasPortRange:
			return nil, errors.New("udp and tcp relay transport require a valid min port and max port range")
		case cfg.MinPort > 65535 || cfg.MaxPort > 65535:
			return nil, errors.New("min port and max port must be between 1 and 65535")
		case cfg.MinPort > cfg.MaxPort:
			return nil, errors.New("min port must be less than or equal to max port")
		}
	}

	cfg.UDPEnabled = cfg.UDPEnabled && hasPortRange
	cfg.TCPEnabled = cfg.TCPEnabled && hasPortRange

	portMin, portMax := 0, 0
	if cfg.UDPEnabled {
		portMin = cfg.MinPort
		portMax = cfg.MaxPort
	}

	identity, created, err := utils.LoadOrCreateIdentity(cfg.IdentityPath, types.Identity{Name: rootHost})
	if err != nil {
		return nil, fmt.Errorf("load relay identity: %w", err)
	}
	if created {
		log.Warn().
			Str("identity_path", cfg.IdentityPath).
			Str("address", identity.Address).
			Msg("generated relay identity and saved it to disk")
	} else {
		log.Info().
			Str("identity_path", cfg.IdentityPath).
			Str("address", identity.Address).
			Msg("loaded relay identity from disk")
	}

	tcpPortMin, tcpPortMax := 0, 0
	if cfg.TCPEnabled {
		tcpPortMin = cfg.MinPort
		tcpPortMax = cfg.MaxPort
	}

	runtimePolicy := policy.NewRuntime()
	runtimePolicy.SetUDPPolicy(cfg.UDPEnabled, 0)
	runtimePolicy.SetTCPPortPolicy(cfg.TCPEnabled, 0)
	registry := newLeaseRegistry(runtimePolicy)
	ports := transport.NewPortAllocator(portMin, portMax, 5*time.Minute)
	tcpPorts := transport.NewPortAllocator(tcpPortMin, tcpPortMax, 5*time.Minute)

	s := &Server{
		cfg:               cfg,
		registry:          registry,
		ports:             ports,
		tcpPorts:          tcpPorts,
		loadMgr:           policy.NewLoadManager(),
		weightMgr:         policy.NewWeightManager(),
		identity:          identity,
		trustedProxyCIDRs: trustedProxyCIDRs,
		thumbnails:        thumbnail.NewService(cfg.HeadlessShellURL),
	}
	if cfg.OverlayEnabled {
		s.overlayPolicy = overlay.NewRoutePolicy()
	}
	if cfg.DiscoveryEnabled {
		manager, err := discovery.NewManager(discovery.ManagerConfig{
			Identity:   identity,
			PortalURL:  cfg.PortalURL,
			Bootstraps: cfg.Bootstraps,
			MaxRouting: cfg.MaxRouting,
		})
		if err != nil {
			return nil, err
		}
		s.discoveryMgr = manager
	}

	return s, nil
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
	var listenConfig net.ListenConfig

	apiListener, err := listenConfig.Listen(serverCtx, "tcp", s.cfg.APIListenAddr)
	if err != nil {
		acmeManager.Stop()
		cancel()
		return fmt.Errorf("listen api: %w", err)
	}
	sniListener, err := listenConfig.Listen(serverCtx, "tcp", s.cfg.SNIListenAddr)
	if err != nil {
		acmeManager.Stop()
		_ = apiListener.Close()
		cancel()
		return fmt.Errorf("listen sni: %w", err)
	}

	group, groupCtx := errgroup.WithContext(serverCtx)
	wrappedAPIListener, apiServer, apiCloser, err := s.newAPIServer(apiListener, apiMux, apiTLS)
	if err != nil {
		acmeManager.Stop()
		_ = apiListener.Close()
		_ = sniListener.Close()
		cancel()
		return err
	}

	s.apiListener = wrappedAPIListener
	s.sniListener = sniListener
	s.apiServer = apiServer
	s.apiTLSClose = apiCloser
	s.acmeManager = acmeManager
	s.cancel = cancel
	s.group = group

	group.Go(s.runAPIServer)
	group.Go(func() error { return s.runSNIListener(groupCtx) })
	group.Go(func() error { return s.runLeaseJanitor(groupCtx, 5*time.Second) })
	if s.cfg.DiscoveryEnabled {
		group.Go(func() error { return s.runRelayDiscoveryLoop(groupCtx) })
	}
	s.acmeManager.Start(serverCtx)

	if s.cfg.UDPEnabled {
		if err := s.startQUICTunnelListener(apiTLS); err != nil {
			log.Warn().Err(err).Msg("quic tunnel listener disabled")
		}
	}
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
		Bool("overlay_enabled", s.cfg.OverlayEnabled).
		Int("overlay_max_hops", s.cfg.OverlayMaxHops).
		Bool("udp_enabled", s.cfg.UDPEnabled).
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

func (s *Server) Identity() types.Identity {
	if s == nil {
		return types.Identity{}
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
			if lease != nil {
				if s.acmeManager != nil {
					deleteCtx, cancel := context.WithTimeout(ctx, defaultClaimTimeout)
					if err := s.acmeManager.DeleteENSGaslessHostname(deleteCtx, lease.Hostname); err != nil {
						log.Warn().
							Err(err).
							Str("hostname", lease.Hostname).
							Str("address", lease.Address).
							Msg("delete lease ens gasless txt during shutdown")
					}
					cancel()
				}
				lease.Close()
			}
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
		if s.apiTLSClose != nil {
			_ = s.apiTLSClose.Close()
		}
		if s.acmeManager != nil {
			s.acmeManager.Stop()
		}
		if s.thumbnails != nil {
			s.thumbnails.Close()
		}
	})
	return shutdownErr
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

func (s *Server) LeaseSnapshots() []types.Lease {
	s.registry.mu.RLock()
	defer s.registry.mu.RUnlock()

	now := time.Now()
	records := make([]*leaseRecord, 0, len(s.registry.leasesByKey))
	for _, record := range s.registry.leasesByKey {
		records = append(records, record)
	}
	snapshots := make([]types.Lease, 0, len(records))
	for _, record := range records {
		if now.After(record.ExpiresAt) {
			continue
		}
		adminSnapshot := s.registry.AdminSnapshot(record)
		since := time.Duration(0)
		if !adminSnapshot.LastSeenAt.IsZero() {
			since = max(now.Sub(adminSnapshot.LastSeenAt), 0)
		}
		if adminSnapshot.IsBanned || adminSnapshot.IsDenied || !adminSnapshot.IsApproved || adminSnapshot.Metadata.Hide {
			continue
		}
		if adminSnapshot.Ready == 0 && since >= 3*time.Minute {
			continue
		}
		snapshots = append(snapshots, adminSnapshot.Lease)
	}
	return snapshots
}

func (s *Server) AdminLeaseSnapshots() []types.AdminLease {
	s.registry.mu.RLock()
	defer s.registry.mu.RUnlock()

	now := time.Now()
	records := make([]*leaseRecord, 0, len(s.registry.leasesByKey))
	for _, record := range s.registry.leasesByKey {
		records = append(records, record)
	}
	snapshots := make([]types.AdminLease, 0, len(records))
	for _, record := range records {
		if now.After(record.ExpiresAt) {
			continue
		}
		snapshots = append(snapshots, s.registry.AdminSnapshot(record))
	}
	return snapshots
}

func (s *Server) LeaseSnapshotByHostname(hostname string) (types.Lease, bool) {
	if s == nil || s.registry == nil {
		return types.Lease{}, false
	}

	record, ok := s.registry.Lookup(hostname)
	if !ok || record == nil || time.Now().After(record.ExpiresAt) {
		return types.Lease{}, false
	}
	return s.registry.Snapshot(record), true
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

func (s *Server) runSNIListener(ctx context.Context) error {
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
					s.BridgeConns(wrappedConn, upstream)
					return
				}

				record, ok := s.registry.Lookup(serverName)
				if !ok || record == nil || time.Now().After(record.ExpiresAt) || !s.registry.policy.IsIdentityRoutable(record.Key()) || record.stream == nil {
					_ = wrappedConn.Close()
					return
				}

				claimCtx, cancel := context.WithTimeout(ctx, defaultClaimTimeout)
				defer cancel()

				session, err := record.stream.Claim(claimCtx)
				if err != nil {
					_ = wrappedConn.Close()
					return
				}

				s.BridgeConns(wrappedConn, session)
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

func (s *Server) runLeaseJanitor(ctx context.Context, interval time.Duration) error {
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
				deleteCtx, cancel := context.WithTimeout(context.Background(), defaultClaimTimeout)
				err := s.acmeManager.DeleteENSGaslessHostname(deleteCtx, lease.Hostname)
				cancel()
				if err != nil {
					log.Warn().
						Err(err).
						Str("hostname", lease.Hostname).
						Str("address", lease.Address).
						Msg("delete expired lease ens gasless txt")
				}
				if s.thumbnails != nil {
					s.thumbnails.Remove(lease.Hostname)
				}
				lease.Close()
			}
		}
	}
}

func (s *Server) startQUICTunnelListener(apiTLS keyless.TLSMaterialConfig) error {
	if len(apiTLS.KeyPEM) == 0 {
		return fmt.Errorf("quic tunnel requires api tls key")
	}
	tlsCert, err := tls.X509KeyPair(apiTLS.CertPEM, apiTLS.KeyPEM)
	if err != nil {
		return fmt.Errorf("parse quic tls keypair: %w", err)
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
		return fmt.Errorf("listen quic: %w", err)
	}

	s.quicTunnel = listener
	s.group.Go(func() error { return s.runQUICTunnelListener(listener) })

	log.Info().
		Str("internal_quic_tunnel_addr", listener.Addr().String()).
		Msg("internal quic tunnel listener started")
	return nil
}

func (s *Server) runQUICTunnelListener(listener *quic.Listener) error {
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleQUICTunnelConn(conn)
	}
}

func (s *Server) runRelayDiscoveryLoop(ctx context.Context) error {
	if s.discoveryMgr == nil {
		<-ctx.Done()
		return nil
	}
	return s.discoveryMgr.Run(ctx, s.handleDiscoverySnapshot)
}

func (s *Server) handleDiscoverySnapshot(_ map[string]types.RelayState) {
	if s.discoveryMgr == nil || s.overlayPolicy == nil || !s.cfg.OverlayEnabled {
		return
	}
	descs := s.discoveryMgr.ActiveRelayDescriptors()
	if len(descs) == 0 {
		s.overlayRouteMu.Lock()
		s.overlayRoute = nil
		s.overlayRouteMu.Unlock()
		return
	}

	candidates := make([]uint32, 0, len(descs))
	for _, d := range descs {
		if d.Key() == "" {
			continue
		}
		candidates = append(candidates, crc32.ChecksumIEEE([]byte(d.Key())))
	}
	if len(candidates) == 0 {
		return
	}
	selfID := crc32.ChecksumIEEE([]byte(s.identity.Key()))
	route, err := s.overlayPolicy.BuildRouteWithLoad(selfID, candidates, s.cfg.OverlayMaxHops, s.weightMgr.Collect(), s.cfg.OverlayCongestion)
	if err != nil {
		return
	}
	s.overlayRouteMu.Lock()
	s.overlayRoute = route
	s.overlayRouteMu.Unlock()
}

func (s *Server) OverlayRoute() []uint32 {
	if s == nil {
		return nil
	}
	s.overlayRouteMu.RLock()
	defer s.overlayRouteMu.RUnlock()
	if len(s.overlayRoute) == 0 {
		return nil
	}
	out := make([]uint32, len(s.overlayRoute))
	copy(out, s.overlayRoute)
	return out
}

func (s *Server) BridgeConns(left, right net.Conn) {
	s.loadMgr.RecordConnStart()
	defer s.loadMgr.RecordConnEnd()

	defer left.Close()
	defer right.Close()

	var group errgroup.Group
	group.Go(func() error {
		n, err := io.Copy(right, left)
		s.loadMgr.RecordBytesIn(n)
		closeWrite(right)
		return err
	})
	group.Go(func() error {
		n, err := io.Copy(left, right)
		s.loadMgr.RecordBytesOut(n)
		closeWrite(left)
		return err
	})
	_ = group.Wait()
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}
