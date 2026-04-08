package portal

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
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
	"github.com/gosuda/portal-tunnel/v2/portal/wireguard"
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
	PortalURL           string
	IdentityPath        string
	Bootstraps          []string
	WireGuardPrivateKey string
	WireGuardEndpoint   string
	WireGuardPublicKey  string
	OverlayIPv4         string
	OverlayCIDRs        []string
	ACME                acme.Config
	APIPort             int
	SNIPort             int
	APIListenAddr       string
	SNIListenAddr       string
	TrustedProxyCIDRs   string
	TrustProxyHeaders   bool
	DiscoveryEnabled    bool
	MaxRouting          int
	OverlayEnabled      bool
	OverlayMaxHops      int
	OverlayCongestion   float64
	MinPort             int
	MaxPort             int
	UDPEnabled          bool
	TCPEnabled          bool
	HeadlessShellURL    string
}

type Server struct {
	sniListener       net.Listener
	apiListener       net.Listener
	apiServer         *http.Server
	wgPeerListener    net.Listener
	wgPeerServer      *http.Server
	apiTLSClose       io.Closer
	acmeManager       *acme.Manager
	quicTunnel        *quic.Listener
	wgRuntime         *wireguard.Runtime
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
	wireGuardConfigured := strings.TrimSpace(cfg.WireGuardPrivateKey) != "" ||
		strings.TrimSpace(cfg.WireGuardEndpoint) != "" ||
		strings.TrimSpace(cfg.WireGuardPublicKey) != "" ||
		strings.TrimSpace(cfg.OverlayIPv4) != "" ||
		len(cfg.OverlayCIDRs) > 0
	if wireGuardConfigured {
		if strings.TrimSpace(cfg.WireGuardPrivateKey) == "" {
			return nil, errors.New("wireguard private key is required when overlay is enabled")
		}
		if strings.TrimSpace(cfg.WireGuardEndpoint) == "" {
			return nil, errors.New("wireguard endpoint is required when overlay is enabled")
		}
		normalizedKey, err := utils.NormalizeWireGuardPrivateKey(cfg.WireGuardPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("normalize wireguard private key: %w", err)
		}
		cfg.WireGuardPrivateKey = normalizedKey
		if strings.TrimSpace(cfg.WireGuardPublicKey) == "" {
			publicKey, err := utils.WireGuardPublicKeyFromPrivate(cfg.WireGuardPrivateKey)
			if err != nil {
				return nil, fmt.Errorf("derive wireguard public key: %w", err)
			}
			cfg.WireGuardPublicKey = publicKey
		}
		if strings.TrimSpace(cfg.OverlayIPv4) == "" {
			overlayIP, err := utils.DeriveWireGuardOverlayIPv4(cfg.WireGuardPublicKey)
			if err != nil {
				return nil, fmt.Errorf("derive overlay ipv4: %w", err)
			}
			cfg.OverlayIPv4 = overlayIP
		}
		cfg.OverlayCIDRs = utils.NormalizeIPPrefixes(cfg.OverlayCIDRs)
	}
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
	if wireGuardConfigured {
		cfg.OverlayEnabled = true
	}
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

	if s.wireGuardPeerPlaneEnabled() {
		if err := s.startWireGuardPeerPlane(); err != nil {
			acmeManager.Stop()
			_ = apiServer.Close()
			_ = apiCloser.Close()
			_ = sniListener.Close()
			cancel()
			return fmt.Errorf("start wireguard peer plane: %w", err)
		}
	}

	group.Go(s.runAPIServer)
	if s.wgPeerServer != nil && s.wgPeerListener != nil {
		group.Go(s.runWireGuardPeerAPIServer)
		group.Go(func() error { return s.runWireGuardSyncLoop(groupCtx) })
	}
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
		Bool("wireguard_enabled", s.wireGuardPeerPlaneEnabled()).
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
		if s.wgPeerServer != nil {
			if err := s.wgPeerServer.Shutdown(ctx); err != nil && shutdownErr == nil && !errors.Is(err, http.ErrServerClosed) {
				shutdownErr = err
			}
		}
		if s.wgPeerListener != nil {
			_ = s.wgPeerListener.Close()
		}
		if s.wgRuntime != nil {
			_ = s.wgRuntime.Close()
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

func (s *Server) wireGuardPeerPlaneEnabled() bool {
	if s == nil {
		return false
	}
	return strings.TrimSpace(s.cfg.WireGuardPrivateKey) != "" &&
		strings.TrimSpace(s.cfg.WireGuardEndpoint) != "" &&
		strings.TrimSpace(s.cfg.WireGuardPublicKey) != "" &&
		strings.TrimSpace(s.cfg.OverlayIPv4) != ""
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

func (s *Server) startWireGuardPeerPlane() error {
	if s == nil {
		return nil
	}
	runtime, err := wireguard.NewRuntime(wireguard.RuntimeConfig{
		PrivateKey:  s.cfg.WireGuardPrivateKey,
		Endpoint:    s.cfg.WireGuardEndpoint,
		OverlayIPv4: s.cfg.OverlayIPv4,
	})
	if err != nil {
		return err
	}

	listener, err := runtime.ListenTCP(wireguard.DefaultPeerAPIHTTPPort)
	if err != nil {
		_ = runtime.Close()
		return fmt.Errorf("listen wireguard peer api: %w", err)
	}

	server := &http.Server{
		Handler:           s.peerAPIHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	s.wgRuntime = runtime
	s.wgPeerListener = listener
	s.wgPeerServer = server
	if err := s.syncWireGuardPeers(); err != nil {
		_ = server.Close()
		_ = runtime.Close()
		s.wgRuntime = nil
		s.wgPeerListener = nil
		s.wgPeerServer = nil
		return err
	}
	return nil
}

func (s *Server) peerAPIHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(types.PathRoot, s.handleRoot)
	mux.HandleFunc(types.PathHealthz, s.handleHealthz)
	if s.cfg.DiscoveryEnabled {
		mux.HandleFunc(types.PathDiscovery, s.handleRelayDiscovery)
	}
	mux.HandleFunc(types.PathOverlayHealth, s.handleOverlayHealth)
	return mux
}

func (s *Server) runWireGuardPeerAPIServer() error {
	if s == nil || s.wgPeerServer == nil || s.wgPeerListener == nil {
		return nil
	}
	err := s.wgPeerServer.Serve(s.wgPeerListener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) runWireGuardSyncLoop(ctx context.Context) error {
	if s.wgRuntime == nil {
		<-ctx.Done()
		return nil
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if err := s.syncWireGuardPeers(); err != nil {
			log.Warn().Err(err).Msg("sync wireguard peers failed")
		}
		s.pollOverlayHealth(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (s *Server) desiredWireGuardPeers() []types.DesiredPeer {
	if s.discoveryMgr == nil {
		return nil
	}
	descs := s.discoveryMgr.ActiveRelayDescriptors()
	if len(descs) == 0 {
		return nil
	}
	selfKey := s.identity.Key()
	peers := make([]types.DesiredPeer, 0, len(descs))
	for _, desc := range descs {
		nodeKey := relayNodeKey(desc)
		if nodeKey == "" || nodeKey == selfKey {
			continue
		}
		if !desc.SupportsOverlayPeer {
			continue
		}
		if strings.TrimSpace(desc.WireGuardPublicKey) == "" ||
			strings.TrimSpace(desc.WireGuardEndpoint) == "" ||
			strings.TrimSpace(desc.OverlayIPv4) == "" {
			continue
		}
		allowed := []string{desc.OverlayIPv4 + "/32"}
		if len(desc.OverlayCIDRs) > 0 {
			allowed = append(allowed, desc.OverlayCIDRs...)
		}
		peers = append(peers, types.DesiredPeer{
			RelayID:            nodeKey,
			WireGuardPublicKey: desc.WireGuardPublicKey,
			WireGuardEndpoint:  desc.WireGuardEndpoint,
			AllowedIPs:         allowed,
		})
	}
	return peers
}

func (s *Server) syncWireGuardPeers() error {
	if s.wgRuntime == nil {
		return nil
	}
	peers := s.desiredWireGuardPeers()
	return s.wgRuntime.ApplyPeers(peers)
}

func (s *Server) pollOverlayHealth(ctx context.Context) {
	if s.wgRuntime == nil || s.overlayPolicy == nil || s.discoveryMgr == nil {
		return
	}
	descs := s.discoveryMgr.ActiveRelayDescriptors()
	for _, desc := range descs {
		nodeKey := relayNodeKey(desc)
		if nodeKey == "" || nodeKey == strings.TrimSpace(s.cfg.PortalURL) {
			continue
		}
		if !desc.SupportsOverlayPeer || strings.TrimSpace(desc.OverlayIPv4) == "" {
			continue
		}
		peerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		resp, err := s.wgRuntime.FetchOverlayHealth(peerCtx, desc.OverlayIPv4, wireguard.DefaultPeerAPIHTTPPort)
		cancel()
		if err != nil {
			log.Debug().
				Err(err).
				Str("peer", desc.Name).
				Msg("overlay health fetch failed")
			continue
		}
		s.overlayPolicy.UpdateNodeHealth(resp.NodeID, policy.RelayHealth{
			RTTMs:         resp.Health.RTTMs,
			PingLatencyMs: resp.Health.PingLatency,
			Healthy:       resp.Health.Healthy,
			ErrorPct:      resp.Health.ErrorPct,
			Fallback:      resp.Health.Fallback,
		})
	}
}

func (s *Server) localRelayHealth() policy.RelayHealth {
	if s == nil || s.weightMgr == nil {
		return policy.RelayHealth{RTTMs: 1, PingLatencyMs: 1, Healthy: true}
	}
	load := s.weightMgr.Collect()
	latency := load.AvgLatencyMs
	if latency <= 0 {
		latency = 1
	}
	jitter := load.JitterMs
	errorPct := math.Max(0, math.Min(1, jitter/500))
	return policy.RelayHealth{
		RTTMs:         latency + jitter*0.5,
		PingLatencyMs: latency,
		Healthy:       true,
		ErrorPct:      errorPct,
	}
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
		nodeKey := relayNodeKey(d)
		if nodeKey == "" {
			continue
		}
		candidates = append(candidates, crc32.ChecksumIEEE([]byte(nodeKey)))
	}
	if len(candidates) == 0 {
		return
	}
	selfKey := strings.TrimSpace(s.cfg.PortalURL)
	if selfKey == "" {
		selfKey = s.identity.Key()
	}
	if selfKey == "" {
		return
	}
	selfID := crc32.ChecksumIEEE([]byte(selfKey))
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

func relayNodeKey(desc types.RelayDescriptor) string {
	if key := strings.TrimSpace(desc.RelayID); key != "" {
		return key
	}
	if key := strings.TrimSpace(desc.APIHTTPSAddr); key != "" {
		return key
	}
	return desc.Key()
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
