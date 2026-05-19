package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/telemetry"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Exposure owns the lifecycle of one or more relay listeners and accepts
// traffic from all of them through one net.Listener.
type Exposure struct {
	cancel context.CancelFunc
	done   <-chan struct{}

	identity        types.Identity
	explicitRelays  []string
	TargetAddr      string
	UDPAddr         string
	udpEnabled      bool
	tcpEnabled      bool
	multiHop        []string
	multiHopDepth   int
	pepperMode      string
	banMITM         bool
	maxActiveRelays int
	metadata        types.LeaseMetadata
	cfg *utils.Snapshot[ExposeConfig]

	accepted  chan net.Conn
	datagrams chan types.DatagramFrame

	relaySet       *discovery.RelaySet
	mu             sync.RWMutex
	listenerMu     sync.RWMutex
	relayListeners map[string]*listener

	cfgMu sync.RWMutex
	cfg   ExposeConfig

	activeMu        sync.RWMutex
	activeCircuit   types.Circuit
	activeResetting bool
	pepperProvider  types.PepperProvider

	closeOnce sync.Once
	connSeq   atomic.Uint64
}

type ExposeConfig struct {
	RelayURLs []string
	Discovery bool

	Identity        types.Identity
	IdentityPath    string
	IdentityJSON    string
	TargetAddr      string
	UDPAddr         string
	UDPEnabled      bool
	TCPEnabled      bool
	MultiHop        []string
	MultiHopDepth   int
	PepperMode      string
	PepperProvider  types.PepperProvider
	BanMITM         bool
	MaxActiveRelays int
	Metadata        types.LeaseMetadata
}

func ValidatePepperMode(mode string) error {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case types.PepperModeDisabled, types.PepperModePassive, types.PepperModeActive:
		return nil
	default:
		return fmt.Errorf("unsupported pepper mode %q: want active or passive", mode)
	}
func (cfg ExposeConfig) snapshot() ExposeConfig {
	cfg.RelayURLs = utils.CloneSlice(cfg.RelayURLs)
	cfg.Identity = cfg.Identity.Copy()
	cfg.MultiHop = utils.CloneSlice(cfg.MultiHop)
	cfg.Metadata = cfg.Metadata.Copy()
	return cfg
}

// Expose creates relay listeners for the selected relay pool and exposes a
// dynamic listener hub for accepting traffic from all of them.
func Expose(ctx context.Context, cfg ExposeConfig) (*Exposure, error) {
	cfg.PepperMode = strings.TrimSpace(strings.ToLower(cfg.PepperMode))
	if err := ValidatePepperMode(cfg.PepperMode); err != nil {
		return nil, err
	}

	explicitRelayURLs, err := utils.NormalizeRelayURLs(cfg.RelayURLs...)
	if err != nil {
		return nil, err
	}
	var multiHop []string
	for _, input := range cfg.MultiHop {
		relayURL, err := utils.NormalizeRelayURL(input)
		if err != nil {
			return nil, fmt.Errorf("normalize multi-hop relay url: %w", err)
		}
		if slices.Contains(multiHop, relayURL) {
			return nil, fmt.Errorf("multi-hop relay url repeated: %s", relayURL)
		}
		multiHop = append(multiHop, relayURL)
	}
	if len(multiHop) == 1 {
		return nil, errors.New("multi-hop requires at least entry and exit relay urls")
	}
	if cfg.MultiHopDepth < 0 {
		return nil, errors.New("multi-hop-depth cannot be negative")
	}
	if len(multiHop) > 0 && cfg.MultiHopDepth > 1 {
		return nil, errors.New("explicit --multi-hop cannot be combined with automatic --multi-hop-depth")
	}
	if (len(multiHop) > 0 || cfg.MultiHopDepth > 1) && (cfg.UDPEnabled || cfg.TCPEnabled) {
		return nil, errors.New("multi-hop currently supports only the default SNI TLS stream transport")
	}
	if cfg.PepperMode != types.PepperModeDisabled && len(multiHop) == 0 && cfg.MultiHopDepth <= 1 {
		return nil, errors.New("pepper requires --multi-hop or --multi-hop-depth 2+")
	}
	if cfg.PepperMode == types.PepperModeActive {
		if cfg.PepperProvider == nil {
			return nil, errors.New("pepper active mode requires a PepperProvider")
		}
		if err := cfg.PepperProvider.ValidatePolicy(cfg.MultiHopDepth, multiHop, cfg.Discovery, cfg.IdentityJSON); err != nil {
			return nil, err
		}
	}

	var listenerRelayURLs []string
	var relaySetURLs []string
	if len(multiHop) > 0 {
		listenerRelayURLs = []string{multiHop[len(multiHop)-1]}
		relaySetURLs = append([]string(nil), multiHop...)
	} else if cfg.MultiHopDepth > 1 {
		relaySetURLs, err = utils.ResolvePortalRelayURLs(explicitRelayURLs, cfg.Discovery)
		if err != nil {
			return nil, err
		}
	} else {
		relaySetURLs, err = utils.ResolvePortalRelayURLs(explicitRelayURLs, cfg.Discovery)
		if err != nil {
			return nil, err
		}
		listenerRelayURLs = append([]string(nil), explicitRelayURLs...)
	}

	identityPath := cfg.IdentityPath
	identityJSON := cfg.IdentityJSON
	if cfg.PepperMode == types.PepperModeActive {
		identityPath = ""
		identityJSON = ""
	}
	identity, createdIdentity, err := identity.ResolveListenerIdentity(
		types.Identity{Name: cfg.Identity.Name},
		cfg.TargetAddr,
		identityPath,
		identityJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("resolve identity: %w", err)
	}
	if createdIdentity {
		log.Info().
			Str("identity_path", strings.TrimSpace(cfg.IdentityPath)).
			Str("address", identity.Address).
			Msg("generated tunnel identity and saved it to disk")
	}
	targetAddr, err := utils.NormalizeLoopbackTarget(cfg.TargetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid target value %q: %w", cfg.TargetAddr, err)
	}
	udpAddr := cfg.UDPAddr
	if cfg.UDPEnabled {
		udpAddr, err = utils.NormalizeLoopbackTarget(utils.StringOrDefault(udpAddr, targetAddr))
		if err != nil {
			return nil, fmt.Errorf("invalid --udp-addr value %q: %w", cfg.UDPAddr, err)
		}
	}
	runtimeCfg := cfg.snapshot()
	runtimeCfg.RelayURLs = append([]string(nil), explicitRelayURLs...)
	runtimeCfg.Identity = identity.Copy()
	runtimeCfg.TargetAddr = targetAddr
	runtimeCfg.UDPAddr = udpAddr
	runtimeCfg.MultiHop = append([]string(nil), multiHop...)
	runtimeCfg.Metadata = cfg.Metadata.Copy()

	exposureCtx, cancel := context.WithCancel(ctx)
	exposure := &Exposure{
		cancel:          cancel,
		done:            exposureCtx.Done(),
		identity:        identity,
		explicitRelays:  explicitRelayURLs,
		TargetAddr:      targetAddr,
		UDPAddr:         udpAddr,
		udpEnabled:      cfg.UDPEnabled,
		tcpEnabled:      cfg.TCPEnabled,
		multiHop:        multiHop,
		multiHopDepth:   cfg.MultiHopDepth,
		pepperMode:      cfg.PepperMode,
		pepperProvider:  cfg.PepperProvider,
		banMITM:         cfg.BanMITM,
		maxActiveRelays: cfg.MaxActiveRelays,
		metadata:        cfg.Metadata,
		cfg:            utils.NewSnapshot(runtimeCfg, ExposeConfig.snapshot),
    datagrams:      make(chan types.DatagramFrame, max(initialRouteCapacity(listenerRelayURLs, cfg.MultiHopDepth)*32, 1)),
		accepted:        make(chan net.Conn, max(initialRouteCapacity(listenerRelayURLs, cfg.MultiHopDepth)*defaultReadyTarget*2, 1)),
		datagrams:       make(chan types.DatagramFrame, max(initialRouteCapacity(listenerRelayURLs, cfg.MultiHopDepth)*32, 1)),
		relaySet:        discovery.NewRelaySet(relaySetURLs),
		relayListeners:  make(map[string]*listener, initialRouteCapacity(listenerRelayURLs, cfg.MultiHopDepth)),
	}

	if cfg.Discovery || len(multiHop) > 0 || cfg.MultiHopDepth > 1 {
		refresher := discovery.NewRefresher(exposure.relaySet, nil)
		if err := refresher.Refresh(ctx, nil); err != nil {
			_ = exposure.Close()
			return nil, fmt.Errorf("discover relays: %w", err)
		}
	}

	if cfg.PepperMode == types.PepperModeActive {
		if err := exposure.establishActiveCircuit(false); err != nil {
			_ = exposure.Close()
			return nil, err
		}
	}

	if len(listenerRelayURLs) > 0 || cfg.Discovery || cfg.MultiHopDepth > 1 {
		if err := exposure.reconcileRelayListeners(true); err != nil {
			_ = exposure.Close()
			return nil, err
		}
	}

	if cfg.Discovery || len(multiHop) > 0 || cfg.MultiHopDepth > 1 {
		go exposure.runDiscoveryLoop(exposureCtx)
	}

	go func() {
		<-exposure.done
		_ = exposure.Close()
	}()

	return exposure, nil
}

// AddRelay attaches an explicit relay to the running exposure without
// restarting the local tunnel.
func (e *Exposure) AddRelay(relayURL string) error {
	relayURL, err := utils.NormalizeRelayURL(relayURL)
	if err != nil {
		return err
	}
	if e.closed() {
		return net.ErrClosed
	}
	if e.relaySet == nil {
		return errors.New("exposure relay set is not initialized")
	}

	e.cfg.UpdateCopy(func(cfg *ExposeConfig) {
		if !slices.Contains(cfg.RelayURLs, relayURL) {
			cfg.RelayURLs = append(cfg.RelayURLs, relayURL)
		}
	})

	e.relaySet.AllowRelayURL(relayURL)
	e.relaySet.AddBootstrapRelayURL(relayURL)
	return e.reconcileRelayListeners(true)
}

// RemoveRelay detaches a relay from the running exposure and lets it fall back
// to the discovered candidate pool.
func (e *Exposure) RemoveRelay(relayURL string) error {
	relayURL, err := utils.NormalizeRelayURL(relayURL)
	if err != nil {
		return err
	}
	if e.closed() {
		return net.ErrClosed
	}
	if e.relaySet == nil {
		return errors.New("exposure relay set is not initialized")
	}

	if _, ok := e.cfg.UpdateIf(func(cfg ExposeConfig) (ExposeConfig, bool) {
		if slices.Contains(cfg.MultiHop, relayURL) {
			return cfg, false
		}
		nextRelays := cfg.RelayURLs[:0]
		for _, existing := range cfg.RelayURLs {
			if existing != relayURL {
				nextRelays = append(nextRelays, existing)
			}
		}
		cfg.RelayURLs = nextRelays
		return cfg, true
	}); !ok {
		return errors.New("relay is part of the multi-hop route; clear multi-hop first")
	}

	e.relaySet.DeactivateRelayURL(relayURL)
	e.relaySet.RemoveBootstrapRelayURL(relayURL)
	return e.reconcileRelayListeners(false)
}

func (e *Exposure) SetMultiHop(relayURLs []string) error {
	multiHop := make([]string, 0, len(relayURLs))
	for _, input := range relayURLs {
		relayURL, err := utils.NormalizeRelayURL(input)
		if err != nil {
			return fmt.Errorf("normalize multi-hop relay url: %w", err)
		}
		if slices.Contains(multiHop, relayURL) {
			return fmt.Errorf("multi-hop relay url repeated: %s", relayURL)
		}
		multiHop = append(multiHop, relayURL)
	}
	if len(multiHop) == 1 {
		return errors.New("multi-hop requires at least entry and exit relay urls")
	}
	cfg := e.Config()
	if len(multiHop) > 0 && (cfg.UDPEnabled || cfg.TCPEnabled) {
		return errors.New("multi-hop currently supports only the default SNI TLS stream transport")
	}
	if e.closed() {
		return net.ErrClosed
	}
	if e.relaySet == nil {
		return errors.New("exposure relay set is not initialized")
	}

	for _, relayURL := range multiHop {
		e.relaySet.AllowRelayURL(relayURL)
		e.relaySet.AddBootstrapRelayURL(relayURL)
	}

	e.cfg.UpdateCopy(func(cfg *ExposeConfig) {
		cfg.MultiHop = append([]string(nil), multiHop...)
		cfg.MultiHopDepth = 0
	})
	return e.reconcileRelayListeners(false)
}

func (e *Exposure) UpdateMetadata(metadata types.LeaseMetadata) error {
	if e.closed() {
		return net.ErrClosed
	}

	e.cfg.UpdateCopy(func(cfg *ExposeConfig) {
		cfg.Metadata = metadata.Copy()
	})
	return nil
}

func (e *Exposure) UpdateMaxActiveRelays(maxActiveRelays int) error {
	if maxActiveRelays <= 0 {
		return errors.New("max_active_relays must be a positive integer")
	}
	if e.closed() {
		return net.ErrClosed
	}

	_, changed := e.cfg.UpdateIf(func(cfg ExposeConfig) (ExposeConfig, bool) {
		if cfg.MaxActiveRelays == maxActiveRelays {
			return cfg, false
		}
		cfg.MaxActiveRelays = maxActiveRelays
		return cfg, true
	})
	if !changed {
		return nil
	}
	return e.reconcileRelayListeners(false)
}

func (cfg ExposeConfig) clone() ExposeConfig {
	cfg.RelayURLs = append([]string(nil), cfg.RelayURLs...)
	cfg.Identity = cfg.Identity.Copy()
	cfg.MultiHop = append([]string(nil), cfg.MultiHop...)
	cfg.Metadata = cfg.Metadata.Copy()
	return cfg
}

func (e *Exposure) config() ExposeConfig {
	if e == nil {
		return ExposeConfig{}
	}
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	return e.cfg.clone()
}

func initialRouteCapacity(listenerRelayURLs []string, multiHopDepth int) int {
	if multiHopDepth > 1 {
		return 1
	}
	return len(listenerRelayURLs)
}

func (e *Exposure) ActiveRelayURLs() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	relayURLs := make([]string, 0, len(e.relayListeners))
	for relayURL := range e.relayListeners {
		relayURLs = append(relayURLs, relayURL)
	}
	slices.Sort(relayURLs)
	return relayURLs
}

func (e *Exposure) closed() bool {
	select {
	case <-e.done:
		return true
	default:
		return false
	}
}

func (e *Exposure) Addr() net.Addr {
	identity := e.Config().Identity
	if identity.Address == "" {
		return exposureAddr("portal:exposure")
	}
	return exposureAddr("portal:" + identity.Address)
}

type exposureAddr string

func (a exposureAddr) Network() string { return "portal" }
func (a exposureAddr) String() string  { return string(a) }

func (e *Exposure) Config() ExposeConfig {
	if e == nil || e.cfg == nil {
		return ExposeConfig{}
	}
	return e.cfg.Load()
}

func (e *Exposure) Snapshot() types.AgentTunnelStatus {
	cfg := e.Config()
	e.mu.RLock()
	listeners := make([]*listener, 0, len(e.relayListeners))
	for _, listener := range e.relayListeners {
		if listener != nil {
			listeners = append(listeners, listener)
		}
	}
	e.mu.RUnlock()

	relayByURL := make(map[string]types.AgentRelayStatus, len(listeners))
	for _, listener := range listeners {
		relayURL := ""
		if listener.relayURL != nil {
			relayURL = listener.relayURL.String()
		}
		explicit := slices.Contains(cfg.RelayURLs, relayURL)
		snap := types.AgentRelayStatus{
			RelayURL:   relayURL,
			Version:    listener.releaseVersion,
			Explicit:   explicit,
			Connecting: explicit || len(listener.multiHop) > 0,
		}
		if lease, ok := listener.leaseSnapshot(); ok {
			snap.PublicURL = listener.publicURLForLease(lease)
			snap.Connecting = snap.PublicURL == ""
		}
		if relayURL != "" {
			relayByURL[relayURL] = snap
		}
	}
	if e.relaySet != nil {
		for _, state := range e.relaySet.AllRelays() {
			relay := state.Descriptor
			relayURL := strings.TrimSpace(relay.APIHTTPSAddr)
			if relayURL == "" {
				continue
			}
			snap := relayByURL[relayURL]
			snap.RelayURL = relayURL
			snap.Explicit = slices.Contains(cfg.RelayURLs, relayURL)
			snap.Bootstrap = state.Bootstrap
			snap.Banned = state.Banned
			snap.SupportsOverlay = relay.SupportsOverlay
			snap.SupportsUDP = relay.SupportsUDP
			snap.SupportsTCP = relay.SupportsTCP
			relayByURL[relayURL] = snap
		}
	}
	relays := make([]types.AgentRelayStatus, 0, len(relayByURL))
	for _, snap := range relayByURL {
		relays = append(relays, snap)
	}
	slices.SortFunc(relays, func(a, b types.AgentRelayStatus) int {
		aReady := a.PublicURL != ""
		bReady := b.PublicURL != ""
		if aReady != bReady {
			if aReady {
				return -1
			}
			return 1
		}
		if a.Connecting != b.Connecting {
			if a.Connecting {
				return -1
			}
			return 1
		}
		return strings.Compare(a.RelayURL, b.RelayURL)
	})

	return types.AgentTunnelStatus{
		Address:         cfg.Identity.Address,
		TargetAddr:      cfg.TargetAddr,
		MaxActiveRelays: cfg.MaxActiveRelays,
		Metadata:        cfg.Metadata,
		MultiHop:        cfg.MultiHop,
		Relays:          relays,
	}
}

func (e *Exposure) AcceptDatagram() (types.DatagramFrame, error) {
	if !e.Config().UDPEnabled {
		return types.DatagramFrame{}, net.ErrClosed
	}

	select {
	case <-e.done:
		return types.DatagramFrame{}, net.ErrClosed
	case frame := <-e.datagrams:
		return frame, nil
	}
}

func (e *Exposure) SendDatagram(frame types.DatagramFrame) error {
	if !e.Config().UDPEnabled {
		return net.ErrClosed
	}

	e.mu.RLock()
	listener := e.relayListeners[frame.RelayURL]
	e.mu.RUnlock()
	if listener == nil {
		return net.ErrClosed
	}
	return listener.sendDatagram(frame)
}

func (e *Exposure) WaitDatagramReady(ctx context.Context) ([]string, error) {
	if !e.Config().UDPEnabled {
		return nil, errors.New("exposure does not have udp enabled")
	}

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		e.mu.RLock()
		addrs := make([]string, 0, len(e.relayListeners))
		seen := make(map[string]struct{})
		resolvedWithoutDatagram := true
		for _, listener := range e.relayListeners {
			if listener == nil {
				continue
			}

			udpAddr, ready, pending := listener.datagramReady()
			if ready {
				if _, ok := seen[udpAddr]; !ok {
					seen[udpAddr] = struct{}{}
					addrs = append(addrs, udpAddr)
				}
			}
			if pending {
				resolvedWithoutDatagram = false
			}
		}
		e.mu.RUnlock()
		if len(addrs) > 0 {
			return addrs, nil
		}
		if resolvedWithoutDatagram {
			return nil, errors.New("relay did not expose udp")
		}

		select {
		case <-e.done:
			return nil, net.ErrClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

// RunHTTPRoutes serves path-routed HTTP upstreams through the exposure.
func (e *Exposure) RunHTTPRoutes(ctx context.Context, routes []HTTPRoute, localAddr string) error {
	handler, err := newHTTPRouteHandler(routes)
	if err != nil {
		return err
	}
	return e.RunHTTP(ctx, handler, localAddr)
}

func (e *Exposure) RunHTTP(ctx context.Context, handler http.Handler, localAddr string) error {
	if handler == nil {
		handler = http.NotFoundHandler()
	}

	e.mu.RLock()
	hasRelayListeners := len(e.relayListeners) > 0
	e.mu.RUnlock()

	if hasRelayListeners {
		return RunHTTP(ctx, e, handler, localAddr)
	}
	return RunHTTP(ctx, nil, handler, localAddr)
}

type exposureConn struct {
	net.Conn
	id         uint64
	localAddr  string
	remoteAddr string
	closeOnce  sync.Once
}

func (c *exposureConn) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		closeErr = c.Conn.Close()
		if errors.Is(closeErr, net.ErrClosed) {
			closeErr = nil
		}

		event := log.Info().
			Uint64("conn_id", c.id).
			Str("local_addr", c.localAddr).
			Str("remote_addr", c.remoteAddr)
		if closeErr != nil {
			event = log.Warn().
				Err(closeErr).
				Uint64("conn_id", c.id).
				Str("local_addr", c.localAddr).
				Str("remote_addr", c.remoteAddr)
		}
		event.Msg("exposure connection closed")
	})
	return closeErr
}

// tunnelCounterConn wraps a net.Conn and calls decr exactly once on the first
// Close invocation to decrement the active_tunnels_per_relay gauge. Subsequent
// Close calls are forwarded to the underlying conn but do not double-decrement.
// Concurrency is guaranteed by sync.Once.
type tunnelCounterConn struct {
	net.Conn
	once sync.Once
	decr func()
}

func (c *tunnelCounterConn) Close() error {
	c.once.Do(c.decr)
	return c.Conn.Close()
}

func (e *Exposure) Accept() (net.Conn, error) {
	for {
		if !e.activeCircuitAvailable() {
			select {
			case <-e.done:
				return nil, net.ErrClosed
			case <-time.After(50 * time.Millisecond):
				continue
			}
		}

		select {
		case <-e.done:
			return nil, net.ErrClosed
		case conn := <-e.accepted:
			if conn == nil {
				return nil, net.ErrClosed
			}
			if !e.activeCircuitAvailable() {
				_ = conn.Close()
				continue
			}

			connID := e.connSeq.Add(1)
			log.Info().
				Uint64("conn_id", connID).
				Str("local_addr", conn.LocalAddr().String()).
				Str("remote_addr", conn.RemoteAddr().String()).
				Msg("exposure connection accepted")

			return &exposureConn{
				Conn:       conn,
				id:         connID,
				localAddr:  conn.LocalAddr().String(),
				remoteAddr: conn.RemoteAddr().String(),
			}, nil
		}
	}
}

func (e *Exposure) Close() error {
	var closeErr error
	e.closeOnce.Do(func() {
		if e.cancel != nil {
			e.cancel()
		}

		e.mu.Lock()
		relayListeners := e.relayListeners
		e.relayListeners = make(map[string]*listener)
		e.mu.Unlock()

		relayURLs := make([]string, 0, len(relayListeners))
		for relayURL, listener := range relayListeners {
			relayURLs = append(relayURLs, relayURL)
			if listener != nil {
				closeErr = errors.Join(closeErr, listener.Close())
			}
		}
		e.activeMu.Lock()
		activeCircuit := e.activeCircuit
		e.activeCircuit = nil
		e.activeResetting = false
		e.activeMu.Unlock()
		closeErr = errors.Join(closeErr, activeCircuit.Close())

		event := log.Info().
			Int("relay_count", len(relayListeners)).
			Strs("relays", relayURLs)
		if closeErr != nil {
			event = log.Warn().
				Err(closeErr).
				Int("relay_count", len(relayListeners)).
				Strs("relays", relayURLs)
		}
		event.Msg("exposure closed")
	})
	return closeErr
}

func (e *Exposure) establishActiveCircuit(reset bool) error {
	if e.pepperMode != types.PepperModeActive {
		return nil
	}
	if e.pepperProvider == nil {
		return errors.New("pepper active mode requires a PepperProvider")
	}
	if err := e.pepperProvider.RequireEntropy(types.DefaultPepperMinEntropyBits); err != nil {
		return err
	}
	circuit, err := e.pepperProvider.NewCircuit()
	if err != nil {
		return err
	}

	e.activeMu.Lock()
	previous := e.activeCircuit
	e.activeCircuit = circuit
	e.activeResetting = false
	e.activeMu.Unlock()
	if previous != nil {
		_ = previous.Close()
	}
	if reset {
		log.Debug().
			Str("error_code", types.ErrPepperCircuitResetIntegrityVoid).
			Msg("pepper active circuit reset")
	}
	return nil
}

func (e *Exposure) activeCircuitSnapshot() (uint64, []byte, [32]byte, bool) {
	e.activeMu.RLock()
	defer e.activeMu.RUnlock()
	if e.activeCircuit == nil {
		return 0, nil, [32]byte{}, false
	}
	return e.activeCircuit.ID(), e.activeCircuit.SessionKey(), e.activeCircuit.PublicKey(), true
}

func (e *Exposure) activeCircuitAvailable() bool {
	if e.pepperMode != types.PepperModeActive {
		return true
	}
	e.activeMu.RLock()
	defer e.activeMu.RUnlock()
	return e.activeCircuit != nil && !e.activeResetting
}

func (e *Exposure) resetActiveCircuit(failed *listener) {
	if e.pepperMode != types.PepperModeActive {
		return
	}

	e.activeMu.Lock()
	if e.activeResetting {
		e.activeMu.Unlock()
		return
	}
	e.activeResetting = true
	oldCircuit := e.activeCircuit
	e.activeCircuit = nil
	e.activeMu.Unlock()

	log.Warn().
		Str("error_code", types.ErrPepperCircuitResetIntegrityVoid).
		Msg("pepper active circuit reset required")

	e.listenerMu.Lock()
	staleListeners := e.relayListeners
	e.relayListeners = make(map[string]*listener)
	e.listenerMu.Unlock()

	for relayURL, stale := range staleListeners {
		if stale == nil {
			continue
		}
		if e.relaySet != nil {
			e.relaySet.UnconfirmRelayURL(relayURL)
			e.relaySet.RecordActiveFailure(relayURL, errors.New(types.ErrPepperCircuitResetIntegrityVoid), 1)
		}
		if err := stale.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Warn().Str("error_code", types.ErrPepperCircuitResetIntegrityVoid).Msg("pepper active stale circuit close failed")
		}
	}
	if failed != nil {
		_ = failed.Close()
	}
	_ = oldCircuit.Close()

	if err := e.establishActiveCircuit(true); err != nil {
		log.Error().
			Str("error_code", types.ErrPepperPFSHandshakeFailed).
			Msg("pepper active circuit re-handshake failed")
		return
	}
	if err := e.reconcileRelayListeners(false); err != nil {
		log.Error().
			Str("error_code", types.ErrPepperPFSHandshakeFailed).
			Msg("pepper active circuit route selection failed")
	}
}

func (e *Exposure) runDiscoveryLoop(ctx context.Context) {
	refresher := discovery.NewRefresher(e.relaySet, nil)
	ticker := time.NewTicker(discovery.DiscoveryPollInterval)
	defer ticker.Stop()

	for {
		if err := refresher.Refresh(ctx, nil); err != nil {
			return
		}
		if err := e.reconcileRelayListeners(false); err != nil {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (e *Exposure) reconcileRelayListeners(failOnError bool) error {
	var multiHop []string
	var listenerRelayURLs []string

	cfg := e.Config()
	e.mu.Lock()
	multiHop = append([]string(nil), cfg.MultiHop...)
	if len(multiHop) > 0 {
		listenerRelayURLs = e.relaySet.PriorityRelays(discovery.ClientState{
			ExplicitRelayURLs: e.explicitRelays,
			MaxActiveRelays:   e.maxActiveRelays,
			RequireUDP:        e.udpEnabled,
			RequireTCP:        e.tcpEnabled,
			LocalAddress:      e.identity.Address,
		})
		if exitRelayURL := multiHop[len(multiHop)-1]; !slices.Contains(listenerRelayURLs, exitRelayURL) {
			listenerRelayURLs = append(listenerRelayURLs, exitRelayURL)
		}
	} else if e.multiHopDepth > 1 {
		clientState := discovery.ClientState{
			MultiHopDepth: e.multiHopDepth,
			LocalAddress:  e.identity.Address,
		}
		if e.pepperMode == types.PepperModeActive {
			multiHop = e.relaySet.RandomMultiHop(clientState)
		} else {
			multiHop = e.relaySet.PriorityMultiHop(clientState)
		}
		if len(multiHop) < e.multiHopDepth {
			e.listenerMu.Unlock()
			return fmt.Errorf("multi-hop-depth %d requires %d overlay relay candidates, got %d", e.multiHopDepth, e.multiHopDepth, len(multiHop))
		}
		listenerRelayURLs = []string{multiHop[len(multiHop)-1]}
	} else {
		listenerRelayURLs = e.relaySet.PriorityRelays(discovery.ClientState{
			ExplicitRelayURLs: cfg.RelayURLs,
			MaxActiveRelays:   cfg.MaxActiveRelays,
			RequireUDP:        cfg.UDPEnabled,
			RequireTCP:        cfg.TCPEnabled,
			LocalAddress:      cfg.Identity.Address,
		})
	}
	staleRelayListeners := make(map[string]*listener)
	removedRelayURLs := make([]string, 0)
	for relayURL, listener := range e.relayListeners {
		wantMultiHop := []string(nil)
		if len(multiHop) > 0 && relayURL == multiHop[len(multiHop)-1] {
			wantMultiHop = multiHop
		}
		if slices.Contains(listenerRelayURLs, relayURL) && slices.Equal(listener.multiHop, wantMultiHop) {
			continue
		}
		staleRelayListeners[relayURL] = listener
		removedRelayURLs = append(removedRelayURLs, relayURL)
		delete(e.relayListeners, relayURL)
	}

	missingRelayURLs := make([]string, 0, len(listenerRelayURLs))
	for _, relayURL := range listenerRelayURLs {
		if _, ok := e.relayListeners[relayURL]; ok {
			continue
		}
		missingRelayURLs = append(missingRelayURLs, relayURL)
	}
	e.mu.Unlock()
	if len(removedRelayURLs) > 1 {
		slices.Sort(removedRelayURLs)
	}

	addedRelayURLs := make([]string, 0, len(missingRelayURLs))
	for relayURL, listener := range staleRelayListeners {
		if listener == nil {
			continue
		}
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Warn().Err(err).Str("relay_url", relayURL).Msg("close stale relay listener")
		}
	}
	for _, relayURL := range missingRelayURLs {
		listenerMultiHop := []string(nil)
		if len(multiHop) > 0 && relayURL == multiHop[len(multiHop)-1] {
			listenerMultiHop = append([]string(nil), multiHop...)
		}
		retryCount := 10
		if len(listenerMultiHop) > 0 {
			retryCount = 0
		}
		if e.pepperMode == types.PepperModeActive {
			retryCount = -1
		}
		listener, err := newListener(context.Background(), relayURL, listenerConfig{
			Identity:   cfg.Identity.Copy(),
			UDPEnabled: cfg.UDPEnabled,
			TCPEnabled: cfg.TCPEnabled,
			PepperMode: e.pepperMode,
			BanMITM:    cfg.BanMITM,
			Identity:   cfg.Identity.Copy(),
			Metadata: func() types.LeaseMetadata {
				return e.Config().Metadata
			},
			MultiHop:   listenerMultiHop,
			RetryCount: retryCount,
			relaySet:   e.relaySet,
		})
		if err != nil {
			if failOnError {
				return fmt.Errorf("listen %q: %w", relayURL, err)
			}
			log.Warn().Err(err).Str("relay_url", relayURL).Msg("add relay listener")
			continue
		}

		select {
		case <-e.done:
			_ = listener.Close()
			continue
		default:
		}

		e.mu.Lock()
		if _, exists := e.relayListeners[relayURL]; exists {
			e.mu.Unlock()
			_ = listener.Close()
			continue
		}
		e.relayListeners[relayURL] = listener
		e.mu.Unlock()
		addedRelayURLs = append(addedRelayURLs, relayURL)

		go e.runListenerAcceptLoop(listener)
	}

	if len(removedRelayURLs) > 0 || len(addedRelayURLs) > 0 {
		log.Info().
			Strs("added_relays", addedRelayURLs).
			Strs("removed_relays", removedRelayURLs).
			Strs("listener_relays", listenerRelayURLs).
			Msg("reconciled relay listeners")
	}
	return nil
}

func (e *Exposure) runListenerAcceptLoop(listener *listener) {
	if listener == nil {
		return
	}

	relayURL := ""
	if listener.relayURL != nil {
		relayURL = listener.relayURL.String()
	}
	if listener.udpEnabled {
		go func() {
			for {
				frame, err := listener.acceptDatagram()
				if err != nil {
					select {
					case <-e.done:
						return
					default:
					}
					if errors.Is(err, net.ErrClosed) {
						return
					}
					log.Warn().
						Err(err).
						Str("relay_url", relayURL).
						Str("address", listener.identity.Address).
						Msg("datagram accept failed")
					return
				}

				select {
				case <-e.done:
					return
				case e.datagrams <- frame:
				}
			}
		}()
	}
	defer func() {
		removed := false
		e.mu.Lock()
		if current, ok := e.relayListeners[relayURL]; ok && current == listener {
			delete(e.relayListeners, relayURL)
			removed = true
		}
		e.mu.Unlock()
		if !removed || e.closed() {
			return
		}

		removedExplicit := false
		if e.cfg != nil {
			_, removedExplicit = e.cfg.UpdateIf(func(cfg ExposeConfig) (ExposeConfig, bool) {
				if !slices.Contains(cfg.RelayURLs, relayURL) {
					return cfg, false
				}
				cfg.RelayURLs = utils.RemoveRelayURL(cfg.RelayURLs, relayURL)
				return cfg, true
			})
		}

		if removedExplicit && e.relaySet != nil {
			e.relaySet.DeactivateRelayURL(relayURL)
			e.relaySet.RemoveBootstrapRelayURL(relayURL)
		}
		e.listenerMu.Unlock()
		if e.pepperMode == types.PepperModeActive {
			go e.resetActiveCircuit(listener)
		}
	}()

	for {
		if !e.activeCircuitAvailable() {
			select {
			case <-e.done:
				return
			case <-time.After(50 * time.Millisecond):
				continue
			}
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-listener.doneCh:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if e.pepperMode == types.PepperModeActive {
				log.Warn().Str("error_code", types.ErrPepperOnionIntegrityVoid).Msg("pepper active circuit accept failed")
			} else {
				log.Warn().Err(err).Str("relay_url", relayURL).Msg("exposure listener accept failed")
			}
			return
		}

		telemetry.ActiveTunnelsPerRelay.WithLabelValues(relayURL).Inc()
		wrappedConn := &tunnelCounterConn{
			Conn: conn,
			decr: func() {
				telemetry.ActiveTunnelsPerRelay.WithLabelValues(relayURL).Dec()
			},
		}

		select {
		case <-e.done:
			_ = wrappedConn.Close()
			return
		case e.accepted <- wrappedConn:
		}
	}
}
