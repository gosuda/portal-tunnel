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
	"github.com/gosuda/portal-tunnel/v2/portal/pepper"
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
	seedOnlyRelays  []string
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

	accepted  chan net.Conn
	datagrams chan types.DatagramFrame

	relaySet       *discovery.RelaySet
	listenerMu     sync.RWMutex
	relayListeners map[string]*listener

	activeMu        sync.RWMutex
	activeCircuit   *pepper.ActiveCircuit
	activeResetting bool

	closeOnce sync.Once
	connSeq   atomic.Uint64
}

type ExposeConfig struct {
	RelayURLs []string
	Discovery bool

	IdentityPath string
	IdentityJSON string
	Name         string
	TargetAddr   string
	UDPAddr      string
	UDPEnabled   bool
	TCPEnabled   bool
	// MultiHop is the caller-selected ordered relay URL path. The first URL is
	// the public entry relay and the last URL is the exit relay the SDK registers with.
	MultiHop []string
	// MultiHopDepth selects one automatic multi-hop route when >= 2. Values 0
	// and 1 keep the automatic route selector in single-hop relay pool mode.
	MultiHopDepth   int
	PepperMode      string
	BanMITM         bool
	MaxActiveRelays int
	Metadata        types.LeaseMetadata
}

const (
	PepperModeDisabled = ""
	PepperModePassive  = "passive"
	PepperModeActive   = "active"
)

func ValidatePepperMode(mode string) error {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case PepperModeDisabled, PepperModePassive, PepperModeActive:
		return nil
	default:
		return fmt.Errorf("unsupported pepper mode %q: want active or passive", mode)
	}
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
	if cfg.PepperMode != PepperModeDisabled && len(multiHop) == 0 && cfg.MultiHopDepth <= 1 {
		return nil, errors.New("pepper requires --multi-hop or --multi-hop-depth 2+")
	}
	if cfg.PepperMode == PepperModeActive {
		if err := (pepper.ActivePolicy{
			MultiHopDepth: cfg.MultiHopDepth,
			ExplicitPath:  multiHop,
			Discovery:     cfg.Discovery,
			IdentityJSON:  cfg.IdentityJSON,
		}).Validate(); err != nil {
			return nil, err
		}
	}

	var listenerRelayURLs []string
	var relaySetURLs []string
	if len(multiHop) > 0 {
		listenerRelayURLs = []string{multiHop[len(multiHop)-1]}
		relaySetURLs = append([]string(nil), multiHop...)
	} else if cfg.MultiHopDepth > 1 {
		relaySetURLs, err = utils.ResolvePortalRelayURLs(ctx, explicitRelayURLs, cfg.Discovery)
		if err != nil {
			return nil, err
		}
	} else {
		relaySetURLs, err = utils.ResolvePortalRelayURLs(ctx, explicitRelayURLs, cfg.Discovery)
		if err != nil {
			return nil, err
		}
		listenerRelayURLs = append([]string(nil), explicitRelayURLs...)
	}

	identityPath := cfg.IdentityPath
	identityJSON := cfg.IdentityJSON
	if cfg.PepperMode == PepperModeActive {
		identityPath = ""
		identityJSON = ""
	}
	identity, createdIdentity, err := utils.ResolveListenerIdentity(
		types.Identity{Name: cfg.Name},
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
		banMITM:         cfg.BanMITM,
		maxActiveRelays: cfg.MaxActiveRelays,
		metadata:        cfg.Metadata,
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

	if cfg.PepperMode == PepperModeActive {
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

	e.listenerMu.Lock()
	nextSeedOnlyRelays := make([]string, 0, len(e.seedOnlyRelays))
	for _, existing := range e.seedOnlyRelays {
		if existing != relayURL {
			nextSeedOnlyRelays = append(nextSeedOnlyRelays, existing)
		}
	}
	e.seedOnlyRelays = nextSeedOnlyRelays
	if !slices.Contains(e.explicitRelays, relayURL) {
		e.explicitRelays = append(append([]string(nil), e.explicitRelays...), relayURL)
	}
	e.listenerMu.Unlock()

	e.relaySet.AllowRelayURL(relayURL)
	e.relaySet.AddBootstrapRelayURL(relayURL)
	return e.reconcileRelayListeners(true)
}

// RemoveRelay detaches a relay from the running exposure and suppresses
// auto-selection for that relay until it is added again.
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

	e.listenerMu.Lock()
	nextRelays := make([]string, 0, len(e.explicitRelays))
	for _, existing := range e.explicitRelays {
		if existing != relayURL {
			nextRelays = append(nextRelays, existing)
		}
	}
	e.explicitRelays = nextRelays
	nextSeedOnlyRelays := make([]string, 0, len(e.seedOnlyRelays))
	for _, existing := range e.seedOnlyRelays {
		if existing != relayURL {
			nextSeedOnlyRelays = append(nextSeedOnlyRelays, existing)
		}
	}
	e.seedOnlyRelays = nextSeedOnlyRelays
	if slices.Contains(e.multiHop, relayURL) {
		nextMultiHop := make([]string, 0, len(e.multiHop))
		for _, existing := range e.multiHop {
			if existing != relayURL {
				nextMultiHop = append(nextMultiHop, existing)
			}
		}
		if len(nextMultiHop) < 2 {
			nextMultiHop = nil
		}
		e.multiHop = nextMultiHop
		e.multiHopDepth = 0
	}
	e.listenerMu.Unlock()

	e.relaySet.BanRelayURL(relayURL)
	e.relaySet.RemoveBootstrapRelayURL(relayURL)
	return e.reconcileRelayListeners(false)
}

// SeedRelay keeps a relay as a discovery seed while removing it from the
// active relay pool for this exposure.
func (e *Exposure) SeedRelay(relayURL string) error {
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

	e.listenerMu.Lock()
	nextRelays := make([]string, 0, len(e.explicitRelays))
	for _, existing := range e.explicitRelays {
		if existing != relayURL {
			nextRelays = append(nextRelays, existing)
		}
	}
	e.explicitRelays = nextRelays
	if !slices.Contains(e.seedOnlyRelays, relayURL) {
		e.seedOnlyRelays = append(append([]string(nil), e.seedOnlyRelays...), relayURL)
	}
	if slices.Contains(e.multiHop, relayURL) {
		nextMultiHop := make([]string, 0, len(e.multiHop))
		for _, existing := range e.multiHop {
			if existing != relayURL {
				nextMultiHop = append(nextMultiHop, existing)
			}
		}
		if len(nextMultiHop) < 2 {
			nextMultiHop = nil
		}
		e.multiHop = nextMultiHop
		e.multiHopDepth = 0
	}
	e.listenerMu.Unlock()

	e.relaySet.AllowRelayURL(relayURL)
	e.relaySet.AddBootstrapRelayURL(relayURL)
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
	if len(multiHop) > 0 && (e.udpEnabled || e.tcpEnabled) {
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

	e.listenerMu.Lock()
	nextSeedOnlyRelays := make([]string, 0, len(e.seedOnlyRelays))
	for _, existing := range e.seedOnlyRelays {
		if !slices.Contains(multiHop, existing) {
			nextSeedOnlyRelays = append(nextSeedOnlyRelays, existing)
		}
	}
	e.seedOnlyRelays = nextSeedOnlyRelays
	e.multiHop = append([]string(nil), multiHop...)
	e.multiHopDepth = 0
	e.listenerMu.Unlock()
	return e.reconcileRelayListeners(false)
}

func initialRouteCapacity(listenerRelayURLs []string, multiHopDepth int) int {
	if multiHopDepth > 1 {
		return 1
	}
	return len(listenerRelayURLs)
}

func (e *Exposure) ActiveRelayURLs() []string {
	e.listenerMu.RLock()
	defer e.listenerMu.RUnlock()
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
	if e.identity.Address == "" {
		return exposureAddr("portal:exposure")
	}
	return exposureAddr("portal:" + e.identity.Address)
}

type exposureAddr string

func (a exposureAddr) Network() string { return "portal" }
func (a exposureAddr) String() string  { return string(a) }

func (e *Exposure) Identity() types.Identity {
	return e.identity
}

func (e *Exposure) Snapshot() types.AgentTunnelStatus {
	e.listenerMu.RLock()
	listeners := make([]*listener, 0, len(e.relayListeners))
	for _, listener := range e.relayListeners {
		if listener != nil {
			listeners = append(listeners, listener)
		}
	}
	multiHop := append([]string(nil), e.multiHop...)
	e.listenerMu.RUnlock()

	relayByURL := make(map[string]types.AgentRelayStatus, len(listeners))
	for _, listener := range listeners {
		relayURL := ""
		if listener.relayURL != nil {
			relayURL = listener.relayURL.String()
		}
		snap := types.AgentRelayStatus{
			RelayURL:   relayURL,
			Connecting: true,
		}
		if lease, ok := listener.leaseSnapshot(); ok {
			snap.PublicURL = listener.publicURLForLease(lease)
		}
		if relayURL != "" {
			relayByURL[relayURL] = snap
		}
	}
	if e.relaySet != nil {
		for _, state := range e.relaySet.AllRelays() {
			relayURL := strings.TrimSpace(state.Descriptor.APIHTTPSAddr)
			if relayURL == "" {
				continue
			}
			snap := relayByURL[relayURL]
			snap.RelayURL = relayURL
			snap.Bootstrap = state.Bootstrap
			snap.Banned = state.Banned
			snap.SupportsOverlay = state.Descriptor.SupportsOverlay
			snap.SupportsUDP = state.Descriptor.SupportsUDP
			snap.SupportsTCP = state.Descriptor.SupportsTCP
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
		TargetAddr: e.TargetAddr,
		MultiHop:   multiHop,
		Relays:     relays,
	}
}

func (e *Exposure) AcceptDatagram() (types.DatagramFrame, error) {
	if !e.udpEnabled {
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
	if !e.udpEnabled {
		return net.ErrClosed
	}

	e.listenerMu.RLock()
	listener := e.relayListeners[frame.RelayURL]
	e.listenerMu.RUnlock()
	if listener == nil {
		return net.ErrClosed
	}
	return listener.sendDatagram(frame)
}

func (e *Exposure) WaitDatagramReady(ctx context.Context) ([]string, error) {
	if !e.udpEnabled {
		return nil, errors.New("exposure does not have udp enabled")
	}

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		e.listenerMu.RLock()
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
		e.listenerMu.RUnlock()
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

	e.listenerMu.RLock()
	hasRelayListeners := len(e.relayListeners) > 0
	e.listenerMu.RUnlock()

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

		e.listenerMu.Lock()
		relayListeners := e.relayListeners
		e.relayListeners = make(map[string]*listener)
		e.listenerMu.Unlock()

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
	if e.pepperMode != PepperModeActive {
		return nil
	}
	if err := pepper.RequireEntropy(pepper.DefaultMinEntropyBits); err != nil {
		return err
	}
	circuit, err := pepper.NewActiveCircuit()
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
			Str("error_code", pepper.ErrCircuitResetIntegrityVoid).
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
	if e.pepperMode != PepperModeActive {
		return true
	}
	e.activeMu.RLock()
	defer e.activeMu.RUnlock()
	return e.activeCircuit != nil && !e.activeResetting
}

func (e *Exposure) resetActiveCircuit(failed *listener) {
	if e.pepperMode != PepperModeActive {
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
		Str("error_code", pepper.ErrCircuitResetIntegrityVoid).
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
			e.relaySet.RecordActiveFailure(relayURL, errors.New(pepper.ErrCircuitResetIntegrityVoid), 1)
		}
		if err := stale.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Warn().Str("error_code", pepper.ErrCircuitResetIntegrityVoid).Msg("pepper active stale circuit close failed")
		}
	}
	if failed != nil {
		_ = failed.Close()
	}
	_ = oldCircuit.Close()

	if err := e.establishActiveCircuit(true); err != nil {
		log.Error().
			Str("error_code", pepper.ErrPFSHandshakeFailed).
			Msg("pepper active circuit re-handshake failed")
		return
	}
	if err := e.reconcileRelayListeners(false); err != nil {
		log.Error().
			Str("error_code", pepper.ErrPFSHandshakeFailed).
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

	e.listenerMu.Lock()
	multiHop = append([]string(nil), e.multiHop...)
	explicitRelays := append([]string(nil), e.explicitRelays...)
	seedOnlyRelays := append([]string(nil), e.seedOnlyRelays...)
	if len(multiHop) > 0 {
		listenerRelayURLs = e.relaySet.PriorityRelays(discovery.ClientState{
			ExplicitRelayURLs:   explicitRelays,
			SuppressedRelayURLs: seedOnlyRelays,
			MaxActiveRelays:     e.maxActiveRelays,
			RequireUDP:          e.udpEnabled,
			RequireTCP:          e.tcpEnabled,
			LocalAddress:        e.identity.Address,
		})
		if exitRelayURL := multiHop[len(multiHop)-1]; !slices.Contains(listenerRelayURLs, exitRelayURL) {
			listenerRelayURLs = append(listenerRelayURLs, exitRelayURL)
		}
	} else if e.multiHopDepth > 1 {
		clientState := discovery.ClientState{
			MultiHopDepth: e.multiHopDepth,
			LocalAddress:  e.identity.Address,
		}
		if e.pepperMode == PepperModeActive {
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
			ExplicitRelayURLs:   explicitRelays,
			SuppressedRelayURLs: seedOnlyRelays,
			MaxActiveRelays:     e.maxActiveRelays,
			RequireUDP:          e.udpEnabled,
			RequireTCP:          e.tcpEnabled,
			LocalAddress:        e.identity.Address,
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
	e.listenerMu.Unlock()
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
		if len(listenerMultiHop) > 0 || slices.Contains(explicitRelays, relayURL) {
			retryCount = 0
		}
		if e.pepperMode == PepperModeActive {
			retryCount = -1
		}
		listener, err := newListener(context.Background(), relayURL, listenerConfig{
			Identity:   e.identity,
			UDPEnabled: e.udpEnabled,
			TCPEnabled: e.tcpEnabled,
			MultiHop:   multiHop,
			PepperMode: e.pepperMode,
			BanMITM:    e.banMITM,
			RetryCount: retryCount,
			Metadata:   e.metadata,
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

		e.listenerMu.Lock()
		if _, exists := e.relayListeners[relayURL]; exists {
			e.listenerMu.Unlock()
			_ = listener.Close()
			continue
		}
		e.relayListeners[relayURL] = listener
		e.listenerMu.Unlock()
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
	if e.udpEnabled {
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
		e.listenerMu.Lock()
		if current, ok := e.relayListeners[relayURL]; ok && current == listener {
			delete(e.relayListeners, relayURL)
		}
		e.listenerMu.Unlock()
		if e.pepperMode == PepperModeActive {
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
			if e.pepperMode == PepperModeActive {
				log.Warn().Str("error_code", pepper.ErrOnionIntegrityVoid).Msg("pepper active circuit accept failed")
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
