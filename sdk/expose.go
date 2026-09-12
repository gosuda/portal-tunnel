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

	"github.com/gosuda/portal-tunnel/v2/internal/discovery"
	"github.com/gosuda/portal-tunnel/v2/internal/identity"
	"github.com/gosuda/portal-tunnel/v2/internal/telemetry"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Exposure owns the lifecycle of one or more relay listeners and accepts
// traffic from all of them through one net.Listener.
type Exposure struct {
	cancel context.CancelFunc
	done   <-chan struct{}

	cfg *utils.Snapshot[ExposeConfig]

	accepted  chan net.Conn
	datagrams chan types.DatagramFrame

	relaySet       *discovery.RelaySet
	mu             sync.RWMutex
	relayListeners map[string]*listener

	// Canonical per-relay runtime state. This is the single authoritative
	// source for relay readiness, failure, and removal. All public status
	// and readiness APIs consume this map directly.
	relayStateMu sync.RWMutex
	relayStates  map[string]*relayRuntimeState

	// notifyCh is closed and replaced on every canonical state change so
	// that WaitReady and WaitDatagramReady can react to transitions
	// without polling.
	notifyMu sync.Mutex
	notifyCh chan struct{}

	// updatesSubs holds fan-out channels for Updates() subscribers.
	updatesMu   sync.Mutex
	updatesSubs map[chan RelayUpdate]struct{}

	closeOnce sync.Once
	connSeq   atomic.Uint64
}

// RelayState is the canonical lifecycle state of a single relay runtime
// owned by the SDK. It is the authoritative source for readiness, failure,
// and removal; callers must not infer readiness from PublicURL alone.
type RelayState string

const (
	// RelayStatePending is the initial state before registration begins.
	RelayStatePending RelayState = "pending"
	// RelayStateRegistering means the listener is actively registering a lease.
	RelayStateRegistering RelayState = "registering"
	// RelayStateReady means the relay has an active lease and is serving traffic.
	RelayStateReady RelayState = "ready"
	// RelayStateDatagramReady means the relay is ready and the UDP datagram
	// backhaul is connected.
	RelayStateDatagramReady RelayState = "datagram_ready"
	// RelayStateFailed means the relay has terminally failed; the error is
	// preserved in RelayStatus.Error.
	RelayStateFailed RelayState = "failed"
	// RelayStateRemoved means the relay was explicitly removed from the exposure.
	RelayStateRemoved RelayState = "removed"
)

// RelayStatus is the canonical snapshot of a single relay runtime exposed by
// the SDK. It is the single source of truth that the agent/dashboard and
// external callers consume; wire projections such as types.AgentRelayStatus are
// derived from it.
type RelayStatus struct {
	RelayURL    string
	State       RelayState
	PublicURL   string
	Error       string
	Version     string
	Explicit    bool
	Connecting  bool
	Bootstrap   bool
	Banned      bool
	SupportsUDP bool
	SupportsTCP bool
}

// relayRuntimeState is the canonical per-relay state owned by the SDK.
// Each field is written by emitRelayEvent under relayStateMu and read by
// Relays, Snapshot, WaitReady, and WaitDatagramReady.
type relayRuntimeState struct {
	state         RelayState
	publicURL     string
	err           error
	udpAddr       string
	datagramReady bool
	version       string
	explicit      bool
}

// RelayUpdate is emitted through Exposure.Updates() when a relay's
// canonical state changes.
type RelayUpdate struct {
	RelayURL  string
	State     RelayState
	PublicURL string
	Error     string
}

// ErrNoRelays indicates that the relay pool is exhausted: no relays are
// available and discovery cannot yield new candidates. It is distinct
// from a temporary zero-relay state where discovery is still active.
var ErrNoRelays = errors.New("no relays available")

type ExposeConfig struct {
	RelayURLs []string
	Discovery bool
	Overlay   bool

	Identity             types.Identity
	IdentityPath         string
	IdentityJSON         string
	TargetAddr           string
	UDPAddr              string
	UDPEnabled           bool
	TCPEnabled           bool
	ECH                  bool
	BanMITM              bool
	MaxActiveRelays      int
	Metadata             types.LeaseMetadata
	X402PayTo            string
	X402Testnet          bool
	X402Network          string
	X402Asset            string
	X402Endpoints        []string
	X402FacilitatorToken string
}

func (cfg ExposeConfig) snapshot() ExposeConfig {
	cfg.RelayURLs = utils.CloneSlice(cfg.RelayURLs)
	cfg.Identity = cfg.Identity.Copy()
	cfg.Metadata = cfg.Metadata.Copy()
	cfg.X402PayTo = strings.TrimSpace(cfg.X402PayTo)
	cfg.X402Network = strings.ToLower(strings.TrimSpace(cfg.X402Network))
	cfg.X402Asset = strings.TrimSpace(cfg.X402Asset)
	cfg.X402Endpoints = utils.CloneSlice(cfg.X402Endpoints)
	cfg.X402FacilitatorToken = strings.TrimSpace(cfg.X402FacilitatorToken)
	return cfg
}

// Expose creates relay listeners for the selected relay pool and exposes a
// dynamic listener hub for accepting traffic from all of them.
func Expose(ctx context.Context, cfg ExposeConfig) (*Exposure, error) {
	explicitRelayURLs, err := utils.NormalizeRelayURLs(cfg.RelayURLs...)
	if err != nil {
		return nil, err
	}
	x402PayTo := strings.TrimSpace(cfg.X402PayTo)

	initialRouteCount := len(explicitRelayURLs)
	relaySetURLs, err := utils.ResolvePortalRelayURLs(explicitRelayURLs, cfg.Discovery)
	if err != nil {
		return nil, err
	}
	listenerIdentity, createdIdentity, err := identity.ResolveListenerIdentity(
		cfg.Identity.Copy(),
		cfg.TargetAddr,
		cfg.IdentityPath,
		cfg.IdentityJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("resolve identity: %w", err)
	}
	if createdIdentity {
		log.Info().
			Str("identity_path", strings.TrimSpace(cfg.IdentityPath)).
			Str("address", listenerIdentity.Address).
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
	runtimeCfg.Identity = listenerIdentity.Copy()
	runtimeCfg.TargetAddr = targetAddr
	runtimeCfg.UDPAddr = udpAddr
	runtimeCfg.Metadata = cfg.Metadata.Copy()
	runtimeCfg.X402PayTo = x402PayTo
	runtimeCfg.X402Testnet = cfg.X402Testnet
	runtimeCfg.X402Network = strings.ToLower(strings.TrimSpace(cfg.X402Network))
	runtimeCfg.X402Asset = strings.TrimSpace(cfg.X402Asset)
	runtimeCfg.X402Endpoints = utils.CloneSlice(cfg.X402Endpoints)
	runtimeCfg.X402FacilitatorToken = strings.TrimSpace(cfg.X402FacilitatorToken)

	exposureCtx, cancel := context.WithCancel(ctx)
	exposure := &Exposure{
		cancel:         cancel,
		done:           exposureCtx.Done(),
		cfg:            utils.NewSnapshot(runtimeCfg, ExposeConfig.snapshot),
		accepted:       make(chan net.Conn, max(initialRouteCount*defaultReadyTarget*2, 1)),
		datagrams:      make(chan types.DatagramFrame, max(initialRouteCount*32, 1)),
		relaySet:       discovery.NewRelaySet(relaySetURLs),
		relayListeners: make(map[string]*listener, initialRouteCount),
		relayStates:    make(map[string]*relayRuntimeState, initialRouteCount),
		notifyCh:       make(chan struct{}),
		updatesSubs:    make(map[chan RelayUpdate]struct{}),
	}

	if cfg.Discovery {
		refresher := discovery.NewRefresher(exposure.relaySet)
		if err := refresher.Refresh(ctx, nil); err != nil {
			_ = exposure.Close()
			return nil, fmt.Errorf("discover relays: %w", err)
		}
	}

	if initialRouteCount > 0 || cfg.Discovery {
		if err := exposure.reconcileRelayListeners(true); err != nil {
			_ = exposure.Close()
			return nil, err
		}
	}

	if cfg.Discovery {
		go exposure.runDiscoveryLoop(exposureCtx)
	}

	go func() {
		<-exposure.done
		_ = exposure.Close()
	}()

	return exposure, nil
}

// emitRelayEvent updates the canonical per-relay state and notifies all
// waiters and Updates() subscribers. It is called by listener lifecycle
// transitions and by reconcileRelayListeners for add/remove events.
func (e *Exposure) emitRelayEvent(relayURL string, state RelayState, publicURL string, err error, udpAddr string, datagramReady bool, version string, explicit bool) {
	if relayURL == "" {
		return
	}

	e.relayStateMu.Lock()
	if e.relayStates == nil {
		e.relayStates = make(map[string]*relayRuntimeState)
	}
	rs, exists := e.relayStates[relayURL]
	if !exists {
		rs = &relayRuntimeState{}
		e.relayStates[relayURL] = rs
	}
	rs.state = state
	rs.publicURL = publicURL
	rs.err = err
	rs.udpAddr = udpAddr
	rs.datagramReady = datagramReady
	rs.version = version
	rs.explicit = explicit
	e.relayStateMu.Unlock()

	// Wake up WaitReady / WaitDatagramReady.
	e.notifyMu.Lock()
	if e.notifyCh == nil {
		e.notifyCh = make(chan struct{})
	}
	close(e.notifyCh)
	e.notifyCh = make(chan struct{})
	e.notifyMu.Unlock()

	// Fan-out to Updates() subscribers.
	update := RelayUpdate{
		RelayURL:  relayURL,
		State:     state,
		PublicURL: publicURL,
	}
	if err != nil {
		update.Error = err.Error()
	}
	e.updatesMu.Lock()
	for ch := range e.updatesSubs {
		select {
		case ch <- update:
		default:
		}
	}
	e.updatesMu.Unlock()
}

// notifyChan returns the current notification channel. It is closed when
// the canonical state changes.
func (e *Exposure) notifyChan() chan struct{} {
	e.notifyMu.Lock()
	ch := e.notifyCh
	if ch == nil {
		ch = make(chan struct{})
	}
	e.notifyMu.Unlock()
	return ch
}

// Relays returns a snapshot of all relay statuses derived from the
// canonical per-relay state, merged with relay-set discovery metadata.
// This is the single source of truth that Snapshot, the agent dashboard,
// and external callers consume.
// Relays returns a snapshot of all relay statuses derived from the
// canonical per-relay state, merged with relay-set discovery metadata.
// This is the single source of truth that the agent dashboard and
// external callers consume.
func (e *Exposure) Relays() []RelayStatus {
	cfg := e.Config()

	e.relayStateMu.RLock()
	relayByURL := make(map[string]RelayStatus, len(e.relayStates))
	for relayURL, rs := range e.relayStates {
		snap := RelayStatus{
			RelayURL:   relayURL,
			State:      rs.state,
			PublicURL:  rs.publicURL,
			Version:    rs.version,
			Explicit:   rs.explicit,
			Connecting: rs.explicit && (rs.state == RelayStatePending || rs.state == RelayStateRegistering),
		}
		if rs.err != nil {
			snap.Error = rs.err.Error()
		}
		relayByURL[relayURL] = snap
	}
	e.relayStateMu.RUnlock()

	// Merge relay-set discovery state (banned, bootstrap, transport caps).
	if e.relaySet != nil {
		for _, state := range e.relaySet.AllRelays() {
			relayURL := strings.TrimSpace(state.Descriptor.APIHTTPSAddr)
			if relayURL == "" {
				continue
			}
			if state.Dead {
				delete(relayByURL, relayURL)
				continue
			}
			snap := relayByURL[relayURL]
			snap.RelayURL = relayURL
			snap.Explicit = slices.Contains(cfg.RelayURLs, relayURL)
			snap.Bootstrap = state.Bootstrap
			snap.Banned = state.Banned
			snap.SupportsUDP = state.Descriptor.SupportsUDP
			snap.SupportsTCP = state.Descriptor.SupportsTCP
			relayByURL[relayURL] = snap
		}
	}

	relays := make([]RelayStatus, 0, len(relayByURL))
	for _, snap := range relayByURL {
		relays = append(relays, snap)
	}
	slices.SortFunc(relays, func(a, b RelayStatus) int {
		aReady := a.State == RelayStateReady || a.State == RelayStateDatagramReady
		bReady := b.State == RelayStateReady || b.State == RelayStateDatagramReady
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
	return relays
}

// Updates returns a channel that receives a RelayUpdate every time a
// relay's canonical state changes. The channel is buffered; events are
// dropped if the buffer is full. The channel is closed when the exposure
// is closed.
func (e *Exposure) Updates() <-chan RelayUpdate {
	ch := make(chan RelayUpdate, 32)
	e.updatesMu.Lock()
	e.updatesSubs[ch] = struct{}{}
	e.updatesMu.Unlock()
	return ch
}

// WaitReady blocks until at least one relay reaches the ready or
// datagramReady state, or returns ErrNoRelays when the relay pool is
// exhausted (no relays and discovery is disabled, or all relays have
// terminally failed and discovery cannot yield new candidates).
func (e *Exposure) WaitReady(ctx context.Context) error {
	for {
		if e.closed() {
			return net.ErrClosed
		}

		e.relayStateMu.RLock()
		hasReady := false
		hasPending := false
		activeRelays := 0
		for _, rs := range e.relayStates {
			if rs.state == RelayStateRemoved {
				continue
			}
			activeRelays++
			switch rs.state {
			case RelayStateReady, RelayStateDatagramReady:
				hasReady = true
			case RelayStatePending, RelayStateRegistering:
				hasPending = true
			}
		}
		e.relayStateMu.RUnlock()

		if hasReady {
			return nil
		}

		discovery := e.Config().Discovery
		if activeRelays == 0 && !discovery {
			return ErrNoRelays
		}
		if !hasPending && !discovery {
			return ErrNoRelays
		}

		select {
		case <-e.done:
			return net.ErrClosed
		case <-ctx.Done():
			return ctx.Err()
		case <-e.notifyChan():
		}
	}
}

// removeRelayState deletes a relay from the canonical state map and
// notifies waiters. Called when a relay is explicitly removed via
// RemoveRelay or when reconcileRelayListeners drops a stale listener
// that was never started.
func (e *Exposure) removeRelayState(relayURL string) {
	if relayURL == "" {
		return
	}
	e.relayStateMu.Lock()
	if e.relayStates != nil {
		delete(e.relayStates, relayURL)
	}
	e.relayStateMu.Unlock()
	e.notifyMu.Lock()
	if e.notifyCh != nil {
		close(e.notifyCh)
		e.notifyCh = make(chan struct{})
	}
	e.notifyMu.Unlock()
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

	e.cfg.UpdateCopy(func(cfg *ExposeConfig) {
		nextRelays := cfg.RelayURLs[:0]
		for _, existing := range cfg.RelayURLs {
			if existing != relayURL {
				nextRelays = append(nextRelays, existing)
			}
		}
		cfg.RelayURLs = nextRelays
	})

	e.relaySet.DeactivateRelayURL(relayURL)
	e.relaySet.RemoveBootstrapRelayURL(relayURL)
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

func (e *Exposure) Identity() types.Identity {
	return e.Config().Identity
}

func (e *Exposure) Snapshot() types.AgentTunnelStatus {
	cfg := e.Config()
	relays := e.Relays()
	agentRelays := make([]types.AgentRelayStatus, len(relays))
	for i, r := range relays {
		agentRelays[i] = types.AgentRelayStatus{
			RelayURL:    r.RelayURL,
			State:       string(r.State),
			PublicURL:   r.PublicURL,
			Error:       r.Error,
			Version:     r.Version,
			Explicit:    r.Explicit,
			Connecting:  r.Connecting,
			Bootstrap:   r.Bootstrap,
			Banned:      r.Banned,
			SupportsUDP: r.SupportsUDP,
			SupportsTCP: r.SupportsTCP,
		}
	}
	return types.AgentTunnelStatus{
		Address:         cfg.Identity.Address,
		TargetAddr:      cfg.TargetAddr,
		Overlay:         cfg.Overlay,
		MaxActiveRelays: cfg.MaxActiveRelays,
		Metadata:        cfg.Metadata,
		Relays:          agentRelays,
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

	for {
		if e.closed() {
			return nil, net.ErrClosed
		}

		e.relayStateMu.RLock()
		addrs := make([]string, 0)
		seen := make(map[string]struct{})
		hasPending := false
		hasReadyWithoutDatagram := false
		activeRelays := 0
		for _, rs := range e.relayStates {
			if rs.state == RelayStateRemoved {
				continue
			}
			activeRelays++
			switch rs.state {
			case RelayStateDatagramReady:
				if rs.udpAddr != "" {
					if _, ok := seen[rs.udpAddr]; !ok {
						seen[rs.udpAddr] = struct{}{}
						addrs = append(addrs, rs.udpAddr)
					}
				}
			case RelayStateReady:
				// A ready relay with a UDP address may still connect its
				// datagram backhaul; one without a UDP address is resolved.
				if rs.udpAddr != "" {
					hasPending = true
				} else {
					hasReadyWithoutDatagram = true
				}
			case RelayStatePending, RelayStateRegistering:
				hasPending = true
			}
		}
		e.relayStateMu.RUnlock()

		if len(addrs) > 0 {
			return addrs, nil
		}

		discovery := e.Config().Discovery
		if activeRelays == 0 && !discovery {
			return nil, ErrNoRelays
		}
		if !hasPending && !discovery {
			if hasReadyWithoutDatagram {
				return nil, errors.New("relay did not expose udp")
			}
			return nil, ErrNoRelays
		}

		select {
		case <-e.done:
			return nil, net.ErrClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-e.notifyChan():
		}
	}
}

// RunHTTPRoutes serves path-routed HTTP upstreams through the exposure.
func (e *Exposure) RunHTTPRoutes(ctx context.Context, routes []HTTPRouteConfig, localAddr string) error {
	cfg := e.Config()
	handler, err := NewHTTPRoutes(routes, types.X402Payment{
		Testnet:          cfg.X402Testnet,
		Network:          cfg.X402Network,
		Asset:            cfg.X402Asset,
		PayTo:            cfg.X402PayTo,
		Endpoints:        cfg.X402Endpoints,
		FacilitatorToken: cfg.X402FacilitatorToken,
	})
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

		event := log.Debug().
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
	select {
	case <-e.done:
		return nil, net.ErrClosed
	case conn := <-e.accepted:
		if conn == nil {
			return nil, net.ErrClosed
		}

		connID := e.connSeq.Add(1)
		log.Debug().
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

		// Emit removed events for all relays in the canonical state.
		e.relayStateMu.Lock()
		if e.relayStates != nil {
			for relayURL := range e.relayStates {
				e.relayStates[relayURL].state = RelayStateRemoved
			}
		}
		e.relayStateMu.Unlock()
		e.notifyMu.Lock()
		if e.notifyCh != nil {
			close(e.notifyCh)
			e.notifyCh = make(chan struct{})
		}
		e.notifyMu.Unlock()

		// Close all Updates() subscriber channels.
		e.updatesMu.Lock()
		if e.updatesSubs != nil {
			for ch := range e.updatesSubs {
				close(ch)
				delete(e.updatesSubs, ch)
			}
		}
		e.updatesMu.Unlock()

		event := log.Debug().
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

func (e *Exposure) runDiscoveryLoop(ctx context.Context) {
	refresher := discovery.NewRefresher(e.relaySet)
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
	if e.relaySet == nil {
		return errors.New("relay set is unavailable")
	}
	cfg := e.Config()
	routes := e.relaySet.SelectRelays(discovery.RouteState{
		ExplicitRelayURLs: append([]string(nil), cfg.RelayURLs...),
		ActiveRelayURLs:   e.ActiveRelayURLs(),
		MaxActiveRelays:   cfg.MaxActiveRelays,
		RequireUDP:        cfg.UDPEnabled,
		RequireTCP:        cfg.TCPEnabled,
		LocalAddress:      cfg.Identity.Address,
	})

	routesByRelay := make(map[string]discovery.Route, len(routes))
	for _, route := range routes {
		relayURL := route.RelayURL
		if relayURL == "" {
			continue
		}
		routesByRelay[relayURL] = route
	}

	e.mu.Lock()
	staleListeners := make(map[string]*listener)
	for relayURL, listener := range e.relayListeners {
		route, wanted := routesByRelay[relayURL]
		if wanted && listener != nil && listener.route == route {
			continue
		}
		staleListeners[relayURL] = listener
		delete(e.relayListeners, relayURL)
	}
	missingRoutes := make([]discovery.Route, 0)
	for _, route := range routes {
		relayURL := route.RelayURL
		if _, exists := e.relayListeners[relayURL]; exists {
			continue
		}
		missingRoutes = append(missingRoutes, route)
	}
	e.mu.Unlock()

	addedRelayURLs := make([]string, 0, len(missingRoutes))
	for relayURL, listener := range staleListeners {
		if listener == nil {
			continue
		}
		e.emitRelayEvent(relayURL, RelayStateRemoved, "", nil, "", false, "", false)
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Warn().Err(err).Str("relay_url", relayURL).Msg("close stale relay listener")
		}
	}
	for _, route := range missingRoutes {
		relayURL := route.RelayURL
		retryCount := 10
		if route.Explicit {
			retryCount = 0
		}
		listener, err := newListener(context.Background(), route, listenerConfig{
			Identity:   cfg.Identity.Copy(),
			Overlay:    cfg.Overlay,
			UDPEnabled: cfg.UDPEnabled,
			TCPEnabled: cfg.TCPEnabled,
			ECH:        cfg.ECH,
			BanMITM:    cfg.BanMITM,
			Metadata: func() types.LeaseMetadata {
				return e.Config().Metadata
			},
			RetryCount: retryCount,
			relaySet:   e.relaySet,
			onEvent:    e.emitRelayEvent,
		})
		if err != nil {
			if failOnError {
				return fmt.Errorf("listen %q: %w", relayURL, err)
			}
			if e.relaySet != nil && relayURL != "" {
				e.relaySet.RecordActiveFailure(relayURL, 1)
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

	if len(staleListeners) > 0 || len(addedRelayURLs) > 0 {
		removedRelayURLs := make([]string, 0, len(staleListeners))
		for relayURL := range staleListeners {
			removedRelayURLs = append(removedRelayURLs, relayURL)
		}
		if len(removedRelayURLs) > 1 {
			slices.Sort(removedRelayURLs)
		}
		listenerRelayURLs := make([]string, 0, len(routes))
		for _, route := range routes {
			listenerRelayURLs = append(listenerRelayURLs, route.RelayURL)
		}
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

	relayURL := listener.route.RelayURL
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
		e.mu.Lock()
		if current, ok := e.relayListeners[relayURL]; ok && current == listener {
			delete(e.relayListeners, relayURL)
		}
		e.mu.Unlock()
	}()

	for {
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
			log.Warn().Err(err).Str("relay_url", relayURL).Msg("exposure listener accept failed")
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
