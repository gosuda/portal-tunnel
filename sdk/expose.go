package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/internal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// ErrNoRelays indicates that every explicitly configured relay failed.
var ErrNoRelays = errors.New("portal sdk: no relays available")

// RelayState is the lifecycle state of one relay.
type RelayState string

const (
	RelayIdle       RelayState = "idle"
	RelayConnecting RelayState = "connecting"
	RelayReady      RelayState = "ready"
	RelayFailed     RelayState = "failed"
)

// RelayStatus is an immutable snapshot of one relay's externally visible state.
type RelayStatus struct {
	RelayURL    string
	PublicURL   string
	UDPAddr     string
	TCPAddr     string
	Version     string
	State       RelayState
	Err         error
	Explicit    bool
	Bootstrap   bool
	Banned      bool
	SupportsUDP bool
	SupportsTCP bool
}

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
	statuses       map[string]RelayStatus
	stateChanged   chan struct{}
	statusEvents   chan RelayStatus
	updates        chan RelayStatus
	acceptLoops    sync.WaitGroup

	closeOnce sync.Once
	connSeq   atomic.Uint64
}

var _ net.Listener = (*Exposure)(nil)

// ExposeConfig contains relay and lease settings for an exposure.
type ExposeConfig struct {
	RelayURLs []string
	Discovery bool
	Overlay   bool

	Identity        types.Identity
	UDPEnabled      bool
	TCPEnabled      bool
	ECH             bool
	BanMITM         bool
	MaxActiveRelays int
	Metadata        types.LeaseMetadata
}

func (cfg ExposeConfig) snapshot() ExposeConfig {
	cfg.RelayURLs = utils.CloneSlice(cfg.RelayURLs)
	cfg.Identity = cfg.Identity.Copy()
	cfg.Metadata = cfg.Metadata.Copy()
	return cfg
}

// Expose creates relay listeners for the selected relay pool and exposes a
// dynamic listener hub for accepting traffic from all of them. Identity must
// already be resolved by the caller; Expose never creates or persists keys.
func Expose(ctx context.Context, cfg ExposeConfig) (*Exposure, error) {
	if ctx == nil {
		return nil, errors.New("portal sdk: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	explicitRelayURLs, err := utils.NormalizeRelayURLs(cfg.RelayURLs...)
	if err != nil {
		return nil, err
	}
	initialRouteCount := len(explicitRelayURLs)
	if initialRouteCount == 0 && !cfg.Discovery {
		return nil, errors.New("portal sdk: at least one relay or discovery is required")
	}
	relaySetURLs, err := utils.ResolvePortalRelayURLs(explicitRelayURLs, cfg.Discovery)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Identity.Name) == "" {
		return nil, errors.New("portal sdk: identity name is required")
	}
	if strings.TrimSpace(cfg.Identity.Address) == "" ||
		strings.TrimSpace(cfg.Identity.PublicKey) == "" ||
		strings.TrimSpace(cfg.Identity.PrivateKey) == "" {
		return nil, errors.New("portal sdk: identity must include address, public key, and private key")
	}
	runtimeCfg := cfg.snapshot()
	runtimeCfg.RelayURLs = append([]string(nil), explicitRelayURLs...)
	runtimeCfg.Identity = cfg.Identity.Copy()

	exposureCtx, cancel := context.WithCancel(ctx)
	exposure := &Exposure{
		cancel:         cancel,
		done:           exposureCtx.Done(),
		cfg:            utils.NewSnapshot(runtimeCfg, ExposeConfig.snapshot),
		accepted:       make(chan net.Conn, max(initialRouteCount*defaultReadyTarget*2, 1)),
		datagrams:      make(chan types.DatagramFrame, max(initialRouteCount*32, 1)),
		relaySet:       discovery.NewRelaySet(relaySetURLs),
		relayListeners: make(map[string]*listener, initialRouteCount),
		statuses:       make(map[string]RelayStatus, initialRouteCount),
		stateChanged:   make(chan struct{}),
		statusEvents:   make(chan RelayStatus, max(initialRouteCount*4, 4)),
		updates:        make(chan RelayStatus, max(initialRouteCount*4, 4)),
	}
	go exposure.runStatusUpdates(exposureCtx)

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

func (e *Exposure) activeRelayURLs() []string {
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
	if e == nil {
		return true
	}
	if e.done == nil {
		return false
	}
	select {
	case <-e.done:
		return true
	default:
		return false
	}
}

func (e *Exposure) Addr() net.Addr {
	identity := e.config().Identity
	if identity.Address == "" {
		return exposureAddr("portal:exposure")
	}
	return exposureAddr("portal:" + identity.Address)
}

type exposureAddr string

func (a exposureAddr) Network() string { return "portal" }
func (a exposureAddr) String() string  { return string(a) }

func (e *Exposure) config() ExposeConfig {
	if e == nil || e.cfg == nil {
		return ExposeConfig{}
	}
	return e.cfg.Load()
}

// Relays returns a sorted point-in-time snapshot of the relay pool.
func (e *Exposure) Relays() []RelayStatus {
	if e == nil {
		return nil
	}
	e.mu.RLock()
	relays := make([]RelayStatus, 0, len(e.statuses))
	for _, status := range e.statuses {
		relays = append(relays, status)
	}
	e.mu.RUnlock()
	slices.SortFunc(relays, func(a, b RelayStatus) int {
		aReady := a.State == RelayReady
		bReady := b.State == RelayReady
		if aReady != bReady {
			if aReady {
				return -1
			}
			return 1
		}
		aConnecting := a.State == RelayConnecting
		bConnecting := b.State == RelayConnecting
		if aConnecting != bConnecting {
			if aConnecting {
				return -1
			}
			return 1
		}
		return strings.Compare(a.RelayURL, b.RelayURL)
	})
	return relays
}

func (e *Exposure) runStatusUpdates(ctx context.Context) {
	defer close(e.updates)
	for {
		select {
		case <-ctx.Done():
			return
		case status := <-e.statusEvents:
			select {
			case e.updates <- status:
			default:
			}
		}
	}
}

func (e *Exposure) setRelayStatus(relayURL string, update listenerStatus) {
	if e == nil || relayURL == "" || e.closed() {
		return
	}

	e.mu.Lock()
	if e.statuses == nil {
		e.statuses = make(map[string]RelayStatus)
	}
	status, exists := e.statuses[relayURL]
	if !exists {
		status = RelayStatus{RelayURL: relayURL, State: RelayConnecting}
	}
	previous := status
	status.RelayURL = relayURL
	if update.state != "" {
		status.State = update.state
	}
	if update.version != "" {
		status.Version = update.version
	}
	if update.err != nil {
		status.Err = update.err
	} else if update.state != RelayFailed {
		status.Err = nil
	}
	if update.state == RelayConnecting {
		status.PublicURL = ""
		status.UDPAddr = ""
		status.TCPAddr = ""
	}
	if update.publicURL != "" || update.state == RelayReady {
		status.PublicURL = update.publicURL
	}
	if update.udpAddr != "" || update.state == RelayConnecting || update.state == RelayReady {
		status.UDPAddr = update.udpAddr
	}
	if update.tcpAddr != "" || update.state == RelayConnecting || update.state == RelayReady {
		status.TCPAddr = update.tcpAddr
	}
	if !relayStatusEqual(previous, status) {
		e.statuses[relayURL] = status
		e.notifyStateChangedLocked()
	} else {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()

	select {
	case <-e.done:
	case e.statusEvents <- status:
	default:
	}
}

func relayStatusEqual(a, b RelayStatus) bool {
	return a.RelayURL == b.RelayURL &&
		a.PublicURL == b.PublicURL &&
		a.UDPAddr == b.UDPAddr &&
		a.TCPAddr == b.TCPAddr &&
		a.Version == b.Version &&
		a.State == b.State &&
		relayErrorsEqual(a.Err, b.Err) &&
		a.Explicit == b.Explicit &&
		a.Bootstrap == b.Bootstrap &&
		a.Banned == b.Banned &&
		a.SupportsUDP == b.SupportsUDP &&
		a.SupportsTCP == b.SupportsTCP
}

func relayErrorsEqual(a, b error) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Error() == b.Error()
}

func (e *Exposure) notifyStateChangedLocked() {
	if e.stateChanged != nil {
		close(e.stateChanged)
	}
	e.stateChanged = make(chan struct{})
}

func (e *Exposure) syncRelayStatuses(routes []discovery.Route, cfg ExposeConfig) {
	desired := make(map[string]RelayStatus)
	dead := make(map[string]bool)
	if e.relaySet != nil {
		for _, state := range e.relaySet.AllRelays() {
			relayURL := strings.TrimSpace(state.Descriptor.APIHTTPSAddr)
			if relayURL == "" {
				continue
			}
			if state.Dead {
				dead[relayURL] = true
				continue
			}
			desired[relayURL] = RelayStatus{
				RelayURL:    relayURL,
				State:       RelayIdle,
				Bootstrap:   state.Bootstrap,
				Banned:      state.Banned,
				SupportsUDP: state.Descriptor.SupportsUDP,
				SupportsTCP: state.Descriptor.SupportsTCP,
			}
		}
	}
	for _, relayURL := range cfg.RelayURLs {
		relayURL = strings.TrimSpace(relayURL)
		if relayURL == "" {
			continue
		}
		status := desired[relayURL]
		status.RelayURL = relayURL
		status.Explicit = true
		if dead[relayURL] {
			status.State = RelayFailed
		}
		if status.State == "" {
			status.State = RelayConnecting
		}
		desired[relayURL] = status
	}
	for _, route := range routes {
		relayURL := strings.TrimSpace(route.RelayURL)
		if relayURL == "" {
			continue
		}
		status := desired[relayURL]
		status.RelayURL = relayURL
		status.Explicit = status.Explicit || route.Explicit
		if status.State == "" {
			status.State = RelayConnecting
		}
		desired[relayURL] = status
	}

	e.mu.Lock()
	if e.statuses == nil {
		e.statuses = make(map[string]RelayStatus)
	}
	changed := false
	for relayURL, status := range desired {
		if current, ok := e.statuses[relayURL]; ok {
			status.PublicURL = current.PublicURL
			status.UDPAddr = current.UDPAddr
			status.TCPAddr = current.TCPAddr
			status.Version = current.Version
			if dead[relayURL] {
				status.State = RelayFailed
				if current.State == RelayFailed {
					status.Err = current.Err
				}
			} else {
				status.State = current.State
				status.Err = current.Err
			}
			if relayStatusEqual(current, status) {
				continue
			}
		}
		e.statuses[relayURL] = status
		changed = true
	}
	for relayURL := range e.statuses {
		if _, ok := desired[relayURL]; ok {
			continue
		}
		delete(e.statuses, relayURL)
		changed = true
	}
	if changed {
		e.notifyStateChangedLocked()
	}
	e.mu.Unlock()
}

func (e *Exposure) noRelaysAvailable() bool {
	if e == nil || e.cfg == nil {
		return true
	}
	cfg := e.config()
	if len(cfg.RelayURLs) == 0 {
		return !cfg.Discovery
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, relayURL := range cfg.RelayURLs {
		status, ok := e.statuses[relayURL]
		if !ok || status.State != RelayFailed {
			return false
		}
	}
	return !cfg.Discovery
}

func (e *Exposure) readyRelays(datagram bool) ([]RelayStatus, <-chan struct{}) {
	e.mu.RLock()
	ready := make([]RelayStatus, 0, len(e.statuses))
	for _, status := range e.statuses {
		if !relayReady(status, datagram) {
			continue
		}
		ready = append(ready, status)
	}
	changed := e.stateChanged
	e.mu.RUnlock()
	slices.SortFunc(ready, func(a, b RelayStatus) int {
		return strings.Compare(a.RelayURL, b.RelayURL)
	})
	return ready, changed
}

func relayReady(status RelayStatus, datagram bool) bool {
	if status.State == RelayFailed {
		return false
	}
	if datagram {
		return status.UDPAddr != ""
	}
	return status.State == RelayReady
}

// Updates reports relay lifecycle changes. Relays is the authoritative
// snapshot; slow consumers may miss intermediate updates.
func (e *Exposure) Updates() <-chan RelayStatus {
	if e == nil {
		return nil
	}
	return e.updates
}

// WaitReady waits until at least one relay can accept tenant connections.
func (e *Exposure) WaitReady(ctx context.Context) ([]RelayStatus, error) {
	if e == nil {
		return nil, net.ErrClosed
	}
	if ctx == nil {
		return nil, errors.New("portal sdk: context is nil")
	}
	for {
		ready, changed := e.readyRelays(false)
		if len(ready) > 0 {
			return ready, nil
		}
		if e.closed() {
			return nil, net.ErrClosed
		}
		if e.noRelaysAvailable() {
			return nil, ErrNoRelays
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-e.done:
			return nil, net.ErrClosed
		case <-changed:
		}
	}
}

func (e *Exposure) AcceptDatagram() (types.DatagramFrame, error) {
	if !e.config().UDPEnabled {
		return types.DatagramFrame{}, net.ErrClosed
	}
	for {
		select {
		case frame := <-e.datagrams:
			return frame, nil
		default:
		}
		if e.noRelaysAvailable() {
			return types.DatagramFrame{}, ErrNoRelays
		}
		select {
		case <-e.done:
			return types.DatagramFrame{}, net.ErrClosed
		case frame := <-e.datagrams:
			return frame, nil
		}
	}
}

func (e *Exposure) SendDatagram(frame types.DatagramFrame) error {
	if !e.config().UDPEnabled {
		return net.ErrClosed
	}
	if e.noRelaysAvailable() {
		return ErrNoRelays
	}

	e.mu.RLock()
	listener := e.relayListeners[frame.RelayURL]
	e.mu.RUnlock()
	if listener == nil {
		return net.ErrClosed
	}
	return listener.sendDatagram(frame)
}

// WaitDatagramReady waits until at least one relay has an authenticated UDP
// backhaul and returns the ready relay snapshots.
func (e *Exposure) WaitDatagramReady(ctx context.Context) ([]RelayStatus, error) {
	if !e.config().UDPEnabled {
		return nil, errors.New("exposure does not have udp enabled")
	}
	if ctx == nil {
		return nil, errors.New("portal sdk: context is nil")
	}

	for {
		ready, changed := e.readyRelays(true)
		if len(ready) > 0 {
			return ready, nil
		}
		if e.noRelaysAvailable() {
			return nil, ErrNoRelays
		}

		select {
		case <-e.done:
			return nil, net.ErrClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
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

func (e *Exposure) Accept() (net.Conn, error) {
	if e == nil {
		return nil, net.ErrClosed
	}
	for {
		select {
		case conn := <-e.accepted:
			return e.wrapAccepted(conn)
		default:
		}

		e.mu.RLock()
		changed := e.stateChanged
		e.mu.RUnlock()
		if e.noRelaysAvailable() {
			return nil, ErrNoRelays
		}
		select {
		case <-e.done:
			return nil, net.ErrClosed
		case <-changed:
			continue
		case conn := <-e.accepted:
			return e.wrapAccepted(conn)
		}
	}
}

func (e *Exposure) wrapAccepted(conn net.Conn) (net.Conn, error) {
	if conn == nil {
		return nil, net.ErrClosed
	}
	if e.closed() {
		_ = conn.Close()
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
		e.acceptLoops.Wait()
		e.drainAccepted()
	})
	return closeErr
}

func (e *Exposure) drainAccepted() {
	if e == nil {
		return
	}
	for {
		select {
		case conn := <-e.accepted:
			if conn != nil {
				_ = conn.Close()
			}
		default:
			return
		}
	}
}

func (e *Exposure) runDiscoveryLoop(ctx context.Context) {
	refresher := discovery.NewRefresher(e.relaySet)
	ticker := time.NewTicker(discovery.DiscoveryPollInterval)
	defer ticker.Stop()

	for {
		if err := refresher.Refresh(ctx, nil); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn().Err(err).Msg("relay discovery refresh failed; will retry")
		} else if err := e.reconcileRelayListeners(false); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn().Err(err).Msg("relay listener reconciliation failed; will retry")
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
	cfg := e.config()
	routes := e.relaySet.SelectRelays(discovery.RouteState{
		ExplicitRelayURLs: append([]string(nil), cfg.RelayURLs...),
		ActiveRelayURLs:   e.activeRelayURLs(),
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
	e.syncRelayStatuses(routes, cfg)

	e.mu.Lock()
	staleListeners := make(map[string]*listener)
	stateChanged := false
	for relayURL, listener := range e.relayListeners {
		route, wanted := routesByRelay[relayURL]
		if wanted && listener != nil && listener.route == route {
			continue
		}
		staleListeners[relayURL] = listener
		delete(e.relayListeners, relayURL)
		stateChanged = true
	}
	missingRoutes := make([]discovery.Route, 0)
	for _, route := range routes {
		relayURL := route.RelayURL
		if _, exists := e.relayListeners[relayURL]; exists {
			continue
		}
		missingRoutes = append(missingRoutes, route)
	}
	if stateChanged {
		e.notifyStateChangedLocked()
	}
	e.mu.Unlock()

	addedRelayURLs := make([]string, 0, len(missingRoutes))
	for relayURL, listener := range staleListeners {
		if listener == nil {
			continue
		}
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Warn().Err(err).Str("relay_url", relayURL).Msg("close stale relay listener")
		}
	}
	for _, route := range missingRoutes {
		relayURL := route.RelayURL
		e.setRelayStatus(relayURL, listenerStatus{state: RelayConnecting})
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
				return e.config().Metadata
			},
			Status: func(status listenerStatus) {
				e.setRelayStatus(relayURL, status)
			},
			RetryCount: retryCount,
			relaySet:   e.relaySet,
		})
		if err != nil {
			e.setRelayStatus(relayURL, listenerStatus{state: RelayFailed, err: err})
			if failOnError {
				return fmt.Errorf("listen %q: %w", relayURL, err)
			}
			if e.relaySet != nil && relayURL != "" {
				e.relaySet.RecordActiveFailure(relayURL, 1)
			}
			log.Warn().Err(err).Str("relay_url", relayURL).Msg("add relay listener")
			continue
		}

		e.mu.Lock()
		if _, exists := e.relayListeners[relayURL]; exists {
			e.mu.Unlock()
			_ = listener.Close()
			continue
		}
		select {
		case <-e.done:
			e.mu.Unlock()
			_ = listener.Close()
			continue
		default:
		}
		e.relayListeners[relayURL] = listener
		e.acceptLoops.Add(1)
		e.mu.Unlock()
		addedRelayURLs = append(addedRelayURLs, relayURL)

		go func() {
			defer e.acceptLoops.Done()
			e.runListenerAcceptLoop(listener)
		}()
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
	var workers sync.WaitGroup
	defer workers.Wait()
	if listener.udpEnabled {
		workers.Add(1)
		go func() {
			defer workers.Done()
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

		select {
		case <-e.done:
			_ = conn.Close()
			return
		case e.accepted <- conn:
		}
	}
}
