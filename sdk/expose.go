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

	"github.com/rs/zerolog/log"

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
	RelayURL  string
	PublicURL string
	UDPAddr   string
	TCPAddr   string
	Version   string
	State     RelayState
	Err       error
}

// Exposure owns the lifecycle of one or more relay listeners and accepts
// traffic from all of them through one net.Listener.
type Exposure struct {
	cancel context.CancelFunc
	done   <-chan struct{}

	identity types.Identity
	options  options
	metadata *utils.Snapshot[types.LeaseMetadata]

	accepted  chan net.Conn
	datagrams chan types.DatagramFrame

	mu             sync.RWMutex
	reconcileMu    sync.Mutex
	relayURLs      []string
	relayListeners map[string]*listener
	blockedRelays  map[string]error
	statuses       map[string]RelayStatus
	stateChanged   chan struct{}
	statusEvents   chan RelayStatus
	updates        chan RelayStatus
	acceptLoops    sync.WaitGroup

	closeOnce sync.Once
	connSeq   atomic.Uint64
}

var _ net.Listener = (*Exposure)(nil)

type options struct {
	UDPEnabled bool
	TCPEnabled bool
	ECH        bool
	BanMITM    bool
	Overlay    bool
	Metadata   types.LeaseMetadata
}

// Option configures an optional capability of a relay-backed exposure.
type Option func(*options)

// WithUDP enables the datagram transport capability.
func WithUDP() Option {
	return func(opts *options) { opts.UDPEnabled = true }
}

// WithTCP enables public raw TCP port allocation.
func WithTCP() Option {
	return func(opts *options) { opts.TCPEnabled = true }
}

// WithECH enables ECH hostname privacy for TLS stream tunnels.
func WithECH() Option {
	return func(opts *options) { opts.ECH = true }
}

// WithMITMProtection controls relay MITM self-probing.
func WithMITMProtection(enabled bool) Option {
	return func(opts *options) { opts.BanMITM = enabled }
}

// WithOverlay enables relay overlay routing.
func WithOverlay() Option {
	return func(opts *options) { opts.Overlay = true }
}

// WithMetadata sets the initial lease metadata.
func WithMetadata(metadata types.LeaseMetadata) Option {
	return func(opts *options) { opts.Metadata = metadata.Copy() }
}

// Expose constructs a relay-backed network endpoint from an already-resolved
// identity and concrete relay URLs. It never creates or persists keys.
func Expose(ctx context.Context, identity types.Identity, relays []string, opts ...Option) (*Exposure, error) {
	var cfg options
	for _, option := range opts {
		if option == nil {
			return nil, errors.New("portal sdk: option is nil")
		}
		option(&cfg)
	}
	if ctx == nil {
		return nil, errors.New("portal sdk: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	relayURLs, err := utils.NormalizeRelayURLs(relays...)
	if err != nil {
		return nil, err
	}
	if len(relayURLs) == 0 {
		return nil, errors.New("portal sdk: at least one relay is required")
	}
	if strings.TrimSpace(identity.Name) == "" {
		return nil, errors.New("portal sdk: identity name is required")
	}
	if strings.TrimSpace(identity.Address) == "" ||
		strings.TrimSpace(identity.PublicKey) == "" ||
		strings.TrimSpace(identity.PrivateKey) == "" {
		return nil, errors.New("portal sdk: identity must include address, public key, and private key")
	}

	exposureCtx, cancel := context.WithCancel(ctx)
	exposure := &Exposure{
		cancel:         cancel,
		done:           exposureCtx.Done(),
		identity:       identity.Copy(),
		options:        cfg,
		metadata:       utils.NewSnapshot(cfg.Metadata.Copy(), types.LeaseMetadata.Copy),
		accepted:       make(chan net.Conn, max(len(relayURLs)*defaultReadyTarget*2, 1)),
		datagrams:      make(chan types.DatagramFrame, max(len(relayURLs)*32, 1)),
		relayListeners: make(map[string]*listener, len(relayURLs)),
		blockedRelays:  make(map[string]error),
		statuses:       make(map[string]RelayStatus, len(relayURLs)),
		stateChanged:   make(chan struct{}),
		statusEvents:   make(chan RelayStatus, max(len(relayURLs)*4, 4)),
		updates:        make(chan RelayStatus, max(len(relayURLs)*4, 4)),
	}
	go exposure.runStatusUpdates(exposureCtx)

	if err := exposure.setRelays(relayURLs, true); err != nil {
		_ = exposure.Close()
		return nil, err
	}

	go func() {
		<-exposure.done
		_ = exposure.Close()
	}()

	return exposure, nil
}

// SetRelays replaces the concrete relay membership without restarting the
// exposure.
func (e *Exposure) SetRelays(relays []string) error {
	relayURLs, err := utils.NormalizeRelayURLs(relays...)
	if err != nil {
		return err
	}
	if e.closed() {
		return net.ErrClosed
	}
	return e.setRelays(relayURLs, true)
}

func (e *Exposure) setRelays(relayURLs []string, failOnError bool) error {
	e.mu.Lock()
	desired := make(map[string]struct{}, len(relayURLs))
	for _, relayURL := range relayURLs {
		desired[relayURL] = struct{}{}
	}
	for relayURL := range e.blockedRelays {
		if _, retained := desired[relayURL]; !retained {
			delete(e.blockedRelays, relayURL)
		}
	}
	e.relayURLs = append([]string(nil), relayURLs...)
	e.mu.Unlock()
	return e.reconcileRelayListeners(failOnError)
}

// AddRelay adds one concrete relay without restarting the exposure.
func (e *Exposure) AddRelay(relayURL string) error {
	relayURL, err := utils.NormalizeRelayURL(relayURL)
	if err != nil {
		return err
	}
	if e.closed() {
		return net.ErrClosed
	}
	e.mu.Lock()
	if !slices.Contains(e.relayURLs, relayURL) {
		e.relayURLs = append(e.relayURLs, relayURL)
		slices.Sort(e.relayURLs)
	}
	e.mu.Unlock()
	return e.reconcileRelayListeners(true)
}

// RemoveRelay removes one concrete relay without restarting the exposure.
func (e *Exposure) RemoveRelay(relayURL string) error {
	relayURL, err := utils.NormalizeRelayURL(relayURL)
	if err != nil {
		return err
	}
	if e.closed() {
		return net.ErrClosed
	}
	e.mu.Lock()
	nextRelays := make([]string, 0, len(e.relayURLs))
	for _, existing := range e.relayURLs {
		if existing != relayURL {
			nextRelays = append(nextRelays, existing)
		}
	}
	e.relayURLs = nextRelays
	delete(e.blockedRelays, relayURL)
	e.mu.Unlock()
	return e.reconcileRelayListeners(false)
}

func (e *Exposure) UpdateMetadata(metadata types.LeaseMetadata) error {
	if e.closed() {
		return net.ErrClosed
	}

	e.metadata.Store(metadata.Copy())
	return nil
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
	identity := e.identity
	if identity.Address == "" {
		return exposureAddr("portal:exposure")
	}
	return exposureAddr("portal:" + identity.Address)
}

type exposureAddr string

func (a exposureAddr) Network() string { return "portal" }
func (a exposureAddr) String() string  { return string(a) }

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
		if errors.Is(update.err, errMITMDetected) {
			if e.blockedRelays == nil {
				e.blockedRelays = make(map[string]error)
			}
			e.blockedRelays[relayURL] = update.err
		}
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
		relayErrorsEqual(a.Err, b.Err)
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

func (e *Exposure) syncRelayStatuses(relayURLs []string) {
	desired := make(map[string]RelayStatus, len(relayURLs))
	for _, relayURL := range relayURLs {
		desired[relayURL] = RelayStatus{
			RelayURL: relayURL,
			State:    RelayConnecting,
		}
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
			status.State = current.State
			status.Err = current.Err
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
	if e == nil {
		return true
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.relayURLs) == 0 {
		return true
	}
	for _, relayURL := range e.relayURLs {
		status, ok := e.statuses[relayURL]
		if !ok || status.State != RelayFailed {
			return false
		}
	}
	return true
}

func (e *Exposure) readyRelays(matches func(RelayStatus) bool) ([]RelayStatus, <-chan struct{}) {
	e.mu.RLock()
	ready := make([]RelayStatus, 0, len(e.statuses))
	for _, status := range e.statuses {
		if !matches(status) {
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
		ready, changed := e.readyRelays(func(status RelayStatus) bool {
			return status.State == RelayReady
		})
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
	if !e.options.UDPEnabled {
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
	if !e.options.UDPEnabled {
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
	if !e.options.UDPEnabled {
		return nil, errors.New("exposure does not have udp enabled")
	}
	if ctx == nil {
		return nil, errors.New("portal sdk: context is nil")
	}

	for {
		ready, changed := e.readyRelays(func(status RelayStatus) bool {
			return status.State != RelayFailed && status.UDPAddr != ""
		})
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

// WaitTCPReady waits until at least one relay has allocated a public TCP
// address and returns the ready relay snapshots.
func (e *Exposure) WaitTCPReady(ctx context.Context) ([]RelayStatus, error) {
	if !e.options.TCPEnabled {
		return nil, errors.New("exposure does not have tcp enabled")
	}
	if ctx == nil {
		return nil, errors.New("portal sdk: context is nil")
	}

	for {
		ready, changed := e.readyRelays(func(status RelayStatus) bool {
			return status.State != RelayFailed && status.TCPAddr != ""
		})
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

func (e *Exposure) reconcileRelayListeners(failOnError bool) error {
	e.reconcileMu.Lock()
	defer e.reconcileMu.Unlock()

	e.mu.RLock()
	relayURLs := append([]string(nil), e.relayURLs...)
	e.mu.RUnlock()
	desired := make(map[string]struct{}, len(relayURLs))
	for _, relayURL := range relayURLs {
		e.mu.RLock()
		_, blocked := e.blockedRelays[relayURL]
		e.mu.RUnlock()
		if blocked {
			continue
		}
		desired[relayURL] = struct{}{}
	}
	e.syncRelayStatuses(relayURLs)

	e.mu.Lock()
	staleListeners := make(map[string]*listener)
	stateChanged := false
	for relayURL, listener := range e.relayListeners {
		_, wanted := desired[relayURL]
		if wanted && listener != nil {
			continue
		}
		staleListeners[relayURL] = listener
		delete(e.relayListeners, relayURL)
		stateChanged = true
	}
	missingRelayURLs := make([]string, 0)
	for _, relayURL := range relayURLs {
		if _, exists := e.relayListeners[relayURL]; exists {
			continue
		}
		missingRelayURLs = append(missingRelayURLs, relayURL)
	}
	if stateChanged {
		e.notifyStateChangedLocked()
	}
	e.mu.Unlock()

	addedRelayURLs := make([]string, 0, len(missingRelayURLs))
	for relayURL, listener := range staleListeners {
		if listener == nil {
			continue
		}
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Warn().Err(err).Str("relay_url", relayURL).Msg("close stale relay listener")
		}
	}
	for _, relayURL := range missingRelayURLs {
		e.setRelayStatus(relayURL, listenerStatus{state: RelayConnecting})
		listener, err := newListener(context.Background(), relayURL, listenerConfig{
			Identity:   e.identity.Copy(),
			Overlay:    e.options.Overlay,
			UDPEnabled: e.options.UDPEnabled,
			TCPEnabled: e.options.TCPEnabled,
			ECH:        e.options.ECH,
			BanMITM:    e.options.BanMITM,
			Metadata: func() types.LeaseMetadata {
				return e.metadata.Load()
			},
			Status: func(status listenerStatus) {
				e.setRelayStatus(relayURL, status)
			},
			RetryCount: 0,
		})
		if err != nil {
			e.setRelayStatus(relayURL, listenerStatus{state: RelayFailed, err: err})
			if failOnError {
				return fmt.Errorf("listen %q: %w", relayURL, err)
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
		log.Info().
			Strs("added_relays", addedRelayURLs).
			Strs("removed_relays", removedRelayURLs).
			Strs("listener_relays", relayURLs).
			Msg("reconciled relay listeners")
	}
	return nil
}

func (e *Exposure) runListenerAcceptLoop(listener *listener) {
	if listener == nil {
		return
	}

	relayURL := listener.relayURL.String()
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
