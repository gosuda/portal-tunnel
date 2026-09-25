package sdk

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// RelayState is the lifecycle state of one relay.
type RelayState string

const (
	RelayConnecting RelayState = "connecting"
	RelayReady      RelayState = "ready"
	RelayFailed     RelayState = "failed"
)

// RelayFailure classifies why a relay listener stopped.  It is an SDK
// runtime/listener-status concept, not a wire DTO: the listener goroutine
// produces it and the exposure consumer reads it to decide relay-selection
// policy (ban vs suppression/backoff).  Keeping it here avoids leaking that
// policy classification into the types package.
type RelayFailure string

const (
	RelayFailureNone     RelayFailure = ""
	RelayFailureRuntime  RelayFailure = "runtime"
	RelayFailureTerminal RelayFailure = "terminal"
	RelayFailureMITM     RelayFailure = "mitm"
)

// RelayStatus is an immutable snapshot of one relay's externally visible state.
type RelayStatus struct {
	RelayURL  string
	PublicURL string
	UDPAddr   string
	TCPAddr   string
	Version   string
	State     RelayState
	Failure   RelayFailure
	Err       error
	// Deselected marks a best-effort removal notification, never a stored
	// snapshot: the relay left the desired membership set (discovery
	// deselection or a relay-list change) and the endpoint fields carry
	// its last known values, which are no longer backed by an active
	// tunnel listener. Relays() stays authoritative — treat Deselected as
	// a trigger to re-read the snapshot, not as durable history.
	Deselected bool
}

// Active reports whether the relay currently has a usable registered
// listener. A deselection notification never describes an active
// listener: it reports that the relay left the desired membership set,
// so its preserved endpoint fields must not keep it advertised.
func (s RelayStatus) Active() bool {
	if s.Deselected {
		return false
	}
	return s.State != RelayFailed &&
		(s.State == RelayReady || s.PublicURL != "" || s.UDPAddr != "" || s.TCPAddr != "")
}

// Exposure owns the lifecycle of one or more relay listeners and accepts
// traffic from all of them through one net.Listener.
type Exposure struct {
	cancel context.CancelFunc
	done   <-chan struct{}

	identity types.Identity
	options  options
	metadata types.LeaseMetadata
	cache    *cache.Source

	accepted  chan net.Conn
	datagrams chan types.DatagramFrame

	mu             sync.RWMutex
	reconcileMu    sync.Mutex
	relayURLs      []string
	relayListeners map[string]*listener
	blockedRelays  map[string]error
	statuses       map[string]RelayStatus
	stateChanged   chan struct{}
	updates        chan RelayStatus
	updatesMu      sync.Mutex
	acceptLoops    sync.WaitGroup

	// discovery is the relay-selection collaborator. It is nil when
	// discovery is disabled, meaning Exposure owns membership directly.
	// When non-nil, Exposure delegates relay selection to the controller
	// and forwards user intent (AddRelay/RemoveRelay/SetMaxActiveRelays)
	// to it — the controller is the single owner of the explicit relay
	// list and applies each intent atomically.
	discovery *discovery.Controller

	closeOnce sync.Once
	connSeq   atomic.Uint64
}

var _ net.Listener = (*Exposure)(nil)

type options struct {
	Cache      *cache.SourceConfig
	UDPEnabled bool
	TCPEnabled bool
	BanMITM    bool
	Overlay    bool
	Metadata   types.LeaseMetadata

	discoveryEnabled bool
	maxActiveRelays  int
}

// Option configures an optional capability of a relay-backed exposure.
type Option func(*options)

// WithStaticRelayCache opts a static site into relay TLS termination and bounded
// offline serving. A zero TTL accepts the relay's maximum offline lifetime.
// Cache errors never stop the exposure; the caller still serves the same path.
func WithStaticRelayCache(path string, ttl time.Duration) Option {
	return func(opts *options) { opts.Cache = &cache.SourceConfig{Path: path, TTL: ttl} }
}

// WithUDP enables the datagram transport capability.
func WithUDP() Option {
	return func(opts *options) { opts.UDPEnabled = true }
}

// WithTCP enables public raw TCP port allocation.
func WithTCP() Option {
	return func(opts *options) { opts.TCPEnabled = true }
}

// WithMITMProtection controls relay MITM self-probing. The probe requires a
// relay tenant TLS stack that exports keying material; exposures with this
// option enabled fail at start against relays whose stack does not.
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

// WithDiscovery enables discovery-driven relay membership. When enabled,
// Exposure delegates relay selection to an internal discovery.Controller:
// the explicit relays passed to Expose are always retained, and the
// controller may expand membership with auto-selected bootstrap candidates
// after discovery refresh confirms them. maxActiveRelays caps the
// auto-selected listener entries; a value <= 0 keeps the selection default.
// Applications provide only user intent (explicit relays, max active relays,
// transport requirements) and never interact with the controller directly.
func WithDiscovery(maxActiveRelays int) Option {
	return func(opts *options) {
		opts.discoveryEnabled = true
		opts.maxActiveRelays = maxActiveRelays
	}
}

// Expose constructs a relay-backed network endpoint from an already-resolved
// identity and concrete relay URLs. It never creates or persists keys.
//
// When WithDiscovery is applied, Exposure delegates relay selection to an
// internal discovery.Controller. The explicit relays are always retained;
// the controller may expand membership with bootstrap candidates after
// discovery refresh confirms them. Applications do not interact with the
// controller directly — AddRelay, RemoveRelay, and SetMaxActiveRelays route
// intent through it automatically. An empty relay list is allowed only in
// this mode: the resolved explicit-plus-bootstrap membership must still be
// non-empty, and without WithDiscovery at least one explicit relay is
// required.
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
	var source *cache.Source
	if cfg.Cache != nil {
		if cfg.UDPEnabled || cfg.TCPEnabled || cfg.BanMITM {
			return nil, errors.New("relay static cache cannot be combined with UDP, raw TCP, or MITM blocking")
		}
		var err error
		source, err = cache.NewSource(*cfg.Cache)
		if err != nil {
			return nil, err
		}
		log.Warn().Msg("relay cache enabled: selected relays are trusted to store static content and terminate browser TLS; cached responses are not end-to-end encrypted to this client")
	}
	relayURLs, err := utils.NormalizeRelayURLs(relays...)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(identity.Name) == "" {
		return nil, errors.New("portal sdk: identity name is required")
	}
	if strings.TrimSpace(identity.Address) == "" ||
		strings.TrimSpace(identity.PublicKey) == "" ||
		strings.TrimSpace(identity.PrivateKey) == "" {
		return nil, errors.New("portal sdk: identity must include address, public key, and private key")
	}

	// Resolve initial membership and enforce the non-empty invariant.
	// When discovery is enabled, the resolved set (explicit + bootstrap
	// candidates) must be non-empty. The actual initial listeners are the
	// explicit relays only — bootstrap candidates do not become listeners
	// until the discovery loop confirms them, which keeps offline/test
	// usage hermetic. The loop may later expand membership with verified
	// bootstrap candidates.
	var controller *discovery.Controller
	initialRelays := relayURLs
	if cfg.discoveryEnabled {
		resolved, err := discovery.ResolveRelayURLs(relayURLs, true)
		if err != nil {
			return nil, err
		}
		if len(resolved) == 0 {
			return nil, errors.New("portal sdk: at least one initial relay is required")
		}
		bootstraps, err := discovery.BootstrapRelayURLs()
		if err != nil {
			return nil, err
		}
		controller = discovery.NewController(bootstraps)
		controller.SetExplicitRelays(relayURLs)
		controller.SetMaxActiveRelays(cfg.maxActiveRelays)
		controller.SetTransportRequirements(cfg.UDPEnabled, cfg.TCPEnabled)
		controller.SetLocalAddress(identity.Address)
		controller.SetSelectionKey(deriveSelectionKey(identity))
	} else if len(relayURLs) == 0 {
		return nil, errors.New("portal sdk: at least one initial relay is required")
	}

	exposureCtx, cancel := context.WithCancel(ctx)
	exposure := &Exposure{
		cancel:         cancel,
		done:           exposureCtx.Done(),
		identity:       identity.Copy(),
		options:        cfg,
		metadata:       cfg.Metadata.Copy(),
		cache:          source,
		accepted:       make(chan net.Conn, max(len(initialRelays)*defaultReadyTarget*2, 1)),
		datagrams:      make(chan types.DatagramFrame, max(len(initialRelays)*32, 1)),
		relayListeners: make(map[string]*listener, len(initialRelays)),
		blockedRelays:  make(map[string]error),
		statuses:       make(map[string]RelayStatus, len(initialRelays)),
		stateChanged:   make(chan struct{}),
		updates:        make(chan RelayStatus, 1),
		discovery:      controller,
	}

	if exposure.cache != nil {
		go exposure.cache.Run(exposureCtx)
	}

	if err := exposure.setRelays(initialRelays, true); err != nil {
		_ = exposure.Close()
		return nil, err
	}

	if controller != nil {
		go func() {
			for {
				desired, err := controller.Next(exposureCtx)
				if err != nil {
					if !errors.Is(err, context.Canceled) && !exposure.closed() {
						log.Warn().Err(err).Msg("relay discovery loop exited")
					}
					return
				}
				if err := exposure.applyRelays(desired); err != nil {
					if !errors.Is(err, net.ErrClosed) && !exposure.closed() {
						log.Warn().Err(err).Msg("apply discovered relay selection")
					}
					return
				}
			}
		}()
	}

	go func() {
		<-exposure.done
		_ = exposure.Close()
	}()

	return exposure, nil
}

// deriveSelectionKey derives a stable, per-identity secret key for MOLS relay
// ranking from the identity private key, so rankings are unpredictable to
// outside observers without persisting any new value: the private key is
// already the long-lived client secret. The domain separator keeps this key
// distinct from any other derivation from the same secret.
func deriveSelectionKey(identity types.Identity) []byte {
	sum := sha256.Sum256(append([]byte("portal-tunnel/mols-selection-key\x00"), identity.PrivateKey...))
	return sum[:]
}

// applyRelays applies a discovery-selected concrete relay set without
// restarting the exposure. It is unexported so external callers cannot bypass
// discovery policy and overwrite runtime membership directly.
func (e *Exposure) applyRelays(relays []string) error {
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
// When discovery is enabled, it forwards the whole add intent to the
// controller, which applies the explicit-list change and the eligibility
// reset (ban and suppression cleared, so a re-added relay is immediately
// selectable) as one atomic unit; re-selection republishes membership
// through the selection loop.
func (e *Exposure) AddRelay(relayURL string) error {
	relayURL, err := utils.NormalizeRelayURL(relayURL)
	if err != nil {
		return err
	}
	if e.closed() {
		return net.ErrClosed
	}
	if e.discovery != nil {
		e.discovery.AddRelay(relayURL)
		return nil
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
// When discovery is enabled, it forwards the whole remove intent to the
// controller, which applies the explicit-list change and the selection
// deactivation (dropped from active selection, kept as a future candidate)
// as one atomic unit; re-selection republishes membership through the
// selection loop.
func (e *Exposure) RemoveRelay(relayURL string) error {
	relayURL, err := utils.NormalizeRelayURL(relayURL)
	if err != nil {
		return err
	}
	if e.closed() {
		return net.ErrClosed
	}
	if e.discovery != nil {
		e.discovery.RemoveRelay(relayURL)
		return nil
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

// SetMaxActiveRelays caps the number of auto-selected relay listeners.
// When discovery is enabled, it updates the controller, which signals a
// re-selection. When discovery is disabled, it is a no-op (the cap only
// applies to discovery-driven selection).
func (e *Exposure) SetMaxActiveRelays(n int) error {
	if e.closed() {
		return net.ErrClosed
	}
	if e.discovery != nil {
		e.discovery.SetMaxActiveRelays(n)
	}
	return nil
}

func (e *Exposure) UpdateMetadata(metadata types.LeaseMetadata) error {
	if e.closed() {
		return net.ErrClosed
	}

	e.reconcileMu.Lock()
	defer e.reconcileMu.Unlock()
	metadata = metadata.Copy()
	e.metadata = metadata
	e.mu.RLock()
	listeners := make([]*listener, 0, len(e.relayListeners))
	for _, listener := range e.relayListeners {
		listeners = append(listeners, listener)
	}
	e.mu.RUnlock()
	for _, listener := range listeners {
		listener.UpdateMetadata(metadata)
	}
	return nil
}

func (e *Exposure) listenerRelayURLs() []string {
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

// ActiveRelays returns the relay URLs whose RelayStatus.Active() is true,
// derived from the same snapshot as Relays.  Relay-selection callers use it
// for stickiness (keeping a slot for a relay that still holds a lease address).
func (e *Exposure) ActiveRelays() []string {
	if e == nil {
		return nil
	}
	e.mu.RLock()
	relayURLs := make([]string, 0, len(e.statuses))
	for relayURL, status := range e.statuses {
		if status.Active() {
			relayURLs = append(relayURLs, relayURL)
		}
	}
	e.mu.RUnlock()
	slices.Sort(relayURLs)
	return relayURLs
}

func (e *Exposure) setRelayStatus(relayURL string, update listenerStatus) {
	e.applyRelayStatus(relayURL, update, nil)
}

// setListenerRelayStatus applies a status update originating from a
// specific listener, but only while that listener still owns its relay
// slot. A deselected or replaced listener can deliver a final update
// after reconcileRelayListeners dropped it; letting that recreate or
// overwrite the entry would contradict the deselection notification
// derived from the status snapshot (and let an old listener overwrite
// its replacement).
func (e *Exposure) setListenerRelayStatus(relayURL string, owner *listener, update listenerStatus) {
	e.applyRelayStatus(relayURL, update, owner)
}

func (e *Exposure) applyRelayStatus(relayURL string, update listenerStatus, owner *listener) {
	if e == nil || relayURL == "" || e.closed() {
		return
	}

	e.mu.Lock()
	if owner != nil {
		if current, ok := e.relayListeners[relayURL]; !ok || current != owner {
			e.mu.Unlock()
			return
		}
	}
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
	if update.failure != "" {
		status.Failure = update.failure
	} else if update.state != RelayFailed {
		status.Failure = RelayFailureNone
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
	advertised := previous.State != RelayReady && status.State == RelayReady && status.PublicURL != ""
	if !relayStatusEqual(previous, status) {
		e.statuses[relayURL] = status
		e.notifyStateChangedLocked()
	} else {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()

	// Advertise readiness from the authoritative snapshot only: the same
	// committed PublicURL that later feeds the deselection tombstone, so
	// every "service ready at" line is guaranteed retractable by a
	// matching "relay no longer active for" line (issue #463).
	if advertised {
		log.Info().
			Str("address", e.identity.Address).
			Str("public_url", status.PublicURL).
			Str("relay_url", status.RelayURL).
			Msg("service ready at " + status.PublicURL)
	}

	e.publishRelayStatus(status)
	if e.discovery != nil {
		e.discovery.SetActiveRelays(e.ActiveRelays())
	}

	// Feed terminal relay failures directly to the discovery collaborator.
	// This bypasses the Updates channel so slow consumers cannot delay
	// policy reactions. discoveryFailureKind maps the classification
	// explicitly so the two string types never form a hidden cross-package
	// value contract.
	if status.State == RelayFailed && e.discovery != nil {
		e.discovery.Report(status.RelayURL, discoveryFailureKind(status.Failure))
	}
}

// discoveryFailureKind maps an SDK relay failure classification onto the
// discovery failure vocabulary. The mapping is a switch, not a string
// conversion, so neither package's literal values become a cross-package
// contract.
func discoveryFailureKind(failure RelayFailure) discovery.FailureKind {
	switch failure {
	case RelayFailureMITM:
		return discovery.FailureMITM
	case RelayFailureTerminal:
		return discovery.FailureTerminal
	default:
		// RelayFailureRuntime, an unclassified failure, and RelayFailureNone
		// on a Failed status all mean "listener stopped, relay suspect":
		// suppression/backoff, not a permanent ban.
		return discovery.FailureRuntime
	}
}

func (e *Exposure) publishRelayStatus(status RelayStatus) {
	e.updatesMu.Lock()
	defer e.updatesMu.Unlock()
	select {
	case <-e.done:
		return
	default:
	}
	select {
	case e.updates <- status:
		return
	default:
	}
	select {
	case <-e.updates:
	default:
	}
	select {
	case <-e.done:
	case e.updates <- status:
	default:
	}
}

func relayStatusEqual(a, b RelayStatus) bool {
	errorsEqual := a.Err == nil && b.Err == nil
	if a.Err != nil && b.Err != nil {
		errorsEqual = a.Err.Error() == b.Err.Error()
	}
	return a.RelayURL == b.RelayURL &&
		a.PublicURL == b.PublicURL &&
		a.UDPAddr == b.UDPAddr &&
		a.TCPAddr == b.TCPAddr &&
		a.Version == b.Version &&
		a.State == b.State &&
		a.Failure == b.Failure &&
		a.Deselected == b.Deselected &&
		errorsEqual
}

func (e *Exposure) notifyStateChangedLocked() {
	if e.stateChanged != nil {
		close(e.stateChanged)
	}
	e.stateChanged = make(chan struct{})
}

// syncRelayStatuses reconciles the stored status snapshot with the
// desired relay set and returns the deselection notifications for relays
// that left it. Callers report them once the stale listeners are
// actually detached (see reportDeselectedRelays), so the lifecycle
// signal lines up with the listener lifecycle.
func (e *Exposure) syncRelayStatuses(relayURLs []string) []RelayStatus {
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
			status.Failure = current.Failure
			status.Err = current.Err
			if relayStatusEqual(current, status) {
				continue
			}
		}
		e.statuses[relayURL] = status
		changed = true
	}
	var deselected []RelayStatus
	for relayURL, previous := range e.statuses {
		if _, ok := desired[relayURL]; ok {
			continue
		}
		delete(e.statuses, relayURL)
		changed = true
		previous.Deselected = true
		deselected = append(deselected, previous)
	}
	if changed {
		e.notifyStateChangedLocked()
	}
	e.mu.Unlock()
	if changed && e.discovery != nil {
		e.discovery.SetActiveRelays(e.ActiveRelays())
	}
	return deselected
}

// reportDeselectedRelays publishes the membership-shrink notifications
// collected by syncRelayStatuses once the stale listeners are detached:
// a structured log mirroring "service ready at" so log consumers can
// stop advertising the URL, and a best-effort Updates() notification.
// Relays() remains the authoritative snapshot.
func (e *Exposure) reportDeselectedRelays(deselected []RelayStatus) {
	for _, status := range deselected {
		if status.PublicURL != "" {
			log.Info().
				Str("relay_url", status.RelayURL).
				Str("public_url", status.PublicURL).
				Str("reason", "deselected").
				Msg("relay no longer active for " + status.PublicURL)
		}
		e.publishRelayStatus(status)
	}
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
// snapshot; slow consumers may miss intermediate updates. When relay
// membership shrinks — discovery deselection or a relay-list change — a
// removal notification with Deselected set and the relay's last known
// endpoint is delivered best-effort; use it as a trigger to re-read
// Relays(), not as durable history.
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
	return e.waitReady(ctx, func(status RelayStatus) bool {
		return status.State == RelayReady
	})
}

func (e *Exposure) waitReady(ctx context.Context, matches func(RelayStatus) bool) ([]RelayStatus, error) {
	if ctx == nil {
		return nil, errors.New("portal sdk: context is nil")
	}
	for {
		ready, changed := e.readyRelays(matches)
		if len(ready) > 0 {
			return ready, nil
		}
		if e.closed() {
			return nil, net.ErrClosed
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
	select {
	case frame := <-e.datagrams:
		return frame, nil
	default:
	}
	select {
	case <-e.done:
		return types.DatagramFrame{}, net.ErrClosed
	case frame := <-e.datagrams:
		return frame, nil
	}
}

func (e *Exposure) SendDatagram(frame types.DatagramFrame) error {
	if !e.options.UDPEnabled {
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

// WaitDatagramReady waits until at least one relay has an authenticated UDP
// backhaul and returns the ready relay snapshots.
func (e *Exposure) WaitDatagramReady(ctx context.Context) ([]RelayStatus, error) {
	if !e.options.UDPEnabled {
		return nil, errors.New("exposure does not have udp enabled")
	}
	return e.waitReady(ctx, func(status RelayStatus) bool {
		return status.State != RelayFailed && status.UDPAddr != ""
	})
}

// WaitTCPReady waits until at least one relay has allocated a public TCP
// address and returns the ready relay snapshots.
func (e *Exposure) WaitTCPReady(ctx context.Context) ([]RelayStatus, error) {
	if !e.options.TCPEnabled {
		return nil, errors.New("exposure does not have tcp enabled")
	}
	return e.waitReady(ctx, func(status RelayStatus) bool {
		return status.State != RelayFailed && status.TCPAddr != ""
	})
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
		if e.cache != nil {
			e.cache.Wait()
		}
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
	// Detach stale listeners before deleting their membership statuses:
	// once a listener no longer owns its relay slot, listener-originated
	// status updates are dropped by the ownership guard in
	// applyRelayStatus, and updates racing ahead of the detach are
	// re-deleted by the sync below. Either way a stale status cannot
	// recreate a deselected entry after its tombstone is published.
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
		if _, wanted := desired[relayURL]; !wanted {
			continue
		}
		if _, exists := e.relayListeners[relayURL]; exists {
			continue
		}
		missingRelayURLs = append(missingRelayURLs, relayURL)
	}
	if stateChanged {
		e.notifyStateChangedLocked()
	}
	e.mu.Unlock()
	deselected := e.syncRelayStatuses(relayURLs)

	addedRelayURLs := make([]string, 0, len(missingRelayURLs))
	for relayURL, listener := range staleListeners {
		if listener == nil {
			continue
		}
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Warn().Err(err).Str("relay_url", relayURL).Msg("close stale relay listener")
		}
	}

	// Report deselection only now that the stale listeners are actually
	// detached, so the lifecycle signal matches the listener lifecycle.
	e.reportDeselectedRelays(deselected)
	for _, relayURL := range missingRelayURLs {
		e.setRelayStatus(relayURL, listenerStatus{state: RelayConnecting})
		listener, err := newListener(context.Background(), relayURL, listenerConfig{
			Cache:      e.cache,
			Identity:   e.identity.Copy(),
			Overlay:    e.options.Overlay,
			UDPEnabled: e.options.UDPEnabled,
			TCPEnabled: e.options.TCPEnabled,
			BanMITM:    e.options.BanMITM,
			Metadata:   e.metadata.Copy(),
		})
		if err != nil {
			e.setRelayStatus(relayURL, listenerStatus{state: RelayFailed, err: err})
			if failOnError {
				return fmt.Errorf("listen %q: %w", relayURL, err)
			}
			log.Warn().Err(err).Str("relay_url", relayURL).Msg("add relay listener")
			continue
		}

		if !e.publishCreatedListener(relayURL, listener) {
			continue
		}
		addedRelayURLs = append(addedRelayURLs, relayURL)
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

// publishCreatedListener installs a freshly created listener for relayURL,
// rechecking under e.mu the conditions that may have changed while the
// listener was being created: a relay MITM-blocked in that window is closed
// and recorded as a MITM failure instead of being published — a blocked
// relay must never receive traffic. It reports whether the listener was
// installed.
func (e *Exposure) publishCreatedListener(relayURL string, listener *listener) bool {
	e.mu.Lock()
	if blockErr, blocked := e.blockedRelays[relayURL]; blocked {
		e.mu.Unlock()
		_ = listener.Close()
		e.setRelayStatus(relayURL, listenerStatus{state: RelayFailed, failure: RelayFailureMITM, err: blockErr})
		return false
	}
	if _, exists := e.relayListeners[relayURL]; exists {
		e.mu.Unlock()
		_ = listener.Close()
		return false
	}
	select {
	case <-e.done:
		e.mu.Unlock()
		_ = listener.Close()
		return false
	default:
	}
	e.relayListeners[relayURL] = listener
	e.acceptLoops.Add(1)
	e.mu.Unlock()

	go func() {
		defer e.acceptLoops.Done()
		e.runListenerAcceptLoop(listener)
	}()
	return true
}

func (e *Exposure) runListenerAcceptLoop(listener *listener) {
	if listener == nil {
		return
	}

	relayURL := listener.api.relayURL.String()
	var workers sync.WaitGroup
	defer workers.Wait()
	statusUpdates := listener.statusUpdates
	if statusUpdates != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case status := <-statusUpdates:
					e.setListenerRelayStatus(relayURL, listener, status)
				case <-listener.doneCh:
					return
				}
			}
		}()
	}
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
