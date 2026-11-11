package sdk

import (
	"context"
	"errors"
	"net"
	"runtime"
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

var (
	errPortalSDKOptionIsNil                = errors.New("portal sdk: option is nil")
	errPortalSDKContextIsNil               = errors.New("portal sdk: context is nil")
	errPortalSDKThisRuntimeSupportsHTTPS   = errors.New("portal sdk: this runtime supports HTTPS exposure only")
	errRelayStaticCacheCannotCombinedUDP   = errors.New("relay static cache cannot be combined with UDP, raw TCP, or MITM blocking")
	errPortalSDKIdentityMustIncludeAddress = errors.New("portal sdk: identity must include address, public key, and private key")
	errPortalSDKLeastOneInitialRelay       = errors.New("portal sdk: at least one initial relay is required")
	errExposureDoesNotHaveUDPEnabled       = errors.New("exposure does not have udp enabled")
	errExposureDoesNotHaveTCPEnabled       = errors.New("exposure does not have tcp enabled")
)

// RelayState is the lifecycle state of one relay.
type RelayState string

const (
	RelayConnecting RelayState = "connecting"
	RelayReady      RelayState = "ready"
	RelayFailed     RelayState = "failed"
)

// RelayApproval reports that a relay refused this lease's reverse connection.
type RelayApproval string

const (
	// RelayApprovalPending means the relay has not approved the lease. An old
	// relay reports a denied lease this way too.
	RelayApprovalPending RelayApproval = "pending"
	// RelayApprovalRefused means the relay denied or banned the lease:
	// lease_denied on the wire, types.LeaseDenied in the relay.
	RelayApprovalRefused RelayApproval = "refused"
)

// Message is the wording to show people for this state.
func (a RelayApproval) Message() string {
	switch a {
	case RelayApprovalPending:
		return "waiting for relay approval"
	case RelayApprovalRefused:
		return "refused by relay"
	default:
		return ""
	}
}

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
	RelayURL string
	// PublicURL is the identity-bound canonical URL. It always routes to
	// this exposure, and the opt-in relay cache serves only this hostname.
	PublicURL string
	// AliasURL is the <name>.<root host> URL when the relay granted that
	// alias to this lease, else empty: another identity may own the name
	// (canonical fallback). A set alias is held by the lease: it stays set
	// while the lease is held (also RelayConnecting while reverse sessions
	// reconnect), is cleared on RelayFailed, and always reaches the live
	// origin. The RelayReady rule is for display only: show the alias only
	// while State is RelayReady.
	AliasURL string
	// AliasSince is when this exposure came to hold AliasURL, zero without one.
	// Another identity may have held the name before that.
	AliasSince time.Time
	UDPAddr    string
	TCPAddr    string
	Version    string
	State      RelayState
	Failure    RelayFailure
	Err        error
	// Approval is set while the relay refuses this lease's reverse connection.
	// State stays RelayConnecting and no endpoint field is set, because nothing
	// routes. Empty means no refusal was reported, and it never means approved:
	// an old relay reports no revoke, and the browser SDK cannot read a refusal.
	Approval RelayApproval
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

	startedAt time.Time
	identity  types.Identity
	options   options
	metadata  types.LeaseMetadata
	cache     *cache.Source

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
	cfg, err := applyExposeOptions(opts)
	if err != nil {
		return nil, err
	}
	if err := validateExposeContext(ctx); err != nil {
		return nil, err
	}
	if err := validateExposeConfig(cfg); err != nil {
		return nil, err
	}
	source, err := newRelayCache(cfg)
	if err != nil {
		return nil, err
	}
	relayURLs, err := utils.NormalizeRelayURLs(relays...)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(identity.Address) == "" ||
		strings.TrimSpace(identity.PublicKey) == "" ||
		strings.TrimSpace(identity.PrivateKey) == "" {
		return nil, errPortalSDKIdentityMustIncludeAddress
	}
	initialRelays, controller, err := resolveExposeMembership(relayURLs, cfg, identity)
	if err != nil {
		return nil, err
	}
	exposureCtx, cancel := context.WithCancel(ctx)
	exposure := &Exposure{
		cancel:         cancel,
		done:           exposureCtx.Done(),
		startedAt:      time.Now().UTC(),
		identity:       identity,
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
	return exposure.startExposeRunners(exposureCtx, initialRelays)
}

func validateExposeContext(ctx context.Context) error {
	if ctx == nil {
		return errPortalSDKContextIsNil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func validateExposeConfig(cfg options) error {
	if err := cfg.Metadata.Validate(); err != nil {
		return err
	}
	requiresSocketTransport := cfg.Overlay || cfg.UDPEnabled || cfg.TCPEnabled || cfg.BanMITM
	if runtime.GOOS == "js" && requiresSocketTransport {
		return errPortalSDKThisRuntimeSupportsHTTPS
	}
	return nil
}

func (e *Exposure) startExposeRunners(exposureCtx context.Context, initialRelays []string) (*Exposure, error) {
	if e.cache != nil {
		go e.cache.Run(exposureCtx)
	}
	if err := e.setRelays(initialRelays, true); err != nil {
		_ = e.Close()
		return nil, err
	}
	if e.discovery != nil {
		go e.runDiscoveryLoop(exposureCtx)
	}
	go func() {
		<-e.done
		_ = e.Close()
	}()
	return e, nil
}

func applyExposeOptions(opts []Option) (options, error) {
	var cfg options
	for _, option := range opts {
		if option == nil {
			return options{}, errPortalSDKOptionIsNil
		}
		option(&cfg)
	}
	return cfg, nil
}

func newRelayCache(cfg options) (*cache.Source, error) {
	if cfg.Cache == nil {
		return nil, nil
	}
	if cfg.UDPEnabled || cfg.TCPEnabled || cfg.BanMITM {
		return nil, errRelayStaticCacheCannotCombinedUDP
	}
	source, err := cache.NewSource(*cfg.Cache)
	if err != nil {
		return nil, err
	}
	log.Warn().Msg("relay cache enabled: selected relays are trusted to store static content and terminate browser TLS; cached responses are not end-to-end encrypted to this client")
	return source, nil
}

func (e *Exposure) runDiscoveryLoop(exposureCtx context.Context) {
	controller := e.discovery
	for {
		desired, err := controller.Next(exposureCtx)
		if err != nil {
			if !errors.Is(err, context.Canceled) && !e.closed() {
				log.Warn().Err(err).Msg("relay discovery loop exited")
			}
			return
		}
		if err := e.applyRelays(desired); err != nil {
			if !errors.Is(err, net.ErrClosed) && !e.closed() {
				log.Warn().Err(err).Msg("apply discovered relay selection")
			}
			return
		}
	}
}

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
	if err := metadata.Validate(); err != nil {
		return err
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
