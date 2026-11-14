package sdk

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/portal/certmonitor"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/localtls"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errAutomaticTLSStateRequired           = errors.New("automatic TLS requires a certificate state directory")
	errAutomaticTLSFilesConflict           = errors.New("automatic TLS cannot be combined with manual certificate files")
	errLocalTLSCertificatePairRequired     = errors.New("tenant TLS requires both certificate and key files")
	errLocalTLSModeUnsupported             = errors.New("local tenant TLS cannot be combined with raw TCP or the browser runtime")
	errCertificateMonitorModeUnsupported   = errors.New("TLS certificate monitoring cannot be combined with raw TCP or the browser runtime")
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
	// PublicURL is the identity-bound canonical URL. With negotiated Local TLS,
	// it stays empty until a valid local certificate exists and is never cached
	// by the relay. Old relays and non-Local-TLS exposures retain their legacy URL.
	PublicURL string
	// LegacyURL preserves the old one-label canonical origin and its optional
	// relay cache. It is not a redirect to PublicURL.
	LegacyURL string
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
	// CertificateError describes an automatic issuance policy refusal. A live
	// legacy endpoint or an already valid local certificate can still work.
	CertificateError error
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

	closeOnce    sync.Once
	connSeq      atomic.Uint64
	http2Enabled bool
}

var _ net.Listener = (*Exposure)(nil)

type options struct {
	CertificateMonitor *certmonitor.MonitorConfig
	AutomaticTLS       bool
	TLSStateDir        string
	TLSRequireLocal    bool
	TLSCertFile        string
	TLSKeyFile         string
	Cache              *cache.SourceConfig
	UDPEnabled         bool
	TCPEnabled         bool
	BanMITM            bool
	Overlay            bool
	Metadata           types.LeaseMetadata

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

// WithTLSCertificate requires a locally held tenant certificate and private key.
// Expose validates the pair before registering. Its only DNS SAN must be the
// exact new canonical hostname. Friendly and legacy URLs remain Keyless.
// Files are reloaded during certificate refresh; errors never enable relay signing.
// This option requires a namespace-capable relay and cannot be used with raw TCP.
func WithTLSCertificate(certFile, keyFile string) Option {
	return func(opts *options) {
		opts.TLSCertFile = certFile
		opts.TLSKeyFile = keyFile
	}
}

// WithAutomaticTLS obtains and renews tenant certificates through the relay.
// The tunnel generates and persists private keys in directory. New canonical
// hostnames never fall back to Keyless. requireLocal additionally rejects old
// relays without namespace support and waits for canonical readiness; false
// allows a live legacy endpoint to satisfy WaitReady while issuance is pending.
// This is local-key ownership, not independent authentication of the relay.
func WithAutomaticTLS(directory string, requireLocal bool) Option {
	return func(opts *options) {
		opts.AutomaticTLS = true
		opts.TLSStateDir = directory
		opts.TLSRequireLocal = requireLocal
	}
}

// WithCertificateMonitoring opts into best-effort, evaluation-only CAA and certificate
// transparency checks for each canonical tenant hostname. stateDir is required
// for durable evidence. baselineFile is operator-managed; an empty path leaves
// CAA policy unconfigured. dnsResolver is an optional IP:port (default 1.1.1.1:53).
// Enabling this sends hostname queries to that resolver and CertSpotter over
// HTTPS. Runtime findings and query failures only warn; they do not change
// certificates, relay selection, or traffic readiness. Invalid initial monitor
// configuration may reject startup. Detection before an attack is not guaranteed.
// Raw TCP and the browser runtime are unsupported.
func WithCertificateMonitoring(stateDir, baselineFile, dnsResolver string) Option {
	return func(opts *options) {
		opts.CertificateMonitor = &certmonitor.MonitorConfig{
			StateDir: stateDir, BaselineFile: baselineFile, DNSResolver: dnsResolver,
		}
	}
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
// identity and concrete relay URLs. It never creates or persists identity keys.
// WithAutomaticTLS persists tenant TLS keys separately in its configured directory.
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
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return errLocalTLSCertificatePairRequired
	}
	if cfg.AutomaticTLS {
		if strings.TrimSpace(cfg.TLSStateDir) == "" {
			return errAutomaticTLSStateRequired
		}
		if cfg.TLSCertFile != "" {
			return errAutomaticTLSFilesConflict
		}
	}
	localTLSConfigured := cfg.TLSCertFile != "" || cfg.AutomaticTLS
	localTLSUnsupported := cfg.TCPEnabled || runtime.GOOS == "js"
	if localTLSConfigured && localTLSUnsupported {
		return errLocalTLSModeUnsupported
	}
	if cfg.TLSCertFile != "" {
		if err := localtls.ValidateCertificateFiles(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
			return fmt.Errorf("tenant TLS: %w", err)
		}
	}
	if cfg.CertificateMonitor != nil {
		if localTLSUnsupported {
			return errCertificateMonitorModeUnsupported
		}
		if err := cfg.CertificateMonitor.Validate(); err != nil {
			return err
		}
	}
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

func resolveExposeMembership(relayURLs []string, cfg options, identity types.Identity) ([]string, *discovery.Controller, error) {
	if !cfg.discoveryEnabled {
		if len(relayURLs) == 0 {
			return nil, nil, errPortalSDKLeastOneInitialRelay
		}
		return relayURLs, nil, nil
	}
	resolved, err := discovery.ResolveRelayURLs(relayURLs, true)
	if err != nil {
		return nil, nil, err
	}
	if len(resolved) == 0 {
		return nil, nil, errPortalSDKLeastOneInitialRelay
	}
	bootstraps, err := discovery.BootstrapRelayURLs()
	if err != nil {
		return nil, nil, err
	}
	controller := discovery.NewController(bootstraps)
	controller.SetExplicitRelays(relayURLs)
	controller.SetMaxActiveRelays(cfg.maxActiveRelays)
	controller.SetTransportRequirements(cfg.UDPEnabled, cfg.TCPEnabled)
	controller.SetLocalAddress(identity.Address)
	controller.SetSelectionKey(deriveSelectionKey(identity))
	return relayURLs, controller, nil
}

func deriveSelectionKey(identity types.Identity) []byte {
	sum := sha256.Sum256(append([]byte("portal-tunnel/mols-selection-key\x00"), identity.PrivateKey...))
	return sum[:]
}

type exposureConn struct {
	net.Conn
	id         uint64
	localAddr  string
	remoteAddr string
	closeOnce  sync.Once
}

func (c *exposureConn) ConnectionState() tls.ConnectionState {
	if conn, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return conn.ConnectionState()
	}
	return tls.ConnectionState{}
}

func (c *exposureConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
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
	desired := e.unblockedRelaySet(relayURLs)

	e.mu.Lock()
	staleListeners, missingRelayURLs := e.detachStaleRelayListenersLocked(relayURLs, desired)
	e.mu.Unlock()
	deselected := e.syncRelayStatuses(relayURLs)

	e.closeStaleRelayListenersLocked(staleListeners)
	e.reportDeselectedRelays(deselected)
	addedRelayURLs, err := e.publishMissingRelayListeners(missingRelayURLs, failOnError)
	if err != nil {
		return err
	}
	logReconciledRelays(relayURLs, staleListeners, addedRelayURLs)
	return nil
}

func (e *Exposure) detachStaleRelayListenersLocked(relayURLs []string, desired map[string]struct{}) (map[string]*listener, []string) {
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
	return staleListeners, missingRelayURLs
}

func (e *Exposure) publishMissingRelayListeners(missingRelayURLs []string, failOnError bool) ([]string, error) {
	addedRelayURLs := make([]string, 0, len(missingRelayURLs))
	for _, relayURL := range missingRelayURLs {
		e.applyRelayStatus(relayURL, listenerStatus{state: RelayConnecting}, nil)
		published, err := e.publishRelayListenerLocked(relayURL)
		if err != nil {
			e.applyRelayStatus(relayURL, listenerStatus{state: RelayFailed, err: err}, nil)
			if failOnError {
				return nil, fmt.Errorf("add relay listener %q: %w", relayURL, err)
			}
			log.Warn().Err(err).Str("relay_url", relayURL).Msg("add relay listener")
			continue
		}
		if published {
			addedRelayURLs = append(addedRelayURLs, relayURL)
		}
	}
	return addedRelayURLs, nil
}

func (e *Exposure) unblockedRelaySet(relayURLs []string) map[string]struct{} {
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
	return desired
}

func (e *Exposure) closeStaleRelayListenersLocked(staleListeners map[string]*listener) {
	for relayURL, listener := range staleListeners {
		if listener == nil {
			continue
		}
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Warn().Err(err).Str("relay_url", relayURL).Msg("close stale relay listener")
		}
	}
}

func (e *Exposure) publishRelayListenerLocked(relayURL string) (bool, error) {
	listener, err := newListener(context.Background(), relayURL, listenerConfig{
		TLSCertFile:        e.options.TLSCertFile,
		TLSKeyFile:         e.options.TLSKeyFile,
		TLSStateDir:        e.options.TLSStateDir,
		TLSRequireLocal:    e.options.TLSRequireLocal,
		CertificateMonitor: e.options.CertificateMonitor,
		Cache:              e.cache,
		Identity:           e.identity,
		Overlay:            e.options.Overlay,
		UDPEnabled:         e.options.UDPEnabled,
		TCPEnabled:         e.options.TCPEnabled,
		BanMITM:            e.options.BanMITM,
		Metadata:           e.metadata.Copy(),
		StartedAt:          e.startedAt,
	})
	if err != nil {
		return false, err
	}
	if e.http2Enabled {
		listener.enableHTTP2()
	}
	return e.publishCreatedListener(relayURL, listener), nil
}

func logReconciledRelays(relayURLs []string, staleListeners map[string]*listener, addedRelayURLs []string) {
	if len(staleListeners) == 0 && len(addedRelayURLs) == 0 {
		return
	}
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

func (e *Exposure) publishCreatedListener(relayURL string, listener *listener) bool {
	e.mu.Lock()
	if blockErr, blocked := e.blockedRelays[relayURL]; blocked {
		e.mu.Unlock()
		_ = listener.Close()
		e.applyRelayStatus(relayURL, listenerStatus{state: RelayFailed, failure: RelayFailureMITM, err: blockErr}, nil)
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
	workers := e.runListenerAcceptLoopSpawnWorkers(listener, relayURL)
	defer func() {

		workers.Wait()
		e.mu.Lock()
		if current, ok := e.relayListeners[relayURL]; ok && current == listener {
			delete(e.relayListeners, relayURL)
		}
		e.mu.Unlock()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			e.reportAcceptLoopError(listener, relayURL, err)
			return
		}

		if e.deliverAcceptedConn(conn) {
			return
		}
	}
}

func (e *Exposure) runListenerAcceptLoopSpawnWorkers(listener *listener, relayURL string) *sync.WaitGroup {
	workers := &sync.WaitGroup{}
	if statusUpdates := listener.statusUpdates; statusUpdates != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			e.forwardListenerStatuses(listener, relayURL, statusUpdates)
		}()
	}
	if listener.udpEnabled {
		workers.Add(1)
		go func() {
			defer workers.Done()
			e.pumpListenerDatagrams(listener, relayURL)
		}()
	}
	return workers
}

func (e *Exposure) reportAcceptLoopError(listener *listener, relayURL string, err error) {
	select {
	case <-listener.doneCh:
		return
	default:
	}
	if errors.Is(err, net.ErrClosed) {
		return
	}
	log.Warn().Err(err).Str("relay_url", relayURL).Msg("exposure listener accept failed")
}

func (e *Exposure) deliverAcceptedConn(conn net.Conn) bool {
	select {
	case <-e.done:
		_ = conn.Close()
		return true
	case e.accepted <- conn:
		return false
	}
}

func (e *Exposure) forwardListenerStatuses(listener *listener, relayURL string, statusUpdates <-chan listenerStatus) {
	for {
		select {
		case status := <-statusUpdates:
			e.applyRelayStatus(relayURL, status, listener)
		case <-listener.doneCh:
			return
		}
	}
}

func (e *Exposure) pumpListenerDatagrams(listener *listener, relayURL string) {
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
		case <-listener.doneCh:
			return
		case e.datagrams <- frame:
		}
	}
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
	slices.SortFunc(relays, compareRelayStatusRelays)
	return relays
}

func compareRelayStatusRelays(a, b RelayStatus) int {
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
		// Listener reports can wait behind other producers. Resolve canonical
		// availability here, where updates are serialized, rather than trusting
		// material that was usable when a report was constructed.
		lease, registered := owner.leaseSnapshot()
		endpoint, local := lease.tenantTLS.(*namespaceTLS)
		if registered && local {
			update.publicURL = ""
			if update.state == RelayReady && endpoint.local.Ready() {
				update.publicURL = owner.leaseURL(lease.hostname)
			}
			update.certificateErr = endpoint.local.IssuanceError()
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
	e.trackBlockedRelayLocked(relayURL, update.err)
	status = mergeRelayStatusFieldsLocked(previous, update, relayURL)
	if !relayStatusEqual(previous, status) {
		e.statuses[relayURL] = status
		e.notifyStateChangedLocked()
	} else {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()

	e.announceRelayStatusChange(previous, status)
}

func (e *Exposure) trackBlockedRelayLocked(relayURL string, err error) {
	if err == nil || !errors.Is(err, errMITMDetected) {
		return
	}
	if e.blockedRelays == nil {
		e.blockedRelays = make(map[string]error)
	}
	e.blockedRelays[relayURL] = err
}

func mergeRelayStatusFieldsLocked(previous RelayStatus, update listenerStatus, relayURL string) RelayStatus {
	status := mergeRelayScalarFieldsLocked(previous, update, relayURL)
	status = applyRelayEndpointsLocked(status, update)
	switch {
	case status.AliasURL == "":
		status.AliasSince = time.Time{}
	case status.AliasURL != previous.AliasURL:
		status.AliasSince = time.Now()
	}
	return status
}

func mergeRelayScalarFieldsLocked(previous RelayStatus, update listenerStatus, relayURL string) RelayStatus {
	status := previous
	status.RelayURL = relayURL
	if update.state != "" {
		status.State = update.state
	}
	if update.failure != "" {
		status.Failure = update.failure
	} else if update.state != RelayFailed {
		status.Failure = RelayFailureNone
	}
	status.Approval = update.approval
	status.CertificateError = update.certificateErr
	if update.version != "" {
		status.Version = update.version
	}
	if update.err != nil {
		status.Err = update.err
	} else if update.state != RelayFailed {
		status.Err = nil
	}
	return status
}

func applyRelayEndpointsLocked(status RelayStatus, update listenerStatus) RelayStatus {
	if update.state == RelayFailed {
		status.AliasURL = ""
		status.LegacyURL = ""
	}
	if update.state == RelayConnecting {
		status.PublicURL = ""
		status.LegacyURL = ""
		status.AliasURL = ""
		status.UDPAddr = ""
		status.TCPAddr = ""
	}
	if update.publicURL != "" || update.legacyURL != "" || update.aliasURL != "" || update.state == RelayReady {
		status.PublicURL = update.publicURL
		status.LegacyURL = update.legacyURL
		status.AliasURL = update.aliasURL
	}
	if update.udpAddr != "" || update.state == RelayConnecting || update.state == RelayReady {
		status.UDPAddr = update.udpAddr
	}
	if update.tcpAddr != "" || update.state == RelayConnecting || update.state == RelayReady {
		status.TCPAddr = update.tcpAddr
	}
	return status
}

func (e *Exposure) announceRelayStatusChange(previous, status RelayStatus) {
	publicURL := cmp.Or(status.PublicURL, status.LegacyURL)
	advertised := (previous.State != RelayReady || previous.PublicURL != status.PublicURL) && status.State == RelayReady && publicURL != ""
	if advertised {
		message := "service ready at " + publicURL
		if status.AliasURL != "" {
			message += " (short URL: " + status.AliasURL + ")"
		}
		relayStatusLogEvent(log.Info(), status).
			Str("address", e.identity.Address).
			Msg(message)
	} else if previous.State == RelayReady && status.State == RelayConnecting {
		relayStatusLogEvent(log.Info(), status).
			Str("address", e.identity.Address).
			Msg("relay reconnecting")
	} else if status.State == RelayFailed {
		relayStatusLogEvent(log.Warn(), status).
			Str("address", e.identity.Address).
			Msg("relay failed")
	}
	if status.Approval != "" && status.Approval != previous.Approval {
		relayStatusLogEvent(log.Warn(), status).
			Str("address", e.identity.Address).
			Msg(status.Approval.Message())
	}

	e.publishRelayStatus(status)
	if e.discovery != nil {
		e.discovery.SetActiveRelays(e.ActiveRelays())
	}

	if status.State == RelayFailed && e.discovery != nil {
		e.discovery.Report(status.RelayURL, discoveryFailureKind(status.Failure))
	}
}

func discoveryFailureKind(failure RelayFailure) discovery.FailureKind {
	switch failure {
	case RelayFailureMITM:
		return discovery.FailureMITM
	case RelayFailureTerminal:
		return discovery.FailureTerminal
	default:

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
	certErrorsEqual := a.CertificateError == nil && b.CertificateError == nil
	if a.CertificateError != nil && b.CertificateError != nil {
		certErrorsEqual = a.CertificateError.Error() == b.CertificateError.Error()
	}
	return certErrorsEqual && a.RelayURL == b.RelayURL &&
		a.PublicURL == b.PublicURL &&
		a.LegacyURL == b.LegacyURL &&
		a.AliasURL == b.AliasURL &&
		a.UDPAddr == b.UDPAddr &&
		a.TCPAddr == b.TCPAddr &&
		a.Version == b.Version &&
		a.State == b.State &&
		a.Failure == b.Failure &&
		a.Approval == b.Approval &&
		a.Deselected == b.Deselected &&
		errorsEqual
}

func (e *Exposure) notifyStateChangedLocked() {
	if e.stateChanged != nil {
		close(e.stateChanged)
	}
	e.stateChanged = make(chan struct{})
}

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
		if _, ok := e.statuses[relayURL]; ok {
			continue
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

func (e *Exposure) reportDeselectedRelays(deselected []RelayStatus) {
	for _, status := range deselected {
		if status.PublicURL != "" {
			relayStatusLogEvent(log.Info(), status).
				Msg("relay no longer active for " + status.PublicURL)
		}
		e.publishRelayStatus(status)
	}
}

func relayStatusLogEvent(event *zerolog.Event, status RelayStatus) *zerolog.Event {
	event = event.
		Str("event", "relay_status").
		Str("relay_url", status.RelayURL).
		Str("state", string(status.State)).
		Str("public_url", status.PublicURL).
		Str("legacy_url", status.LegacyURL).
		Bool("deselected", status.Deselected)
	if status.State == RelayReady && !status.Deselected && status.AliasURL != "" {
		event = event.Str("alias_url", status.AliasURL)
	}
	if status.State == RelayFailed {
		event = event.Str("failure", string(status.Failure))
	}
	if status.Approval != "" {
		event = event.Str("approval", string(status.Approval))
	}
	return event
}

func (e *Exposure) readyRelays(matches func(RelayStatus) bool, requireLocal bool) ([]RelayStatus, <-chan struct{}, error) {
	e.mu.RLock()
	ready := make([]RelayStatus, 0, len(e.statuses))
	allTerminal := len(e.statuses) > 0
	var terminalErr error
	for _, status := range e.statuses {
		if matches(status) {
			ready = append(ready, status)
		}
		if status.State == RelayFailed && status.Failure == RelayFailureTerminal && status.Err != nil {
			terminalErr = errors.Join(terminalErr, fmt.Errorf("relay %s: %w", status.RelayURL, status.Err))
		} else if requireLocal && status.PublicURL == "" && status.CertificateError != nil {
			terminalErr = errors.Join(terminalErr, fmt.Errorf("relay %s: %w", status.RelayURL, status.CertificateError))
		} else {
			allTerminal = false
		}
	}
	changed := e.stateChanged
	e.mu.RUnlock()
	slices.SortFunc(ready, func(a, b RelayStatus) int {
		return strings.Compare(a.RelayURL, b.RelayURL)
	})
	if !allTerminal {
		terminalErr = nil
	}
	return ready, changed, terminalErr
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
// With require-local, it waits for a usable canonical Local TLS URL and
// returns errors if all current relays failed or refuse automatic issuance. The
// exposure stays open, and callers may add relays or continue discovery.
func (e *Exposure) WaitReady(ctx context.Context) ([]RelayStatus, error) {
	if e == nil {
		return nil, net.ErrClosed
	}
	requireLocal := e.options.TLSRequireLocal
	return e.waitReady(ctx, func(status RelayStatus) bool {
		return status.State == RelayReady && (!requireLocal || status.PublicURL != "")
	}, requireLocal)
}

func (e *Exposure) waitReady(ctx context.Context, matches func(RelayStatus) bool, requireLocal bool) ([]RelayStatus, error) {
	if ctx == nil {
		return nil, errPortalSDKContextIsNil
	}
	for {
		ready, changed, terminalErr := e.readyRelays(matches, requireLocal)
		if len(ready) > 0 {
			return ready, nil
		}
		if e.closed() {
			return nil, net.ErrClosed
		}
		if terminalErr != nil {
			return nil, terminalErr
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
		case <-e.done:
			return types.DatagramFrame{}, net.ErrClosed
		case frame := <-e.datagrams:
			select {
			case <-frame.LeaseDone:
				continue
			default:
			}
			return frame, nil
		}
	}
}

// SendDatagram replies on the lease that delivered frame. Preserve the accepted
// frame's LeaseDone metadata when constructing a reply.
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
		return nil, errExposureDoesNotHaveUDPEnabled
	}
	return e.waitReady(ctx, func(status RelayStatus) bool {
		return status.State != RelayFailed && status.UDPAddr != ""
	}, false)
}

// WaitTCPReady waits until at least one relay has allocated a public TCP
// address and returns the ready relay snapshots.
func (e *Exposure) WaitTCPReady(ctx context.Context) ([]RelayStatus, error) {
	if !e.options.TCPEnabled {
		return nil, errExposureDoesNotHaveTCPEnabled
	}
	return e.waitReady(ctx, func(status RelayStatus) bool {
		return status.State != RelayFailed && status.TCPAddr != ""
	}, false)
}
