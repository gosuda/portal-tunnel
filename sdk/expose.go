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

	accepted  chan net.Conn
	datagrams chan types.DatagramFrame

	relaySet       *discovery.RelaySet
	listenerMu     sync.RWMutex
	relayListeners map[string]*listener

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
		return nil, errors.New("pepper active mode is not implemented yet")
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

	identity, createdIdentity, err := utils.ResolveListenerIdentity(
		types.Identity{Name: cfg.Name},
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

func (e *Exposure) Accept() (net.Conn, error) {
	select {
	case <-e.done:
		return nil, net.ErrClosed
	case conn := <-e.accepted:
		if conn == nil {
			return nil, net.ErrClosed
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
	var listenerRelayURLs []string
	var multiHop []string
	if len(e.multiHop) > 0 {
		listenerRelayURLs = []string{e.multiHop[len(e.multiHop)-1]}
		multiHop = append([]string(nil), e.multiHop...)
	} else if e.multiHopDepth > 1 {
		multiHop = e.relaySet.PriorityMultiHop(discovery.ClientState{
			MultiHopDepth: e.multiHopDepth,
			LocalAddress:  e.identity.Address,
		})
		if len(multiHop) < e.multiHopDepth {
			return fmt.Errorf("multi-hop-depth %d requires %d overlay relay candidates, got %d", e.multiHopDepth, e.multiHopDepth, len(multiHop))
		}
		listenerRelayURLs = []string{multiHop[len(multiHop)-1]}
	} else {
		listenerRelayURLs = e.relaySet.PriorityRelays(discovery.ClientState{
			ExplicitRelayURLs: append([]string(nil), e.explicitRelays...),
			MaxActiveRelays:   e.maxActiveRelays,
			RequireUDP:        e.udpEnabled,
			RequireTCP:        e.tcpEnabled,
			LocalAddress:      e.identity.Address,
		})
	}

	e.listenerMu.Lock()
	staleRelayListeners := make(map[string]*listener)
	removedRelayURLs := make([]string, 0)
	for relayURL, listener := range e.relayListeners {
		if slices.Contains(listenerRelayURLs, relayURL) && slices.Equal(listener.multiHop, multiHop) {
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
		retryCount := 10
		if len(multiHop) > 0 || slices.Contains(e.explicitRelays, relayURL) {
			retryCount = 0
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
