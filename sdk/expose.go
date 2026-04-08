package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
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

	identity   types.Identity
	TargetAddr string
	UDPAddr    string
	udpEnabled bool
	tcpEnabled bool
	banMITM    bool
	metadata   types.LeaseMetadata
	rootCAPEM  []byte

	accepted  chan net.Conn
	datagrams chan types.DatagramFrame

	relaySet       *discovery.RelaySet
	discoveryMgr   *discovery.Manager
	listenerMu     sync.RWMutex
	relayListeners map[string]*Listener

	closeOnce sync.Once
	connSeq   atomic.Uint64
}

type ExposeConfig struct {
	RelayURLs    []string
	IdentityPath string
	IdentityJSON string
	Name         string
	TargetAddr   string
	UDPAddr      string
	UDPEnabled   bool
	TCPEnabled   bool
	BanMITM      bool
	Discovery    bool
	Metadata     types.LeaseMetadata
	RootCAPEM    []byte
	MaxRouting   int
}

// Expose creates relay listeners for each normalized relay URL and exposes a
// dynamic listener hub for accepting traffic from all of them.
func Expose(ctx context.Context, cfg ExposeConfig) (*Exposure, error) {
	includeDefaults := cfg.Discovery
	relayURLs, err := utils.ResolvePortalRelayURLs(ctx, cfg.RelayURLs, includeDefaults)
	if err != nil {
		return nil, err
	}
	useManager := cfg.Discovery
	var discoveryMgr *discovery.Manager
	if useManager {
		managerCfg := discovery.ManagerConfig{
			Bootstraps: relayURLs,
			RootCAPEM:  append([]byte(nil), cfg.RootCAPEM...),
			MaxRouting: cfg.MaxRouting,
		}
		discoveryMgr, err = discovery.NewManager(managerCfg)
		if err != nil {
			return nil, fmt.Errorf("discovery manager: %w", err)
		}
	}

	identity, err := utils.ResolveListenerIdentity(
		types.Identity{Name: cfg.Name},
		cfg.TargetAddr,
		cfg.IdentityPath,
		cfg.IdentityJSON,
	)
	if err != nil {
		return nil, err
	}
	targetAddr, udpAddr, err := resolveExposeTargets(cfg)
	if err != nil {
		return nil, err
	}

	exposureCtx, cancel := context.WithCancel(ctx)
	exposure := &Exposure{
		cancel:         cancel,
		done:           exposureCtx.Done(),
		identity:       identity,
		TargetAddr:     targetAddr,
		UDPAddr:        udpAddr,
		udpEnabled:     cfg.UDPEnabled,
		tcpEnabled:     cfg.TCPEnabled,
		banMITM:        cfg.BanMITM,
		metadata:       cfg.Metadata.Copy(),
		rootCAPEM:      append([]byte(nil), cfg.RootCAPEM...),
		accepted:       make(chan net.Conn, max(len(relayURLs)*defaultReadyTarget*2, 1)),
		datagrams:      make(chan types.DatagramFrame, max(len(relayURLs)*32, 1)),
		discoveryMgr:   discoveryMgr,
		relayListeners: make(map[string]*Listener, len(relayURLs)),
	}
	if exposure.discoveryMgr != nil {
		exposure.relaySet = exposure.discoveryMgr.RelaySet()
	} else {
		exposure.relaySet = discovery.NewRelaySet()
	}

	if err := exposure.bootstrapRelayListeners(relayURLs); err != nil {
		_ = exposure.Close()
		return nil, err
	}

	exposure.startDiscoveryLoop(cfg.Discovery, exposureCtx)
	go func() {
		<-exposure.done
		_ = exposure.Close()
	}()

	return exposure, nil
}

func resolveExposeTargets(cfg ExposeConfig) (string, string, error) {
	targetAddr, err := utils.NormalizeLoopbackTarget(cfg.TargetAddr)
	if err != nil {
		return "", "", fmt.Errorf("invalid target value %q: %w", cfg.TargetAddr, err)
	}
	udpAddr := cfg.UDPAddr
	if !cfg.UDPEnabled {
		return targetAddr, udpAddr, nil
	}
	udpAddr, err = utils.NormalizeLoopbackTarget(utils.StringOrDefault(udpAddr, targetAddr))
	if err != nil {
		return "", "", fmt.Errorf("invalid --udp-addr value %q: %w", cfg.UDPAddr, err)
	}
	return targetAddr, udpAddr, nil
}

func (e *Exposure) bootstrapRelayListeners(relayURLs []string) error {
	if len(relayURLs) == 0 {
		return nil
	}
	if e.discoveryMgr != nil {
		e.discoveryMgr.SetBootstrapRelayURLs(relayURLs)
	} else {
		e.relaySet.SetBootstrapRelayURLs(relayURLs)
	}
	return e.reconcileRelayListeners(true)
}

func (e *Exposure) startDiscoveryLoop(enabled bool, exposureCtx context.Context) {
	if !enabled {
		return
	}
	if e.discoveryMgr != nil {
		go func() {
			_ = e.discoveryMgr.Run(exposureCtx, func(map[string]types.RelayState) {
				if err := e.reconcileRelayListeners(false); err != nil {
					log.Warn().Err(err).Msg("exposure: reconcile after discovery update failed")
				}
			})
		}()
		return
	}
	go func() {
		_ = e.relaySet.RunLoop(exposureCtx, e.rootCAPEM, func() error {
			return e.reconcileRelayListeners(false)
		})
	}()
}
func (e *Exposure) ActiveRelayURLs() []string {
	return e.relaySet.ActiveRelayURLs()
}

func (e *Exposure) Addr() net.Addr {
	return listenerAddr("portal:exposure")
}

func (e *Exposure) Identity() types.Identity {
	if e == nil {
		return types.Identity{}
	}
	return e.identity.Copy()
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
			Str("local_addr", utils.AddrString(conn.LocalAddr())).
			Str("remote_addr", utils.AddrString(conn.RemoteAddr())).
			Msg("exposure connection accepted")

		return &exposureConn{
			Conn:       conn,
			id:         connID,
			localAddr:  utils.AddrString(conn.LocalAddr()),
			remoteAddr: utils.AddrString(conn.RemoteAddr()),
		}, nil
	}
}

func (e *Exposure) Close() error {
	var closeErr error
	e.closeOnce.Do(func() {
		if e.cancel != nil {
			e.cancel()
		}

		e.listenerMu.RLock()
		relayURLs := make([]string, 0, len(e.relayListeners))
		listeners := make([]*Listener, 0, len(e.relayListeners))
		for relayURL, listener := range e.relayListeners {
			relayURLs = append(relayURLs, relayURL)
			listeners = append(listeners, listener)
		}
		e.listenerMu.RUnlock()

		for _, listener := range listeners {
			if listener != nil {
				closeErr = errors.Join(closeErr, listener.Close())
			}
		}

		event := log.Info().
			Int("relay_count", len(listeners)).
			Strs("relays", relayURLs)
		if closeErr != nil {
			event = log.Warn().
				Err(closeErr).
				Int("relay_count", len(listeners)).
				Strs("relays", relayURLs)
		}
		event.Msg("exposure closed")
	})
	return closeErr
}

func (e *Exposure) reconcileRelayListeners(failOnError bool) error {
	if e.relaySet == nil {
		e.relaySet = discovery.NewRelaySet()
	}
	e.listenerMu.Lock()
	if e.relayListeners == nil {
		e.relayListeners = make(map[string]*Listener)
	}
	activeRelayURLs := e.relaySet.ActiveRelayURLs()
	currentRelayURLs := make([]string, 0, len(e.relayListeners))
	for relayURL := range e.relayListeners {
		currentRelayURLs = append(currentRelayURLs, relayURL)
	}
	missingRelayURLs := utils.FilterRelayURLs(activeRelayURLs, currentRelayURLs)
	staleRelayURLs := utils.FilterRelayURLs(currentRelayURLs, activeRelayURLs)
	staleListeners := make([]*Listener, 0, len(staleRelayURLs))
	for _, relayURL := range staleRelayURLs {
		staleListeners = append(staleListeners, e.relayListeners[relayURL])
		delete(e.relayListeners, relayURL)
	}
	e.listenerMu.Unlock()

	for i, listener := range staleListeners {
		if listener == nil {
			continue
		}
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Warn().Err(err).Str("relay_url", staleRelayURLs[i]).Msg("close stale relay listener")
		}
	}
	for _, relayURL := range missingRelayURLs {
		listener, err := NewListener(context.Background(), relayURL, ListenerConfig{
			Identity:   e.identity.Copy(),
			UDPEnabled: e.udpEnabled,
			TCPEnabled: e.tcpEnabled,
			BanMITM:    e.banMITM,
			Metadata:   e.metadata.Copy(),
			RootCAPEM:  append([]byte(nil), e.rootCAPEM...),
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
		if e.relayListeners == nil {
			e.relayListeners = make(map[string]*Listener, 1)
		}
		if _, exists := e.relayListeners[relayURL]; exists {
			e.listenerMu.Unlock()
			_ = listener.Close()
			continue
		}
		e.relayListeners[relayURL] = listener
		e.listenerMu.Unlock()

		go e.runListenerAcceptLoop(listener)
	}
	return nil
}

func (e *Exposure) runListenerAcceptLoop(listener *Listener) {
	if listener == nil {
		return
	}

	relayURL := listener.api.baseURL.String()
	if e.udpEnabled {
		go func() {
			for {
				frame, err := listener.AcceptDatagram()
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
						Str("address", listener.Address()).
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
			if listener.closed() || errors.Is(err, net.ErrClosed) {
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
	return listener.SendDatagram(frame)
}

func (e *Exposure) WaitDatagramReady(ctx context.Context) ([]string, error) {
	if !e.udpEnabled {
		return nil, errors.New("exposure does not have udp enabled")
	}

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		e.listenerMu.RLock()
		listeners := make([]*Listener, 0, len(e.relayListeners))
		for _, listener := range e.relayListeners {
			listeners = append(listeners, listener)
		}
		e.listenerMu.RUnlock()

		addrs := make([]string, 0, len(listeners))
		seen := make(map[string]struct{})
		resolvedWithoutDatagram := true
		for _, listener := range listeners {
			if listener == nil {
				continue
			}

			udpAddr, ready, pending := listener.DatagramReady()
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

func (e *Exposure) RunHTTP(ctx context.Context, handler http.Handler, localAddr string) error {
	var relayListener net.Listener
	e.listenerMu.RLock()
	activeListeners := make([]*Listener, 0, len(e.relayListeners))
	for _, relayURL := range e.relaySet.ActiveRelayURLs() {
		listener, ok := e.relayListeners[relayURL]
		if !ok {
			continue
		}
		activeListeners = append(activeListeners, listener)
	}
	e.listenerMu.RUnlock()
	if len(activeListeners) > 0 {
		relayListener = e
	}
	return RunHTTP(ctx, relayListener, handler, localAddr)
}
