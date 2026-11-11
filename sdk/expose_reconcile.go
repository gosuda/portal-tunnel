package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"

	"github.com/rs/zerolog/log"
)

type exposureConn struct {
	net.Conn
	id         uint64
	localAddr  string
	remoteAddr string
	closeOnce  sync.Once
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
		e.setRelayStatus(relayURL, listenerStatus{state: RelayConnecting})
		published, err := e.publishRelayListenerLocked(relayURL)
		if err != nil {
			e.setRelayStatus(relayURL, listenerStatus{state: RelayFailed, err: err})
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
		Cache:      e.cache,
		Identity:   e.identity,
		Overlay:    e.options.Overlay,
		UDPEnabled: e.options.UDPEnabled,
		TCPEnabled: e.options.TCPEnabled,
		BanMITM:    e.options.BanMITM,
		Metadata:   e.metadata.Copy(),
		StartedAt:  e.startedAt,
	})
	if err != nil {
		return false, err
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
			e.setListenerRelayStatus(relayURL, listener, status)
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
