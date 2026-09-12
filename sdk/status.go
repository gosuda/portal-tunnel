package sdk

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
)

var (
	errNilContext       = errors.New("sdk: context is nil")
	errRelayUnavailable = errors.New("relay is unavailable")
)

// ErrNoRelays is returned by WaitReady once every observed relay has failed.
var ErrNoRelays = errors.New("sdk: no relays available")

// RelayState is the externally visible lifecycle state of one relay.
type RelayState string

const (
	RelayConnecting RelayState = "connecting"
	RelayReady      RelayState = "ready"
	RelayUDPReady   RelayState = "udp_ready"
	RelayFailed     RelayState = "failed"
)

// RelayStatus is the listener-oriented status of one relay. It is kept in
// sdk because it describes the client runtime, not a wire-level type.
type RelayStatus struct {
	RelayURL  string
	PublicURL string
	UDPAddr   string
	State     RelayState
	Err       error
}

// Relays returns the current relay lifecycle projection, sorted by relay URL.
func (e *Exposure) Relays() []RelayStatus {
	if e == nil {
		return nil
	}
	return e.currentRelayStatuses()
}

// WaitReady waits until at least one relay can accept tenant connections.
// It does not consume Updates.
func (e *Exposure) WaitReady(ctx context.Context) ([]RelayStatus, error) {
	if e == nil {
		return nil, net.ErrClosed
	}
	if ctx == nil {
		return nil, errNilContext
	}
	for {
		statuses := e.currentRelayStatuses()
		if ready := readyStatuses(statuses); len(ready) != 0 {
			return ready, nil
		}
		if len(statuses) != 0 && allFailed(statuses) {
			return nil, ErrNoRelays
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-e.done:
			return nil, net.ErrClosed
		case <-e.statusNotify:
		}
	}
}

// WaitDatagramStatuses waits for authenticated datagram backhauls and
// returns their complete relay status. WaitDatagramReady retains its historic
// []string API for compatibility and returns only the UDP addresses.
func (e *Exposure) WaitDatagramStatuses(ctx context.Context) ([]RelayStatus, error) {
	if e == nil {
		return nil, net.ErrClosed
	}
	if ctx == nil {
		return nil, errNilContext
	}
	addrs, err := e.WaitDatagramReady(ctx)
	if err != nil {
		return nil, err
	}
	ready := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		ready[addr] = struct{}{}
	}
	statuses := e.currentRelayStatuses()
	out := make([]RelayStatus, 0, len(ready))
	for _, status := range statuses {
		if _, ok := ready[status.UDPAddr]; !ok {
			continue
		}
		status.State = RelayUDPReady
		out = append(out, status)
	}
	return out, nil
}

// Updates returns lifecycle changes emitted by the relay runtime. Existing
// statuses are replayed when the channel is first created. The channel is
// closed when the exposure closes.
func (e *Exposure) Updates() <-chan RelayStatus {
	if e == nil {
		return nil
	}
	initial := e.currentRelayStatuses()
	e.statusMu.Lock()
	if e.statusNotify == nil {
		e.statusNotify = make(chan struct{}, 1)
	}
	if e.statusUpdates == nil {
		e.statusUpdates = make(chan RelayStatus, 16)
		if !e.statusClosed {
			for _, status := range initial {
				select {
				case e.statusUpdates <- status:
				default:
				}
			}
		} else {
			close(e.statusUpdates)
		}
	}
	updates := e.statusUpdates
	e.statusMu.Unlock()
	return updates
}

func (e *Exposure) currentRelayStatuses() []RelayStatus {
	if e == nil {
		return nil
	}

	e.mu.RLock()
	listeners := make(map[string]*listener, len(e.relayListeners))
	for relayURL, listener := range e.relayListeners {
		listeners[relayURL] = listener
	}
	relaySet := e.relaySet
	e.mu.RUnlock()

	e.statusMu.Lock()
	statuses := make(map[string]RelayStatus, len(e.statuses)+len(listeners))
	for relayURL, status := range e.statuses {
		statuses[relayURL] = status
	}
	e.statusMu.Unlock()

	for relayURL, listener := range listeners {
		if listener == nil {
			continue
		}
		statuses[relayURL] = relayStatusFromListener(listener)
	}
	if relaySet != nil {
		for _, state := range relaySet.AllRelays() {
			relayURL := strings.TrimSpace(state.Descriptor.APIHTTPSAddr)
			if relayURL == "" {
				continue
			}
			if _, active := listeners[relayURL]; active {
				continue
			}
			switch {
			case state.Banned || state.Dead:
				statuses[relayURL] = RelayStatus{
					RelayURL: relayURL,
					State:    RelayFailed,
					Err:      errRelayUnavailable,
				}
			default:
				if _, ok := statuses[relayURL]; !ok {
					statuses[relayURL] = RelayStatus{RelayURL: relayURL, State: RelayConnecting}
				}
			}
		}
	}

	out := make([]RelayStatus, 0, len(statuses))
	for _, status := range statuses {
		out = append(out, status)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RelayURL < out[j].RelayURL })
	return out
}

func relayStatusFromListener(listener *listener) RelayStatus {
	status := RelayStatus{State: RelayConnecting}
	if listener == nil {
		return status
	}
	status.RelayURL = listener.route.RelayURL
	if lease, ok := listener.leaseSnapshot(); ok {
		status.PublicURL = listener.publicURLForLease(lease)
		status.UDPAddr = lease.udpAddr
		switch {
		case status.UDPAddr != "" && listener.datagram != nil && listener.datagram.Connected():
			status.State = RelayUDPReady
		case status.PublicURL != "" || lease.tcpAddr != "":
			status.State = RelayReady
		}
	}
	return status
}

func (e *Exposure) updateRelayStatus(listener *listener, err error) {
	if listener == nil {
		return
	}
	e.statusMu.Lock()
	previous, ok := e.statuses[listener.route.RelayURL]
	e.statusMu.Unlock()
	if errors.Is(err, net.ErrClosed) || (err == nil && listenerStopped(listener)) {
		if ok && previous.State == RelayFailed && previous.Err != nil {
			return
		}
	}
	status := relayStatusFromListener(listener)
	if err != nil {
		status.State = RelayFailed
		status.Err = err
	}
	e.publishRelayStatus(status)
}

func listenerStopped(listener *listener) bool {
	if listener == nil || listener.doneCh == nil {
		return false
	}
	select {
	case <-listener.doneCh:
		return true
	default:
		return false
	}
}

func (e *Exposure) setRelayConnecting(relayURL string) {
	relayURL = strings.TrimSpace(relayURL)
	if relayURL == "" {
		return
	}
	e.publishRelayStatus(RelayStatus{RelayURL: relayURL, State: RelayConnecting})
}

func (e *Exposure) publishRelayStatus(status RelayStatus) {
	if e == nil || strings.TrimSpace(status.RelayURL) == "" {
		return
	}
	status.RelayURL = strings.TrimSpace(status.RelayURL)
	e.statusMu.Lock()
	if e.statuses == nil {
		e.statuses = make(map[string]RelayStatus)
	}
	previous, ok := e.statuses[status.RelayURL]
	if ok && relayStatusUnchanged(previous, status) {
		e.statusMu.Unlock()
		return
	}
	e.statuses[status.RelayURL] = status
	if e.statusUpdates != nil && !e.statusClosed {
		select {
		case e.statusUpdates <- status:
		default:
		}
	}
	e.statusMu.Unlock()

	if e.statusNotify != nil {
		select {
		case e.statusNotify <- struct{}{}:
		default:
		}
	}
}

func relayStatusUnchanged(previous, current RelayStatus) bool {
	return previous.RelayURL == current.RelayURL &&
		previous.PublicURL == current.PublicURL &&
		previous.UDPAddr == current.UDPAddr &&
		previous.State == current.State &&
		errorText(previous.Err) == errorText(current.Err)
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func readyStatuses(statuses []RelayStatus) []RelayStatus {
	ready := make([]RelayStatus, 0, len(statuses))
	for _, status := range statuses {
		if status.State == RelayReady || status.State == RelayUDPReady {
			ready = append(ready, status)
		}
	}
	return ready
}

func allFailed(statuses []RelayStatus) bool {
	for _, status := range statuses {
		if status.State != RelayFailed {
			return false
		}
	}
	return len(statuses) > 0
}

func (e *Exposure) publishInactiveRelayStatuses() {
	if e == nil || e.relaySet == nil {
		return
	}
	e.mu.RLock()
	active := make(map[string]struct{}, len(e.relayListeners))
	for relayURL := range e.relayListeners {
		active[relayURL] = struct{}{}
	}
	e.mu.RUnlock()
	for _, state := range e.relaySet.AllRelays() {
		relayURL := strings.TrimSpace(state.Descriptor.APIHTTPSAddr)
		if relayURL == "" {
			continue
		}
		if _, ok := active[relayURL]; ok {
			continue
		}
		if state.Banned || state.Dead {
			e.publishRelayStatus(RelayStatus{
				RelayURL: relayURL,
				State:    RelayFailed,
				Err:      errRelayUnavailable,
			})
		}
	}
}

func (e *Exposure) closeStatusUpdates() {
	e.statusMu.Lock()
	defer e.statusMu.Unlock()
	if e.statusClosed {
		return
	}
	e.statusClosed = true
	if e.statusUpdates != nil {
		close(e.statusUpdates)
	}
}
