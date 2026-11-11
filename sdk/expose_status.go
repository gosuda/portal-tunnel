package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
)

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

func (e *Exposure) setRelayStatus(relayURL string, update listenerStatus) {
	e.applyRelayStatus(relayURL, update, nil)
}

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
	}
	if update.state == RelayConnecting {
		status.PublicURL = ""
		status.AliasURL = ""
		status.UDPAddr = ""
		status.TCPAddr = ""
	}
	if update.publicURL != "" || update.state == RelayReady {
		status.PublicURL = update.publicURL
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
	advertised := previous.State != RelayReady && status.State == RelayReady && status.PublicURL != ""
	if advertised {
		message := "service ready at " + status.PublicURL
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
	return a.RelayURL == b.RelayURL &&
		a.PublicURL == b.PublicURL &&
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

func (e *Exposure) readyRelays(matches func(RelayStatus) bool) ([]RelayStatus, <-chan struct{}, error) {
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
// If every current relay has failed terminally, it returns their errors. The
// exposure stays open, and callers may add relays or continue discovery.
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
		return nil, errPortalSDKContextIsNil
	}
	for {
		ready, changed, terminalErr := e.readyRelays(matches)
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
	})
}

// WaitTCPReady waits until at least one relay has allocated a public TCP
// address and returns the ready relay snapshots.
func (e *Exposure) WaitTCPReady(ctx context.Context) ([]RelayStatus, error) {
	if !e.options.TCPEnabled {
		return nil, errExposureDoesNotHaveTCPEnabled
	}
	return e.waitReady(ctx, func(status RelayStatus) bool {
		return status.State != RelayFailed && status.TCPAddr != ""
	})
}
