package portal

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// errNilContext mirrors portalite's nil-context contract for the status APIs.
var errNilContext = errors.New("portal: context is nil")

// pollInterval is how often WaitReady and the Updates stream observe the
// underlying relay snapshot.
const pollInterval = 250 * time.Millisecond

// Exposure is the relayed network endpoint: a net.Listener that fans in
// tenant connections from all relays. Proxying to a local service is a
// separate concern (see Proxy).
type Exposure struct {
	inner  *sdk.Exposure
	ctx    context.Context
	cancel context.CancelFunc

	updatesOnce sync.Once
	updates     chan RelayStatus
}

// Accept returns the next tenant connection from any relay.
func (e *Exposure) Accept() (net.Conn, error) {
	if e == nil {
		return nil, net.ErrClosed
	}
	return e.inner.Accept()
}

// Addr identifies the aggregate listener and its identity.
func (e *Exposure) Addr() net.Addr {
	if e == nil {
		return nil
	}
	return e.inner.Addr()
}

// Close shuts down every relay listener. Subsequent Accept calls return
// net.ErrClosed.
func (e *Exposure) Close() error {
	if e == nil {
		return net.ErrClosed
	}
	e.cancel()
	return e.inner.Close()
}

// AcceptDatagram returns the next relayed datagram frame.
func (e *Exposure) AcceptDatagram() (types.DatagramFrame, error) {
	if e == nil {
		return types.DatagramFrame{}, net.ErrClosed
	}
	return e.inner.AcceptDatagram()
}

// SendDatagram sends a response frame through its relay and flow.
func (e *Exposure) SendDatagram(frame types.DatagramFrame) error {
	if e == nil {
		return net.ErrClosed
	}
	return e.inner.SendDatagram(frame)
}

// WaitDatagramReady waits until at least one relay has an authenticated
// datagram backhaul and returns those relays as statuses.
func (e *Exposure) WaitDatagramReady(ctx context.Context) ([]RelayStatus, error) {
	if e == nil {
		return nil, net.ErrClosed
	}
	readyURLs, err := e.inner.WaitDatagramReady(ctx)
	if err != nil {
		return nil, err
	}
	ready := make(map[string]struct{}, len(readyURLs))
	for _, relayURL := range readyURLs {
		ready[relayURL] = struct{}{}
	}
	var statuses []RelayStatus
	for _, status := range e.relayStatuses() {
		if _, ok := ready[status.RelayURL]; ok {
			statuses = append(statuses, status)
		}
	}
	return statuses, nil
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
		statuses := e.relayStatuses()
		if ready := readyStatuses(statuses); len(ready) != 0 {
			return ready, nil
		}
		if len(statuses) != 0 && allFailed(statuses) {
			return nil, ErrNoRelays
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-e.ctx.Done():
			return nil, net.ErrClosed
		case <-time.After(pollInterval):
		}
	}
}

// Updates returns the relay lifecycle stream. Only relays whose status
// changed are emitted; the channel is non-blocking, drops updates when
// unconsumed, and is closed when the exposure closes.
func (e *Exposure) Updates() <-chan RelayStatus {
	if e == nil {
		return nil
	}
	e.updatesOnce.Do(func() {
		e.updates = make(chan RelayStatus, 16)
		go e.runUpdatesLoop()
	})
	return e.updates
}

func (e *Exposure) runUpdatesLoop() {
	defer close(e.updates)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	last := make(map[string]RelayStatus)
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
		}
		for _, status := range e.relayStatuses() {
			if previous, ok := last[status.RelayURL]; ok && relayStatusUnchanged(previous, status) {
				continue
			}
			last[status.RelayURL] = status
			select {
			case e.updates <- status:
			default:
			}
		}
	}
}

// Relays returns a snapshot of every relay's current status, sorted by relay
// URL.
func (e *Exposure) Relays() []RelayStatus {
	if e == nil {
		return nil
	}
	return e.relayStatuses()
}

func (e *Exposure) relayStatuses() []RelayStatus {
	if e.inner == nil {
		return nil
	}
	return relayStatusesFromSnapshot(e.inner.Snapshot())
}
