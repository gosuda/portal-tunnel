package portal

import (
	"errors"
	"sort"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// ErrNoRelays is returned by WaitReady once every observed relay has failed.
var ErrNoRelays = errors.New("portal: no relays available")

// RelayState is the lifecycle state of one relay as seen by the facade.
type RelayState string

const (
	// RelayConnecting means the relay listener is registered but does not
	// have a public URL yet.
	RelayConnecting RelayState = "connecting"
	// RelayReady means the relay can accept tenant connections.
	RelayReady RelayState = "ready"
	// RelayUDPReady means the relay additionally has an authenticated
	// datagram backhaul.
	RelayUDPReady RelayState = "udp_ready"
	// RelayFailed means the relay is banned or otherwise unusable.
	RelayFailed RelayState = "failed"
)

// RelayStatus is an immutable snapshot of one relay's externally visible
// state. UDPAddr and Err are reserved for relay-status data the sdk does not
// surface yet; they stay empty and nil until that grows.
type RelayStatus struct {
	RelayURL  string
	PublicURL string
	UDPAddr   string
	State     RelayState
	Err       error
}

// relayStatusesFromSnapshot maps an sdk tunnel snapshot onto facade
// statuses, sorted by relay URL.
func relayStatusesFromSnapshot(snapshot types.AgentTunnelStatus) []RelayStatus {
	statuses := make([]RelayStatus, 0, len(snapshot.Relays))
	for _, relay := range snapshot.Relays {
		status := RelayStatus{
			RelayURL:  relay.RelayURL,
			PublicURL: relay.PublicURL,
		}
		switch {
		case relay.Banned:
			status.State = RelayFailed
		case relay.PublicURL != "":
			status.State = RelayReady
		default:
			status.State = RelayConnecting
		}
		statuses = append(statuses, status)
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].RelayURL < statuses[j].RelayURL })
	return statuses
}

func readyStatuses(statuses []RelayStatus) []RelayStatus {
	var ready []RelayStatus
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
	return true
}

func relayStatusUnchanged(previous, current RelayStatus) bool {
	return previous.RelayURL == current.RelayURL &&
		previous.PublicURL == current.PublicURL &&
		previous.UDPAddr == current.UDPAddr &&
		previous.State == current.State
}
