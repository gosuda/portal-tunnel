package discovery

import (
	"slices"
	"sort"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/telemetry"
)

// RelayPolicy owns relay state transitions and selection ordering.
// It is the boundary between the RelaySet (state ownership) and the
// ranking engine (stateless computation).
type RelayPolicy interface {
	SelectAggregate(states []RelayState) []RelayState
	SelectConfirmed(states []RelayState) []RelayState

	OnActiveConfirmed(state RelayState) RelayState
	OnUnconfirmed(state RelayState) RelayState
	OnDiscoveryConfirmed(state RelayState) RelayState
	OnDiscoveryFailure(state RelayState, err error, recoveryFailures int) (RelayState, bool, string)
	OnActiveFailure(state RelayState, err error, recoveryFailures int) (RelayState, bool, string)
	OnBanned(state RelayState) RelayState

	SelectPriority(states []RelayState, cs ClientState) []string
	SelectPriorityWithTrace(states []RelayState, cs ClientState) ([]string, telemetry.SelectionTrace)
	SelectMultiHop(states []RelayState, cs ClientState) []string
	SelectMultiHopWithTrace(states []RelayState, cs ClientState) ([]string, telemetry.SelectionTrace)
}

// SimpleRelayPolicy is a lightweight fallback policy that does not depend on
// the MOLS engine.  It keeps explicit relays first, filters suppressed/expired
// entries, and orders the auto pool by RTT (lowest first).  This guarantees that
// portal-tunnel continues to function even when the MOLS module is unavailable.
type SimpleRelayPolicy struct{}

func (SimpleRelayPolicy) SelectAggregate(states []RelayState) []RelayState {
	out := make([]RelayState, 0, len(states))
	for _, s := range states {
		if !s.Banned {
			out = append(out, s)
		}
	}
	return out
}

func (SimpleRelayPolicy) SelectConfirmed(states []RelayState) []RelayState {
	out := make([]RelayState, 0)
	for _, s := range states {
		if s.Confirmed {
			out = append(out, s)
		}
	}
	return out
}

func (SimpleRelayPolicy) OnActiveConfirmed(state RelayState) RelayState {
	state.Confirmed = true
	state.activeFailures = 0
	state.suppressActiveUntil = time.Time{}
	return state
}

func (SimpleRelayPolicy) OnUnconfirmed(state RelayState) RelayState {
	state.Confirmed = false
	return state
}

func (SimpleRelayPolicy) OnDiscoveryConfirmed(state RelayState) RelayState {
	state.discoveryFailures = 0
	state.nextDiscoveryRefreshAt = time.Time{}
	return state
}

func (SimpleRelayPolicy) OnDiscoveryFailure(state RelayState, err error, recoveryFailures int) (RelayState, bool, string) {
	state.discoveryFailures++
	if recoveryFailures <= 0 || state.discoveryFailures < recoveryFailures {
		return state, false, "retry"
	}
	failuresOverBudget := state.discoveryFailures - recoveryFailures
	backoff := defaultDirectRecoveryBackoff << min(failuresOverBudget, 3)
	if backoff > maxDirectRecoveryBackoff {
		backoff = maxDirectRecoveryBackoff
	}
	state.nextDiscoveryRefreshAt = time.Now().Add(backoff)
	return state, true, "discovery"
}

func (SimpleRelayPolicy) OnActiveFailure(state RelayState, err error, recoveryFailures int) (RelayState, bool, string) {
	state.activeFailures++
	if recoveryFailures <= 0 || state.activeFailures < recoveryFailures {
		return state, false, "retry"
	}
	failuresOverBudget := state.activeFailures - recoveryFailures
	backoff := defaultDirectRecoveryBackoff << min(failuresOverBudget, 3)
	if backoff > maxDirectRecoveryBackoff {
		backoff = maxDirectRecoveryBackoff
	}
	state.suppressActiveUntil = time.Now().Add(backoff)
	return state, true, "active"
}

func (SimpleRelayPolicy) OnBanned(state RelayState) RelayState {
	state.Banned = true
	return state
}

func (p SimpleRelayPolicy) SelectPriority(states []RelayState, cs ClientState) []string {
	now := time.Now().UTC()

	selected := p.SelectAggregate(states)
	if len(selected) == 0 {
		return nil
	}

	explicit := make([]string, 0, len(cs.ExplicitRelayURLs))
	auto := make([]RelayState, 0, len(selected))

	for _, state := range selected {
		relayURL := state.Descriptor.APIHTTPSAddr
		if slices.Contains(cs.ExplicitRelayURLs, relayURL) {
			if state.hasObservedDescriptor() && state.Descriptor.ExpiresAt.After(now) {
				if cs.RequireUDP && !state.Descriptor.SupportsUDP {
					continue
				}
				if cs.RequireTCP && !state.Descriptor.SupportsTCP {
					continue
				}
			}
			explicit = append(explicit, relayURL)
			continue
		}
		if state.hasObservedDescriptor() {
			if !state.Descriptor.ExpiresAt.After(now) {
				continue
			}
			if cs.RequireUDP && !state.Descriptor.SupportsUDP {
				continue
			}
			if cs.RequireTCP && !state.Descriptor.SupportsTCP {
				continue
			}
		}
		if !state.suppressActiveUntil.IsZero() && state.suppressActiveUntil.After(now) {
			continue
		}
		auto = append(auto, state)
	}

	// Order by RTT; unmeasured (zero) relays are treated as best-effort seeds.
	sort.Slice(auto, func(i, j int) bool {
		if auto[i].DiscoveryRTT == 0 {
			return true
		}
		if auto[j].DiscoveryRTT == 0 {
			return false
		}
		return auto[i].DiscoveryRTT < auto[j].DiscoveryRTT
	})

	out := make([]string, 0, len(explicit)+len(auto))
	out = append(out, explicit...)
	for _, s := range auto {
		out = append(out, s.Descriptor.APIHTTPSAddr)
	}

	maxActiveRelays := cs.MaxActiveRelays
	if maxActiveRelays <= 0 {
		maxActiveRelays = 3
	}
	if len(out) > maxActiveRelays {
		out = out[:maxActiveRelays]
	}
	return out
}

func (p SimpleRelayPolicy) SelectPriorityWithTrace(states []RelayState, cs ClientState) ([]string, telemetry.SelectionTrace) {
	start := time.Now()
	trace := telemetry.SelectionTrace{
		Timestamp: start,
		Mode:      "priority",
		PoolTotal: len(states),
		Reasons:   make(map[string]string),
	}
	urls := p.SelectPriority(states, cs)
	trace.OutputURLs = urls
	trace.SelectionTook = time.Since(start)
	return urls, trace
}

func (p SimpleRelayPolicy) SelectMultiHop(states []RelayState, cs ClientState) []string {
	if cs.MultiHopDepth <= 1 {
		return nil
	}
	now := time.Now().UTC()

	selected := p.SelectAggregate(states)
	if len(selected) == 0 {
		return nil
	}

	out := make([]string, 0, len(selected))
	for _, state := range selected {
		relayURL := state.Descriptor.APIHTTPSAddr
		if cs.RequireUDP && state.hasObservedDescriptor() && !state.Descriptor.SupportsUDP {
			continue
		}
		if cs.RequireTCP && state.hasObservedDescriptor() && !state.Descriptor.SupportsTCP {
			continue
		}
		if !state.hasObservedDescriptor() {
			continue
		}
		if !state.Descriptor.ExpiresAt.After(now) {
			continue
		}
		if !state.Descriptor.HasOverlayPeer() {
			continue
		}
		if !state.suppressActiveUntil.IsZero() && state.suppressActiveUntil.After(now) {
			continue
		}
		out = append(out, relayURL)
	}

	if len(out) > cs.MultiHopDepth {
		out = out[:cs.MultiHopDepth]
	}
	return out
}

func (p SimpleRelayPolicy) SelectMultiHopWithTrace(states []RelayState, cs ClientState) ([]string, telemetry.SelectionTrace) {
	start := time.Now()
	trace := telemetry.SelectionTrace{
		Timestamp: start,
		Mode:      "multihop",
		PoolTotal: len(states),
		Reasons:   make(map[string]string),
	}
	urls := p.SelectMultiHop(states, cs)
	trace.OutputURLs = urls
	trace.SelectionTook = time.Since(start)
	return urls, trace
}
