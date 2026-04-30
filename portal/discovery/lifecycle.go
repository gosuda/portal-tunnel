package discovery

import "time"

// Lifecycle owns policy-agnostic relay state transitions: bans, confirmation,
// discovery and active failure tracking, and suppression bookkeeping. It holds
// no MOLS scoring state and is independent of any selection algorithm.
//
// The struct is intentionally kept extensible for Stage 2B, which will add
// EWMA load fields; callers should always construct via NewLifecycle.
//
// Concurrency: Lifecycle methods are not internally synchronized. All On*
// methods must be called with the owning RelaySet.mu write lock already held.
// Stage 2B EWMA fields must follow this same discipline; do NOT add an
// internal mutex to Lifecycle. Single owner = no nested-lock hazard.
type Lifecycle struct{}

// NewLifecycle returns a ready-to-use Lifecycle. Stage 2B will accept
// configuration parameters here; the zero-arg form is the Stage 1 shape.
func NewLifecycle() *Lifecycle {
	return &Lifecycle{}
}

// OnBanned marks a relay as banned.
func (lc *Lifecycle) OnBanned(state RelayState) RelayState {
	state.Banned = true
	return state
}

// OnActiveConfirmed marks a relay as confirmed and clears any active failure
// suppression counters.
func (lc *Lifecycle) OnActiveConfirmed(state RelayState) RelayState {
	state.Confirmed = true
	state.activeFailures = 0
	state.suppressActiveUntil = time.Time{}
	return state
}

// OnUnconfirmed clears the Confirmed flag.
func (lc *Lifecycle) OnUnconfirmed(state RelayState) RelayState {
	state.Confirmed = false
	return state
}

// OnDiscoveryConfirmed clears discovery failure counters and the pending
// discovery refresh timer.
func (lc *Lifecycle) OnDiscoveryConfirmed(state RelayState) RelayState {
	state.discoveryFailures = 0
	state.nextDiscoveryRefreshAt = time.Time{}
	return state
}

// OnDiscoveryFailure records a discovery failure and, once the failure budget
// is exhausted, schedules an exponential-backoff refresh delay. It returns the
// updated state, a bool indicating whether a backoff was scheduled, and the
// reason string ("retry" or "discovery").
//
// The err parameter is accepted for interface compatibility and future use
// (e.g., error-type-specific backoff or telemetry); it is not inspected in
// this implementation.
func (lc *Lifecycle) OnDiscoveryFailure(state RelayState, err error, recoveryFailures int) (RelayState, bool, string) {
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

// OnActiveFailure records an active connection failure and, once the failure
// budget is exhausted, schedules an exponential-backoff active suppression.
// It returns the updated state, a bool indicating whether a backoff was
// scheduled, and the reason string ("retry" or "active").
//
// The err parameter is accepted for interface compatibility and future use
// (e.g., error-type-specific backoff or telemetry); it is not inspected in
// this implementation.
func (lc *Lifecycle) OnActiveFailure(state RelayState, err error, recoveryFailures int) (RelayState, bool, string) {
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
