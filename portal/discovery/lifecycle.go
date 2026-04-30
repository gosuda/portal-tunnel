package discovery

import (
	"math"
	"time"
)

// Lifecycle owns policy-agnostic relay state transitions: bans, confirmation,
// discovery and active failure tracking, suppression bookkeeping, and EWMA
// load-surface updates.
//
// Concurrency: Lifecycle methods are not internally synchronized. All On*
// methods must be called with the owning RelaySet.mu write lock already held.
// EWMA fields must follow this same discipline; do NOT add an internal mutex
// to Lifecycle. Single owner = no nested-lock hazard.
//
// # EWMA design note — shared LastUpdated
//
// RelayState carries a single LastUpdated timestamp shared by both LoadFactor
// and FailureRate. Because the two rates use different time constants (loadTau
// and failureTau), every method that touches either EWMA field decays BOTH
// fields consistently before applying its additive update. This eliminates the
// coupling hazard where a failure event would shorten the effective load-decay
// interval (or vice versa): each field always decays from the most recent
// observed wall-clock time, regardless of which event triggered the update.
type Lifecycle struct {
	loadTau     time.Duration // EWMA time constant for LoadFactor
	failureTau  time.Duration // EWMA time constant for FailureRate
	failureBeta float64       // multiplier on FailureRate when composing LoadFactor
}

const (
	// defaultLoadTau is the EWMA time constant for LoadFactor.
	// At dt == defaultLoadTau the decay factor is e^(-1) ≈ 0.368.
	defaultLoadTau = 30 * time.Second

	// defaultFailureTau is the EWMA time constant for FailureRate.
	defaultFailureTau = 60 * time.Second

	// defaultFailureBeta is the multiplier on FailureRate when composing
	// LoadFactor (composed LoadFactor = load_sample + failure_rate * beta).
	defaultFailureBeta = 1.0
)

// LifecycleConfig holds optional overrides for EWMA parameters. Zero values
// fall back to package defaults, so existing callers that pass a zero-value
// config get identical behaviour to NewLifecycle().
type LifecycleConfig struct {
	// LoadTau overrides the EWMA time constant for LoadFactor.
	// Zero uses defaultLoadTau (30s).
	LoadTau time.Duration

	// FailureTau overrides the EWMA time constant for FailureRate.
	// Zero uses defaultFailureTau (60s).
	FailureTau time.Duration

	// FailureBeta overrides the multiplier on FailureRate when composing
	// LoadFactor. Zero uses defaultFailureBeta (1.0).
	FailureBeta float64
}

// NewLifecycle returns a ready-to-use Lifecycle with default EWMA parameters.
func NewLifecycle() *Lifecycle {
	return NewLifecycleWithConfig(LifecycleConfig{})
}

// NewLifecycleWithConfig returns a Lifecycle with the given EWMA configuration.
// Zero fields in cfg fall back to package defaults.
func NewLifecycleWithConfig(cfg LifecycleConfig) *Lifecycle {
	lc := &Lifecycle{
		loadTau:     cfg.LoadTau,
		failureTau:  cfg.FailureTau,
		failureBeta: cfg.FailureBeta,
	}
	if lc.loadTau <= 0 {
		lc.loadTau = defaultLoadTau
	}
	if lc.failureTau <= 0 {
		lc.failureTau = defaultFailureTau
	}
	if lc.failureBeta == 0 {
		lc.failureBeta = defaultFailureBeta
	}
	return lc
}

// ewmaDecay returns the EWMA decay factor for a time delta dt and time
// constant tau.
//
// EWMA update math:
//
//	dt := now.Sub(state.LastUpdated)
//	if dt < 0 || state.LastUpdated.IsZero() { dt = 0 }  // first sample: no decay
//	decay = exp(−dt / tau)
//	state.Field = state.Field*decay + sample
//	state.LastUpdated = now
//
// tau is the time constant: at dt == tau, decay == e^(-1) ≈ 0.368. NOT half-life.
func ewmaDecay(dt, tau time.Duration) float64 {
	if tau <= 0 {
		return 0
	}
	return math.Exp(-float64(dt) / float64(tau))
}

// normalizeEWMADt clamps dt for use in EWMA calculations: if the previous
// timestamp is zero (first sample) or dt is negative (clock skew), return 0
// so that no decay is applied.
func normalizeEWMADt(lastUpdated, now time.Time) time.Duration {
	if lastUpdated.IsZero() {
		return 0
	}
	dt := now.Sub(lastUpdated)
	if dt < 0 {
		return 0
	}
	return dt
}

// decayBoth applies EWMA decay to both LoadFactor and FailureRate using their
// respective time constants and the shared dt derived from state.LastUpdated.
// It does NOT add any sample — the caller must add the appropriate sample
// value after calling this helper. LastUpdated is NOT updated here; the caller
// must set it to now.
func (lc *Lifecycle) decayBoth(state RelayState, now time.Time) RelayState {
	dt := normalizeEWMADt(state.LastUpdated, now)
	state.LoadFactor = state.LoadFactor * ewmaDecay(dt, lc.loadTau)
	state.FailureRate = state.FailureRate * ewmaDecay(dt, lc.failureTau)
	return state
}

// SampleLoad applies an EWMA update for an active-tunnel load sample. The
// sample is typically (active_tunnels / pool_avg) at the time of the event;
// callers may also pass a fixed value such as 1.0 per tunnel event when a
// normalized rate is not available.
//
// Both LoadFactor and FailureRate are decayed from LastUpdated before the
// sample is applied, so that neither field's decay is corrupted by the
// other's update path. The LoadFactor update is:
//
//	state.LoadFactor = state.LoadFactor*loadDecay + sample
//
// FailureBeta is NOT folded into the stored LoadFactor here. Selectors and
// other read-time consumers that want the composed value should evaluate
//
//	state.LoadFactor + state.FailureRate*lc.FailureBeta()
//
// at the time of use. This keeps the stored EWMA fields independent and
// avoids compounding failure contributions across updates.
//
// If state.LastUpdated is zero (first sample) no decay is applied.
//
// The caller must hold RelaySet.mu as a write lock.
//
// Returns the updated state.
func (lc *Lifecycle) SampleLoad(state RelayState, sample float64, now time.Time) RelayState {
	state = lc.decayBoth(state, now)
	state.LoadFactor += sample
	state.LastUpdated = now
	return state
}

// FailureBeta returns the configured multiplier for composing FailureRate into
// an effective load score at read time:
//
//	effectiveLoad = state.LoadFactor + state.FailureRate*lc.FailureBeta()
func (lc *Lifecycle) FailureBeta() float64 {
	return lc.failureBeta
}

// OnSuccess decays both FailureRate and LoadFactor toward zero and refreshes
// LastUpdated. A zero-sample EWMA step is applied to FailureRate (no additive
// bump), so the rate decays by exp(-dt/failureTau) without adding new failure
// contribution. LoadFactor is also decayed for consistency (same LastUpdated).
//
// The caller must hold RelaySet.mu as a write lock.
func (lc *Lifecycle) OnSuccess(state RelayState) RelayState {
	now := time.Now().UTC()
	state = lc.decayBoth(state, now)
	// No additive bump to either field — pure decay step.
	state.LastUpdated = now
	return state
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
// In addition to the existing backoff logic, both FailureRate and LoadFactor
// are decayed from LastUpdated and then FailureRate is bumped by 1.0 (EWMA
// sample = 1.0). This is additive to the backoff path and does not affect the
// returned bool or string.
//
// The err parameter is accepted for interface compatibility and future use
// (e.g., error-type-specific backoff or telemetry); it is not inspected in
// this implementation.
func (lc *Lifecycle) OnDiscoveryFailure(state RelayState, err error, recoveryFailures int) (RelayState, bool, string) {
	state.discoveryFailures++

	// Decay both EWMAs from the shared LastUpdated, then bump FailureRate.
	now := time.Now().UTC()
	state = lc.decayBoth(state, now)
	state.FailureRate += 1.0
	state.LastUpdated = now

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
// In addition to the existing backoff logic, both FailureRate and LoadFactor
// are decayed from LastUpdated and then FailureRate is bumped by 1.0 (EWMA
// sample = 1.0). This is additive to the backoff path and does not affect the
// returned bool or string.
//
// The err parameter is accepted for interface compatibility and future use
// (e.g., error-type-specific backoff or telemetry); it is not inspected in
// this implementation.
func (lc *Lifecycle) OnActiveFailure(state RelayState, err error, recoveryFailures int) (RelayState, bool, string) {
	state.activeFailures++

	// Decay both EWMAs from the shared LastUpdated, then bump FailureRate.
	now := time.Now().UTC()
	state = lc.decayBoth(state, now)
	state.FailureRate += 1.0
	state.LastUpdated = now

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
