package discovery

import "time"

// ReputationScorer converts observed relay behavior into a demotion factor
// for tunnel allocation. Signal kinds, their weights, and the combining
// arithmetic are implementation details of the scorer; consumers only see
// the factor. This keeps every tuning decision in one owner.
type ReputationScorer interface {
	// Demotion returns a factor in (0, 1]: 1 means full allocation, values
	// below 1 scale the number of tunnels opened toward the relay down.
	// A clean history scores 1; accumulating failures lower the factor
	// gradually, so a degrading relay loses capacity before it loses
	// membership. The factor never reaches 0 here — zero allocation is the
	// exclusion path's decision, not the scorer's.
	Demotion(state RelayState, now time.Time) float64
}

// reputationSignal enumerates the failure-derived inputs the weighted scorer
// combines. Signals are strictly reputation-shaped: QoS observations (RTT,
// pressure) belong to MOLS ranking and are deliberately not inputs here.
type reputationSignal int

const (
	signalActiveFailures reputationSignal = iota
	signalDiscoveryFailures
	signalSuppression
	signalUnhealthy
	signalCount
)

const (
	// activeFailureScale: three active failures — one full suppression
	// cycle's worth — saturate the signal.
	activeFailureScale = 3.0
	// discoveryFailureScale: three unanswered discovery probes saturate the
	// signal, matching the retry budget before backoff.
	discoveryFailureScale = 3.0
	// suppressionScale: the maximum active-failure backoff (5 minutes) maps
	// to a fully saturated remaining-suppression signal.
	suppressionScale = 5 * time.Minute
	// unhealthyScale: half an hour without a successful discovery response
	// saturates the unhealthiness signal.
	unhealthyScale = 30 * time.Minute
)

// weightedScorer combines the normalized signal contributions into a
// demotion factor with one weight per signal. All tuning lives here.
type weightedScorer struct {
	weights [signalCount]float64
}

// NewReputationScorer returns the default weighted reputation scorer.
func NewReputationScorer() ReputationScorer {
	return &weightedScorer{
		weights: [signalCount]float64{
			signalActiveFailures:    1.0,
			signalDiscoveryFailures: 1.0,
			signalSuppression:       0.5,
			signalUnhealthy:         0.5,
		},
	}
}

func (s *weightedScorer) Demotion(state RelayState, now time.Time) float64 {
	contributions := [signalCount]float64{
		signalActiveFailures:    min(float64(state.activeFailures)/activeFailureScale, 1),
		signalDiscoveryFailures: min(float64(state.discoveryFailures)/discoveryFailureScale, 1),
		signalSuppression:       suppressedFraction(state, now),
		signalUnhealthy:         unhealthyFraction(state, now),
	}
	sum := 0.0
	for signal := range contributions {
		sum += s.weights[signal] * contributions[signal]
	}
	return 1 / (1 + sum)
}

// suppressedFraction is the remaining fraction of an active-failure
// suppression window, or 0 when the relay is not currently suppressed.
func suppressedFraction(state RelayState, now time.Time) float64 {
	if state.suppressActiveUntil.IsZero() || !state.suppressActiveUntil.After(now) {
		return 0
	}
	return min(state.suppressActiveUntil.Sub(now).Seconds()/suppressionScale.Seconds(), 1)
}

// unhealthyFraction is how long the relay has gone without a successful
// discovery response, normalized, or 0 when no unhealthiness is retained.
func unhealthyFraction(state RelayState, now time.Time) float64 {
	if state.unhealthySince.IsZero() || !now.After(state.unhealthySince) {
		return 0
	}
	return min(now.Sub(state.unhealthySince).Seconds()/unhealthyScale.Seconds(), 1)
}
