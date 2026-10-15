package discovery

import (
	"math"
	"testing"
	"time"
)

func cleanRelayState() RelayState {
	return newRelayState("https://relay.example.com")
}

func TestWeightedScorerCleanStateScoresOne(t *testing.T) {
	scorer := NewReputationScorer()
	now := time.Now().UTC()
	if factor := scorer.Demotion(cleanRelayState(), now); factor != 1 {
		t.Fatalf("clean state factor = %v, want 1", factor)
	}
}

func TestWeightedScorerSignalsLowerFactorMonotonically(t *testing.T) {
	now := time.Now().UTC()
	scorer := NewReputationScorer()

	cases := []struct {
		name  string
		build func(failures int) RelayState
	}{
		{
			name: "active failures",
			build: func(failures int) RelayState {
				state := cleanRelayState()
				state.activeFailures = failures
				return state
			},
		},
		{
			name: "discovery failures",
			build: func(failures int) RelayState {
				state := cleanRelayState()
				state.discoveryFailures = failures
				return state
			},
		},
		{
			name: "suppression",
			build: func(failures int) RelayState {
				state := cleanRelayState()
				state.suppressActiveUntil = now.Add(time.Duration(failures) * time.Minute)
				return state
			},
		},
		{
			name: "unhealthy",
			build: func(failures int) RelayState {
				state := cleanRelayState()
				state.unhealthySince = now.Add(-time.Duration(failures) * time.Minute)
				return state
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev := scorer.Demotion(tc.build(0), now)
			if prev != 1 {
				t.Fatalf("zero-signal factor = %v, want 1", prev)
			}
			for failures := 1; failures <= 10; failures++ {
				factor := scorer.Demotion(tc.build(failures), now)
				if factor >= 1 {
					t.Fatalf("failures=%d factor = %v, want < 1", failures, factor)
				}
				if factor > prev {
					t.Fatalf("failures=%d factor = %v, want <= previous %v", failures, factor, prev)
				}
				prev = factor
			}
		})
	}
}

func TestWeightedScorerNeverReachesZero(t *testing.T) {
	scorer := NewReputationScorer()
	now := time.Now().UTC()
	state := cleanRelayState()
	state.activeFailures = math.MaxInt32
	state.discoveryFailures = math.MaxInt32
	state.suppressActiveUntil = now.Add(365 * 24 * time.Hour)
	state.unhealthySince = now.Add(-365 * 24 * time.Hour)
	factor := scorer.Demotion(state, now)
	if factor <= 0 {
		t.Fatalf("factor = %v, want > 0", factor)
	}
	if factor >= 1 {
		t.Fatalf("factor = %v, want < 1", factor)
	}
}

func TestWeightedScorerWeightsConfineArithmetic(t *testing.T) {
	now := time.Now().UTC()
	state := cleanRelayState()
	state.activeFailures = 1

	defaultScorer := NewReputationScorer()
	heavier := &weightedScorer{
		weights: [signalCount]float64{
			signalActiveFailures:    4.0,
			signalDiscoveryFailures: 1.0,
			signalSuppression:       0.5,
			signalUnhealthy:         0.5,
		},
	}
	base := defaultScorer.Demotion(state, now)
	scaled := heavier.Demotion(state, now)
	if base >= 1 || scaled >= 1 {
		t.Fatalf("factors = %v, %v, want both < 1", base, scaled)
	}
	if scaled >= base {
		t.Fatalf("scaled factor = %v, want < base %v", scaled, base)
	}
}

func TestControllerRelayDemotionUnknownURL(t *testing.T) {
	controller := NewController(nil)
	if factor := controller.RelayDemotion("https://unknown.example.com"); factor != 1 {
		t.Fatalf("unknown URL factor = %v, want 1", factor)
	}
}

func TestControllerRelayDemotionWithFailures(t *testing.T) {
	relayURL := "https://relay.example.com"
	controller := NewController([]string{relayURL})
	if factor := controller.RelayDemotion(relayURL); factor != 1 {
		t.Fatalf("clean bootstrap factor = %v, want 1", factor)
	}
	controller.Report(relayURL, FailureRuntime)
	if factor := controller.RelayDemotion(relayURL); factor >= 1 {
		t.Fatalf("factor after failure report = %v, want < 1", factor)
	}
}
