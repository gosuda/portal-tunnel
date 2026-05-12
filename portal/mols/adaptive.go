package mols

import (
	"math"
	"slices"
	"time"
)

// AdaptiveStrategy decides how the candidate pool is classified and partitioned
// before the fixed MOLS scoring step.  A nil strategy on Engine defaults to
// DefaultAdaptiveStrategy.
type AdaptiveStrategy interface {
	// Classify inspects the candidate pool and returns congestion/non-linear flags
	// together with the RTT statistics that produced them.
	Classify(candidates []Candidate, cfg Config) (congested, nonLinear bool, avgRTT time.Duration, cv float64)

	// Partition splits candidates into active and fallback tiers.  If the active
	// tier is smaller than cfg.MinActiveNodes, the healthiest fallbacks are
	// promoted until the minimum is met.
	Partition(candidates []Candidate, cfg Config) (active, fallback []Candidate)

	// SelectMultipliers returns the MOLS multipliers for the current classification.
	SelectMultipliers(nonLinear bool, cfg Config) (m1, m2 uint8)
}

// DefaultAdaptiveStrategy is the built-in adaptive layer shipped with the MOLS
// engine.  It mirrors the historical congestion-grid, variant-grid, fallback-
// demotion and min-active-node-promotion behaviour.
type DefaultAdaptiveStrategy struct{}

func (DefaultAdaptiveStrategy) Classify(candidates []Candidate, cfg Config) (congested, nonLinear bool, avgRTT time.Duration, cv float64) {
	avgRTT, cv = poolRTTStats(candidates)
	congested = avgRTT > cfg.CongestionRTTThreshold
	nonLinear = cv > cfg.CVThreshold
	return
}

func (DefaultAdaptiveStrategy) Partition(candidates []Candidate, cfg Config) (active, fallback []Candidate) {
	active = make([]Candidate, 0, len(candidates))
	fallback = make([]Candidate, 0)

	for _, c := range candidates {
		if isFallback(c, cfg.FallbackRTTThreshold) {
			fallback = append(fallback, c)
		} else {
			active = append(active, c)
		}
	}

	if len(active) < cfg.MinActiveNodes && len(fallback) > 0 {
		slices.SortFunc(fallback, func(a, b Candidate) int {
			if a.RTT < b.RTT {
				return -1
			}
			if a.RTT > b.RTT {
				return 1
			}
			return 0
		})
		promote := min(cfg.MinActiveNodes-len(active), len(fallback))
		active = append(active, fallback[:promote]...)
		fallback = fallback[promote:]
	}
	return
}

func (DefaultAdaptiveStrategy) SelectMultipliers(nonLinear bool, cfg Config) (m1, m2 uint8) {
	if nonLinear {
		return cfg.VariantM1, cfg.VariantM2
	}
	return cfg.BaseM1, cfg.BaseM2
}

// poolRTTStats computes mean RTT and coefficient of variation across candidates
// that carry a non-zero RTTAt.
func poolRTTStats(candidates []Candidate) (mean time.Duration, cv float64) {
	var count int
	var sum float64
	for _, c := range candidates {
		if c.RTTAt.IsZero() {
			continue
		}
		count++
		sum += float64(c.RTT)
	}
	if count == 0 {
		return 0, 0
	}
	avg := sum / float64(count)
	if count == 1 {
		return time.Duration(avg), 0
	}
	var sq float64
	for _, c := range candidates {
		if c.RTTAt.IsZero() {
			continue
		}
		d := float64(c.RTT) - avg
		sq += d * d
	}
	stddev := math.Sqrt(sq / float64(count))
	if avg > 0 {
		cv = stddev / avg
	}
	return time.Duration(avg), cv
}

func isFallback(c Candidate, threshold time.Duration) bool {
	return !c.RTTAt.IsZero() && c.RTT > threshold
}
