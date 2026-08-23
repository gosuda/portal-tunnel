package discovery

// MOLS selection ranks relays on an NxN MOLS grid sized to the current relay
// pool, with a non-invasive adaptive partition over local load telemetry.
// The grid is rebuilt on every selection from the eligible pool, so a node
// that was evicted or filtered out simply shrinks the grid (N+1 -> N) and the
// remaining indexes are recomputed mechanically; no stale entries can linger.
//
// Ordering Pipeline:
//   1. Filter: Apply ban, dead, expiry, and protocol compatibility gates.
//   2. Rank: Order every eligible candidate deterministically with MOLS.
//   3. Partition: Move saturated relays behind active relays.
//   4. Preserve: Keep intra-tier MOLS order unchanged.
import (
	"math"
	"slices"
	"time"
)

const (
	molsBaseM1    uint8 = 3
	molsBaseM2    uint8 = 5
	molsVariantM1 uint8 = 7
	molsVariantM2 uint8 = 11

	molsCongestionRTTThreshold = 500 * time.Millisecond
	molsCVThreshold            = 0.5
	molsFallbackRTTThreshold   = 2 * time.Second
	molsMinActiveNodes         = 2
	defaultMaxActiveRelays     = 3
)

func molsScore(i, j, m1, m2, order int) int {
	return ((m1*i+j)%order)*order + ((m2*i + j) % order) + 1
}

func molsCongestionScore(i, j, m1, m2, order int) int {
	return (order*order + 1) - molsScore(i, (order-1)-j, m1, m2, order)
}

// hashToGridIndex maps an identity string to an FNV-1a hash. Callers fold it
// into the current grid order with % order, so the same identity keeps a
// stable index as the grid grows or shrinks with the pool.
func hashToGridIndex(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

func molsRTTStats(states []RelayState) (mean time.Duration, cv float64) {
	var count int
	var sum float64
	for _, state := range states {
		if state.DiscoveryRTTAt.IsZero() {
			continue
		}
		count++
		sum += float64(state.DiscoveryRTT)
	}
	if count == 0 {
		return 0, 0
	}
	avg := sum / float64(count)
	if count == 1 {
		return time.Duration(avg), 0
	}
	var sq float64
	for _, state := range states {
		if state.DiscoveryRTTAt.IsZero() {
			continue
		}
		d := float64(state.DiscoveryRTT) - avg
		sq += d * d
	}
	stddev := math.Sqrt(sq / float64(count))
	if avg > 0 {
		cv = stddev / avg
	}
	return time.Duration(avg), cv
}

func isRelayFallback(state RelayState) bool {
	return !state.DiscoveryRTTAt.IsZero() && state.DiscoveryRTT > molsFallbackRTTThreshold
}

type molsCandidate struct {
	state RelayState
	score int
	seq   int
}

func betterMOLSCandidate(a, b molsCandidate) bool {
	if a.score != b.score {
		return a.score > b.score
	}
	if a.state.Confirmed != b.state.Confirmed {
		return a.state.Confirmed
	}
	aURL := a.state.Descriptor.APIHTTPSAddr
	bURL := b.state.Descriptor.APIHTTPSAddr
	if aURL != bURL {
		return aURL < bURL
	}
	return a.seq < b.seq
}

func selectAggregate(states []RelayState) []RelayState {
	out := make([]RelayState, 0, len(states))
	for _, state := range states {
		if !state.Banned {
			out = append(out, state)
		}
	}
	return out
}

func selectConfirmed(states []RelayState) []RelayState {
	out := make([]RelayState, 0)
	for _, state := range states {
		if state.Confirmed {
			out = append(out, state)
		}
	}
	return out
}

func RankRelayPool(autoPool []RelayState, localAddress string) []string {
	if len(autoPool) == 0 {
		return nil
	}

	avgRTT, cv := molsRTTStats(autoPool)
	congested := avgRTT > molsCongestionRTTThreshold
	nonLinear := cv > molsCVThreshold

	m1, m2 := molsBaseM1, molsBaseM2
	if nonLinear {
		m1, m2 = molsVariantM1, molsVariantM2
	}

	order := len(autoPool)
	ingressRow := int(hashToGridIndex(localAddress) % uint32(order))
	scoreFor := func(state RelayState) int {
		col := int(hashToGridIndex(state.Descriptor.APIHTTPSAddr) % uint32(order))
		if congested {
			return molsCongestionScore(ingressRow, col, int(m1), int(m2), order)
		}
		return molsScore(ingressRow, col, int(m1), int(m2), order)
	}

	activeStates := make([]RelayState, 0, len(autoPool))
	fallbackStates := make([]RelayState, 0)
	for _, state := range autoPool {
		if isRelayFallback(state) {
			fallbackStates = append(fallbackStates, state)
		} else {
			activeStates = append(activeStates, state)
		}
	}

	if len(activeStates) < molsMinActiveNodes && len(fallbackStates) > 0 {
		slices.SortFunc(fallbackStates, func(a, b RelayState) int {
			if a.DiscoveryRTT < b.DiscoveryRTT {
				return -1
			}
			if a.DiscoveryRTT > b.DiscoveryRTT {
				return 1
			}
			return 0
		})
		promote := min(molsMinActiveNodes-len(activeStates), len(fallbackStates))
		activeStates = append(activeStates, fallbackStates[:promote]...)
		fallbackStates = fallbackStates[promote:]
	}

	rankTier := func(states []RelayState) []string {
		if len(states) == 0 {
			return nil
		}
		candidates := make([]molsCandidate, 0, len(states))
		for i, state := range states {
			state.EvaluateSaturation()
			candidates = append(candidates, molsCandidate{
				state: state,
				score: scoreFor(state),
				seq:   i,
			})
		}
		slices.SortFunc(candidates, func(a, b molsCandidate) int {
			if betterMOLSCandidate(a, b) {
				return -1
			}
			if betterMOLSCandidate(b, a) {
				return 1
			}
			return 0
		})

		tierOut := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			if !candidate.state.IsSaturated {
				tierOut = append(tierOut, candidate.state.Descriptor.APIHTTPSAddr)
			}
		}
		for _, candidate := range candidates {
			if candidate.state.IsSaturated {
				tierOut = append(tierOut, candidate.state.Descriptor.APIHTTPSAddr)
			}
		}
		return tierOut
	}

	activeURLs := rankTier(activeStates)
	fallbackURLs := rankTier(fallbackStates)
	return append(activeURLs, fallbackURLs...)
}

// SelectPriority returns the ordered relay URLs for a client using MOLS selection.
func SelectPriority(states []RelayState, routeState RouteState) []string {
	if len(states) == 0 {
		return nil
	}
	now := time.Now().UTC()
	explicit := make([]string, 0, len(routeState.ExplicitRelayURLs))
	for _, state := range states {
		relayURL := state.Descriptor.APIHTTPSAddr
		if state.Banned || !slices.Contains(routeState.ExplicitRelayURLs, relayURL) {
			continue
		}
		if !state.supportsRequiredTransports(routeState, now) {
			continue
		}
		explicit = append(explicit, relayURL)
	}
	auto := RankRelayPool(filterCandidatePool(states, routeState, now, false), routeState.LocalAddress)
	maxActive := routeState.MaxActiveRelays
	if maxActive <= 0 {
		maxActive = defaultMaxActiveRelays
	}
	if len(auto) > maxActive {
		auto = auto[:maxActive]
	}
	return append(explicit, auto...)
}
