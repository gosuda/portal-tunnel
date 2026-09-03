package discovery

// MOLS selection ranks relays on a dynamic NxN MOLS grid sized to the current
// relay pool, with a non-invasive adaptive partition over local load telemetry.
// Multipliers are chosen per grid order so m1, m2, and m1-m2 stay coprime to
// the order; even orders admit no such pair and fall back to a single-square
// (1,1) score, which remains deterministic and duplicate-free per row.
// The grid is rebuilt on every selection from the eligible pool, so a node
// that was evicted or filtered out simply shrinks the grid (N+1 -> N) and the
// remaining indexes are recomputed mechanically; no stale entries can linger.
// Because order := len(autoPool), adding, removing, or filtering a relay recomputes
// all folded indexes and can substantially reshuffle future rankings. This dynamic
// order trade-off ensures zero stale entries without requiring a fixed grid size.
//
// Ordering Pipeline:
//   1. Filter: Apply ban, dead, expiry, and protocol compatibility gates.
//   2. Rank: Order every eligible candidate deterministically with MOLS.
//   3. Partition: Move saturated relays behind active relays.
//   4. Preserve: Keep intra-tier MOLS order unchanged.
import (
	"cmp"
	"math"
	"slices"
	"strconv"
	"time"
)

const (
	molsBaseM1    uint8 = 3
	molsBaseM2    uint8 = 5
	molsVariantM1 uint8 = 7
	molsVariantM2 uint8 = 11

	molsCongestionRTTThreshold = 500 * time.Millisecond
	molsCVThreshold            = 0.6
	molsFallbackRTTThreshold   = 2 * time.Second
	molsMinActiveNodes         = 2
	defaultMaxActiveRelays     = 3
	molsP2CPressureDelta       = 0.3
)

// molsScore computes the MOLS grid score for position (i, j) using multipliers m1 and m2.
func molsScore(i, j, m1, m2, order int) int {
	return ((m1*i+j)%order)*order + ((m2*i + j) % order) + 1
}

// molsPairValid reports whether m1, m2, and m1-m2 are all coprime to order,
// which keeps both linear Latin squares orthogonal at this grid order.
func molsPairValid(order, m1, m2 int) bool {
	gcd := func(a, b int) int {
		if a < 0 {
			a = -a
		}
		for b != 0 {
			a, b = b, a%b
		}
		return a
	}
	return gcd(m1, order) == 1 && gcd(m2, order) == 1 && gcd(m1-m2, order) == 1
}

// molsMultipliers selects per-order multipliers: it prefers the base (or
// variant) constants and otherwise scans for the smallest valid pair. Even
// orders admit no orthogonal pair (all units are odd, so m1-m2 is even); ok is
// false then and callers fall back to the single-square (1,1) score, which
// stays deterministic and duplicate-free per row without MOLS fairness.
func molsMultipliers(order int, variant bool) (m1, m2 int, ok bool) {
	if order%2 == 0 {
		return 1, 1, false
	}
	if variant {
		baseM1, baseM2, baseOK := molsMultipliers(order, false)
		if !baseOK {
			return 1, 1, false
		}
		differsFromBase := func(a, b int) bool {
			return a%order != baseM1%order || b%order != baseM2%order
		}
		p1, p2 := int(molsVariantM1), int(molsVariantM2)
		if molsPairValid(order, p1, p2) && differsFromBase(p1, p2) {
			return p1, p2, true
		}
		for a := 1; a < order; a++ {
			for b := 1; b < order; b++ {
				if a != b && molsPairValid(order, a, b) && differsFromBase(a, b) {
					return a, b, true
				}
			}
		}
		return 1, 1, false
	}

	p1, p2 := int(molsBaseM1), int(molsBaseM2)
	if molsPairValid(order, p1, p2) {
		return p1, p2, true
	}
	for a := 1; a < order; a++ {
		for b := 1; b < order; b++ {
			if a != b && molsPairValid(order, a, b) {
				return a, b, true
			}
		}
	}
	return 1, 1, false
}

// molsCongestionScore inverts the MOLS score to prioritize low-latency relays during congestion.
func molsCongestionScore(i, j, m1, m2, order int) int {
	return (order*order + 1) - molsScore(i, (order-1)-j, m1, m2, order)
}

// hashToGridIndex maps an identity string to a stable FNV-1a hash with a 2nd-stage
// bit-mixing cascade (avalanche diffusion to eliminate clustering). Callers
// fold it into the current grid order with % order; the folded index is not
// stable across orders, so it is recomputed whenever the pool size changes.
func hashToGridIndex(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// molsRTTStats computes the mean RTT and coefficient of variation across relay states.
func molsRTTStats(states []RelayState) (mean time.Duration, cv float64) {
	var count int
	var sum float64
	for _, state := range states {
		if state.DiscoveryRTTAt.IsZero() {
			continue
		}
		count++
		sum += float64(state.effectiveRTT())
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
		d := float64(state.effectiveRTT()) - avg
		sq += d * d
	}
	stddev := math.Sqrt(sq / float64(count))
	if avg > 0 {
		cv = stddev / avg
	}
	return time.Duration(avg), cv
}

// isRelayFallback reports whether the relay's effective RTT exceeds the fallback threshold.
func isRelayFallback(state RelayState) bool {
	return !state.DiscoveryRTTAt.IsZero() && state.effectiveRTT() > molsFallbackRTTThreshold
}

type molsCandidate struct {
	state RelayState
	score int
	seq   int
}

// betterMOLSCandidate reports whether candidate a should be ranked higher than b using MOLS score and tiebreakers.
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

// selectAggregate filters relay states to exclude banned relays.
func selectAggregate(states []RelayState) []RelayState {
	out := make([]RelayState, 0, len(states))
	for _, state := range states {
		if !state.Banned {
			out = append(out, state)
		}
	}
	return out
}

// selectConfirmed filters relay states to include only confirmed relays.
func selectConfirmed(states []RelayState) []RelayState {
	out := make([]RelayState, 0)
	for _, state := range states {
		if state.Confirmed {
			out = append(out, state)
		}
	}
	return out
}

// RankRelayPool ranks the autoPool of relay states using MOLS selection for the given local address and epoch.
// The returned slice contains relay URLs ordered by MOLS-derived priority with saturation partitioning.
func RankRelayPool(autoPool []RelayState, localAddress string, epoch uint64) []string {
	if len(autoPool) == 0 {
		return nil
	}

	avgRTT, cv := molsRTTStats(autoPool)
	congested := avgRTT > molsCongestionRTTThreshold
	nonLinear := cv > molsCVThreshold

	order := len(autoPool)
	m1, m2, _ := molsMultipliers(order, nonLinear)
	ingressKey := localAddress
	if epoch > 0 {
		ingressKey = localAddress + "#" + strconv.FormatUint(epoch, 10)
	}
	ingressRow := int(hashToGridIndex(ingressKey) % uint32(order))

	type relayHash struct {
		url  string
		hash uint32
	}
	sortedRelays := make([]relayHash, order)
	for i, state := range autoPool {
		sortedRelays[i] = relayHash{
			url:  state.Descriptor.APIHTTPSAddr,
			hash: hashToGridIndex(state.Descriptor.APIHTTPSAddr),
		}
	}
	slices.SortFunc(sortedRelays, func(a, b relayHash) int {
		if a.hash != b.hash {
			return cmp.Compare(a.hash, b.hash)
		}
		return cmp.Compare(a.url, b.url)
	})

	relayCols := make(map[string]int, order)
	for col, rh := range sortedRelays {
		relayCols[rh.url] = col
	}

	scoreFor := func(state RelayState) int {
		col := relayCols[state.Descriptor.APIHTTPSAddr]
		if congested {
			return molsCongestionScore(ingressRow, col, m1, m2, order)
		}
		return molsScore(ingressRow, col, m1, m2, order)
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
			aRTT := a.effectiveRTT()
			bRTT := b.effectiveRTT()
			if aRTT < bRTT {
				return -1
			}
			if aRTT > bRTT {
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

		var nonSaturated []molsCandidate
		var saturated []molsCandidate
		for _, candidate := range candidates {
			if candidate.state.IsSaturated {
				saturated = append(saturated, candidate)
			} else {
				nonSaturated = append(nonSaturated, candidate)
			}
		}

		// Pressure-aware partitioning: Candidates with significantly elevated pressure
		// (pressure difference > molsP2CPressureDelta compared to minimum pressure) are
		// demoted behind low-pressure candidates so they are pushed outside the MaxActiveRelays
		// quota, achieving real active-set membership migration.
		if len(nonSaturated) >= 2 {
			minPressure := nonSaturated[0].state.Pressure()
			for _, c := range nonSaturated[1:] {
				if p := c.state.Pressure(); p < minPressure {
					minPressure = p
				}
			}
			var lowPressure []molsCandidate
			var highPressure []molsCandidate
			for _, c := range nonSaturated {
				if c.state.Pressure()-minPressure > molsP2CPressureDelta {
					highPressure = append(highPressure, c)
				} else {
					lowPressure = append(lowPressure, c)
				}
			}
			nonSaturated = append(lowPressure, highPressure...)
		}

		tierOut := make([]string, 0, len(candidates))
		for _, candidate := range nonSaturated {
			tierOut = append(tierOut, candidate.state.Descriptor.APIHTTPSAddr)
		}
		for _, candidate := range saturated {
			tierOut = append(tierOut, candidate.state.Descriptor.APIHTTPSAddr)
		}
		return tierOut
	}

	activeURLs := rankTier(activeStates)
	fallbackURLs := rankTier(fallbackStates)
	return append(activeURLs, fallbackURLs...)
}

// SelectPriority returns the ordered relay URLs for a client using MOLS selection with explicit relays prepended.
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
	auto := RankRelayPool(filterCandidatePool(states, routeState, now, false), routeState.LocalAddress, routeState.SelectionEpoch)
	maxActive := routeState.MaxActiveRelays
	if maxActive <= 0 {
		maxActive = defaultMaxActiveRelays
	}
	auto = applyActiveStickiness(auto, routeState.ActiveRelayURLs, states, maxActive)
	if len(auto) > maxActive {
		auto = auto[:maxActive]
	}
	return append(explicit, auto...)
}

// applyActiveStickiness reorders the ranked candidates so that eligible healthy sticky
// relays occupy the first maxActive positions without dropping remaining pool candidates.
//
// Priority cascade:
//
//	Layer 1: Sticky relays — preserves currently active connections ONLY if they remain in
//	         the healthy tier (not saturated and not in fallback) to avoid zombie resurrection.
//	Layer 2: Warm healthy candidates — fills remaining slots using top-ranked MOLS candidates.
//	Trailing: Remaining ranked candidates are preserved to support multi-hop path building.
func applyActiveStickiness(ranked []string, activeRelayURLs []string, states []RelayState, maxActive int) []string {
	if len(ranked) == 0 || maxActive <= 0 {
		return ranked
	}
	if len(activeRelayURLs) == 0 {
		return ranked
	}

	stateMap := make(map[string]RelayState, len(states))
	for _, s := range states {
		stateMap[s.Descriptor.APIHTTPSAddr] = s
	}

	// Compute baseline minimum pressure among selectable candidates (ranked pool only)
	minPressure := math.MaxFloat64
	for _, u := range ranked {
		if s, ok := stateMap[u]; ok {
			s.EvaluateSaturation()
			if !s.IsSaturated && !isRelayFallback(s) {
				if p := s.Pressure(); p < minPressure {
					minPressure = p
				}
			}
		}
	}

	// Stickiness is ONLY granted to healthy nodes: non-saturated, non-fallback,
	// and without significantly elevated pressure (to allow load-shedding migration).
	activeSet := make(map[string]struct{}, len(activeRelayURLs))
	for _, u := range activeRelayURLs {
		if s, ok := stateMap[u]; ok {
			s.EvaluateSaturation()
			if s.IsSaturated || isRelayFallback(s) {
				continue
			}
			if minPressure != math.MaxFloat64 && s.Pressure()-minPressure > molsP2CPressureDelta {
				continue
			}
			activeSet[u] = struct{}{}
		}
	}

	selected := make([]string, 0, len(ranked))
	// Layer 1: Retain currently active sticky relays that remain healthy (capped at maxActive)
	for _, u := range ranked {
		if _, isActive := activeSet[u]; isActive {
			selected = append(selected, u)
			if len(selected) == maxActive {
				break
			}
		}
	}
	// Layer 2 & Trailing: Append remaining candidates preserving their relative MOLS ranking
	for _, u := range ranked {
		if !slices.Contains(selected, u) {
			selected = append(selected, u)
		}
	}
	return selected
}
