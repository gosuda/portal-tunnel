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
// When m1 and m2 form a valid orthogonal pair, the client's 2D grid coordinates (row, col)
// project target positions across both Latin squares:
//
//	Square 1 (m1): Primary target t1 = (m1*row + col) % order
//	Square 2 (m2): Secondary target t2 = (m2*row + col) % order
//
// Relay column j receives its ranking score via proximity to both targets, ensuring
// that displaced clients disperse across diverse secondary nodes rather than collapsing
// onto a single cyclic successor (herd elimination).
func molsScore(row, col, j, m1, m2, order int, ok bool) int {
	if !ok || order <= 1 {
		return ((m1*row+j)%order)*order + 1
	}
	t1 := (m1*row + col) % order
	t2 := (m2*row + col) % order

	d1 := (j - t1 + order) % order
	d2 := (j - t2 + order) % order

	bonus := 0
	if j == t1 {
		bonus += 2 * order * order
	}
	if j == t2 {
		bonus += order * order
	}
	return bonus + (order-d1)*order + (order - d2) + 1
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
func molsCongestionScore(row, col, j, m1, m2, order int, ok bool) int {
	maxScore := 3*order*order + order*order + order + 1
	return maxScore - molsScore(row, col, (order-1)-j, m1, m2, order, ok)
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
	m1, m2, ok := molsMultipliers(order, nonLinear)
	ingressKey := localAddress
	if epoch > 0 {
		ingressKey = localAddress + "#" + strconv.FormatUint(epoch, 10)
	}
	ingressHash := hashToGridIndex(ingressKey)
	ingressRow := int(ingressHash % uint32(order))
	ingressCol := int((ingressHash >> 16) % uint32(order))

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
			return molsCongestionScore(ingressRow, ingressCol, col, m1, m2, order, ok)
		}
		return molsScore(ingressRow, ingressCol, col, m1, m2, order, ok)
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
			if aRTT != bRTT {
				return cmp.Compare(aRTT, bRTT)
			}
			return cmp.Compare(a.Descriptor.APIHTTPSAddr, b.Descriptor.APIHTTPSAddr)
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

		// P2C pressure optimization:
		// Compare candidate 0 and 1. If p0 - p1 > molsP2CPressureDelta, candidate 0
		// is significantly overloaded. To achieve real load-shedding under active listener
		// quotas (such as the default MaxActiveRelays = 3), candidate 0 yields its active slot
		// and is demoted behind non-saturated candidates, enabling warm reserve candidates
		// to enter the active set while preserving local client-specific MOLS ordering.
		if len(nonSaturated) >= 2 {
			p0 := nonSaturated[0].state.Pressure()
			p1 := nonSaturated[1].state.Pressure()
			if p0-p1 > molsP2CPressureDelta {
				overloaded := nonSaturated[0]
				nonSaturated = append(nonSaturated[1:], overloaded)
			}
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

// Selection Policy Hierarchy (Canonized Invariants):
//
//	Stage 1 - Eligibility: Drop dead, banned, expired, or transport-mismatched relays (filterCandidatePool).
//	Stage 2 - Hard Health Gate: Partition relays into Active vs Fallback tiers (effectiveRTT > 2s).
//	          Saturated relays are demoted behind all non-saturated candidates within each tier.
//	Stage 3 - P2C Pressure Choice: Local comparison between candidate 0 and 1 in the active tier.
//	          If p0 - p1 > molsP2CPressureDelta, swap 0 and 1 to balance surging queues.
//	Stage 4 - Asymmetric Stickiness: Retain currently active listener connections ONLY if they remain in the healthy tier
//	          (non-saturated and non-fallback). Saturated or failing relays are strictly evicted without zombie resurrection.
//	Stage 5 - Deterministic MOLS Geometry: Structural Latin-square spreading acts as the underlying anchor,
//	          with SelectionEpoch salt providing deterministic rotation across connection retry cycles.
//
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

	// Stickiness is ONLY granted to healthy nodes: non-saturated and non-fallback.
	// Degraded/saturated nodes must migrate out rather than being resurrected.
	activeSet := make(map[string]struct{}, len(activeRelayURLs))
	for _, u := range activeRelayURLs {
		if s, ok := stateMap[u]; ok {
			s.EvaluateSaturation()
			if s.IsSaturated || isRelayFallback(s) {
				continue
			}
			activeSet[u] = struct{}{}
		}
	}

	// Active quota boundary: only candidates ranked within the eligible active quota
	// (top maxActive in the ranked pool) can exercise stickiness. Candidates demoted
	// outside the active quota (e.g. by P2C pressure demotion or saturation tiering)
	// cannot be promoted back over healthier candidates.
	quotaLen := min(len(ranked), maxActive)
	eligibleQuota := ranked[:quotaLen]

	selected := make([]string, 0, len(ranked))
	// Layer 1: Retain currently active sticky relays among the eligible quota candidates
	for _, u := range eligibleQuota {
		if _, isActive := activeSet[u]; isActive {
			selected = append(selected, u)
		}
	}
	// Layer 2: Fill remaining quota slots with top-ranked candidates from eligible quota
	for _, u := range eligibleQuota {
		if !slices.Contains(selected, u) {
			selected = append(selected, u)
		}
	}
	// Trailing: Preserve remaining reserve candidates in their ranked order
	selected = append(selected, ranked[quotaLen:]...)
	return selected
}
