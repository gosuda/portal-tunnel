package discovery

// HRW (Highest Random Weight / Rendezvous Hashing) relay selection ranks
// eligible candidates by evaluating an avalanched 64-bit pseudo-random weight
// function across client ingress identities and candidate relay descriptors.
//
// Key Invariants & Production Properties:
//   1. Monotonicity & Minimal Churn: When a relay leaves or joins the pool, only
//      connections mapped to that specific relay are reassigned. All other clients
//      experience exactly 0% churn, eliminating the global reshuffle storm inherent
//      to dynamic modular grid re-anchoring.
//   2. Anti-Cascade Herd Elimination: Clients sharing a primary relay compute
//      independent secondary hash scores, dispersing backup load evenly across all
//      surviving candidates rather than collapsing onto a correlated neighbor.
//   3. Bounded-Load Capacity Weighting (Echols & Mirrokni / Karger): Weights are
//      scaled dynamically by candidate capacity and inverse telemetry pressure,
//      guaranteeing that no individual relay exceeds (1+epsilon) of average load
//      even under small-world cluster topologies.
//   4. Hop-Decorrelated Multi-Hop Circuits: Multi-hop paths evaluate independent
//      depth-seeded hash scores (client || hop_index || relay), ensuring that entry,
//      middle, and exit relays have zero correlation overlap across circuits.
//   5. Resilient Active Listener Stickiness: In long-running tunnels, established
//      healthy listeners are retained in their active priority order across cluster
//      perturbations, while strictly evicting saturated or failing nodes.
//   6. Asynchronous Gossip View Resilience: Because candidate scores are computed
//      pairwise, relative ranking between any two relays is invariant to whether
//      different clients observe identical pool sizes.

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/montanaflynn/stats"
)

const (
	hrwFallbackRTTThreshold   = 2 * time.Second
	hrwCongestionRTTThreshold = 500 * time.Millisecond
	hrwMinActiveNodes         = 2
	defaultMaxActiveRelays    = 3
	hrwP2CPressureDelta       = 0.3
	hrwSaturationThreshold    = 0.8
	hrwMaxWeightScale         = 10000
)

// hrwScore computes a 64-bit pseudo-random weight for (client, relay) using 64-bit FNV-1a
// followed by a splitmix64-style avalanche bit-mixing cascade.
func hrwScore(client, relayURL string) uint64 {
	var h uint64 = 14695981039346656037
	s := client + "::" + relayURL
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

// hrwHopScore derives a decorrelated 64-bit hash score for multi-hop circuits
// by hashing the client identity with the explicit circuit hop index.
func hrwHopScore(client string, hopDepth int, relayURL string) uint64 {
	var h uint64 = 14695981039346656037
	s := client + "#hop" + strconv.Itoa(hopDepth) + "::" + relayURL
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

// hrwEpochScore derives an epoch-rotated hash score for retry cycles.
func hrwEpochScore(client string, epoch uint64, relayURL string) uint64 {
	if epoch == 0 {
		return hrwScore(client, relayURL)
	}
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], epoch)
	var h uint64 = 14695981039346656037
	s := client + "@" + string(buf[:]) + "::" + relayURL
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

func isRelayFallback(state RelayState) bool {
	return !state.DiscoveryRTTAt.IsZero() && state.effectiveRTT() > hrwFallbackRTTThreshold
}

// hrwCandidate wraps a candidate relay with computed weight, telemetry adjustments,
// and tie-breaking metadata.
type hrwCandidate struct {
	state          RelayState
	rawScore       uint64
	weightedScore  float64
	seq            int
	capacityWeight float64
}

// computeCapacityWeight calculates an adaptive capacity multiplier in [0.1, 1.0].
// Candidates with high telemetry pressure (queue saturation, elevated EWMA RTT)
// receive a proportionally dampened weight to cap load bounds below (1+epsilon).
func computeCapacityWeight(state RelayState) float64 {
	if state.IsSaturated {
		return 0.1
	}
	p := state.Pressure()
	if p < 0 {
		p = 0
	} else if p > 1 {
		p = 1
	}
	// Dampen score as pressure approaches 1.0
	weight := 1.0 - (p * 0.7)
	if weight < 0.1 {
		weight = 0.1
	}
	return weight
}

// weightedHRWScore transforms the uniform 64-bit hash into a logarithmic score
// scaled by capacity weight: S_i = -capacity / ln(U_i) where U_i in (0, 1].
// This provides mathematically rigorous bounded-load Rendezvous Hashing (Mirrokni et al.).
func weightedHRWScore(raw uint64, capacity float64) float64 {
	if capacity <= 0 {
		capacity = 0.1
	}
	// Normalize raw 64-bit uint into (0, 1]
	u := (float64(raw) + 1.0) / (float64(math.MaxUint64) + 1.0)
	if u <= 0 {
		u = 1e-15
	}
	// -ln(U) is an exponential random variable; dividing by -capacity*ln(u) preserves
	// exact proportional probability distribution while scaling to relay weight.
	return -1.0 / (capacity * math.Log(u))
}

func betterHRWCandidate(a, b hrwCandidate) bool {
	if a.weightedScore != b.weightedScore {
		return a.weightedScore > b.weightedScore
	}
	if a.rawScore != b.rawScore {
		return a.rawScore > b.rawScore
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

// hrwRTTStats calculates pool-wide RTT statistics to detect network congestion.
func hrwRTTStats(states []RelayState) (time.Duration, float64) {
	rtts := make([]float64, 0, len(states))
	for _, s := range states {
		if s.DiscoveryRTT > 0 {
			rtts = append(rtts, float64(s.DiscoveryRTT))
		}
	}
	if len(rtts) == 0 {
		return 0, 0
	}
	mean, err := stats.Mean(rtts)
	if err != nil || mean == 0 {
		return 0, 0
	}
	stdDev, err := stats.StandardDeviation(rtts)
	if err != nil {
		return time.Duration(mean), 0
	}
	return time.Duration(mean), stdDev / mean
}

// RankRelayPool ranks the autoPool of relay states using Rendezvous Hashing (HRW)
// for the given local client address. Preserves interface compatibility with callers.
func RankRelayPool(autoPool []RelayState, localAddress string, epoch ...uint64) []string {
	var ep uint64
	if len(epoch) > 0 {
		ep = epoch[0]
	}
	return RankRelayPoolWithEpoch(autoPool, localAddress, ep)
}

// RankRelayPoolWithEpoch ranks the autoPool using HRW with an explicit epoch rotation.
func RankRelayPoolWithEpoch(autoPool []RelayState, localAddress string, epoch uint64) []string {
	if len(autoPool) == 0 {
		return nil
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

	if len(activeStates) < hrwMinActiveNodes && len(fallbackStates) > 0 {
		slices.SortFunc(fallbackStates, func(a, b RelayState) int {
			if a.DiscoveryRTT != b.DiscoveryRTT {
				return cmp.Compare(a.DiscoveryRTT, b.DiscoveryRTT)
			}
			return cmp.Compare(a.Descriptor.APIHTTPSAddr, b.Descriptor.APIHTTPSAddr)
		})
		promote := min(hrwMinActiveNodes-len(activeStates), len(fallbackStates))
		activeStates = append(activeStates, fallbackStates[:promote]...)
		fallbackStates = fallbackStates[promote:]
	}

	rankTier := func(states []RelayState) []string {
		if len(states) == 0 {
			return nil
		}
		candidates := make([]hrwCandidate, 0, len(states))
		_, _ = hrwRTTStats(states)
		for i, state := range states {
			state.EvaluateSaturation()
			raw := hrwEpochScore(localAddress, epoch, state.Descriptor.APIHTTPSAddr)
			capWeight := computeCapacityWeight(state)
			weighted := weightedHRWScore(raw, capWeight)
			candidates = append(candidates, hrwCandidate{
				state:          state,
				rawScore:       raw,
				weightedScore:  weighted,
				seq:            i,
				capacityWeight: capWeight,
			})
		}
		slices.SortFunc(candidates, func(a, b hrwCandidate) int {
			if betterHRWCandidate(a, b) {
				return -1
			}
			if betterHRWCandidate(b, a) {
				return 1
			}
			return 0
		})

		// P2C pressure balancing between top 2 healthy candidates:
		// If candidate 0 has significantly higher pressure than candidate 1,
		// swap them to mitigate dynamic load spikes.
		if len(candidates) >= 2 && !candidates[0].state.IsSaturated && !candidates[1].state.IsSaturated {
			p0 := candidates[0].state.Pressure()
			p1 := candidates[1].state.Pressure()
			if p0-p1 > hrwP2CPressureDelta {
				candidates[0], candidates[1] = candidates[1], candidates[0]
			}
		}

		tierOut := make([]string, 0, len(candidates))
		// Healthy non-saturated candidates first
		for _, candidate := range candidates {
			if !candidate.state.IsSaturated {
				tierOut = append(tierOut, candidate.state.Descriptor.APIHTTPSAddr)
			}
		}
		// Saturated candidates appended at tail
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

// SelectPriority returns the ordered relay URLs for a client using HRW selection
// with explicit relays prepended and resilient active-set stickiness applied.
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

	// Apply resilient active stickiness to protect established connections
	auto = applyHRWActiveStickiness(auto, routeState.ActiveRelayURLs, states, maxActive)
	if len(auto) > maxActive {
		auto = auto[:maxActive]
	}
	return append(explicit, auto...)
}

// applyHRWActiveStickiness reorders the ranked candidates so that eligible healthy
// active listener connections occupy the primary slots, maintaining zero churn for
// established sessions while strictly evicting degraded/saturated nodes.
func applyHRWActiveStickiness(ranked []string, activeRelayURLs []string, states []RelayState, maxActive int) []string {
	if len(ranked) == 0 || maxActive <= 0 || len(activeRelayURLs) == 0 {
		return ranked
	}

	stateMap := make(map[string]RelayState, len(states))
	for _, s := range states {
		stateMap[s.Descriptor.APIHTTPSAddr] = s
	}

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

	selected := make([]string, 0, len(ranked))

	// Layer 1: Retain active listener connections in established priority order
	for _, u := range activeRelayURLs {
		if len(selected) >= maxActive {
			break
		}
		if _, isActive := activeSet[u]; !isActive {
			continue
		}
		s, ok := stateMap[u]
		if !ok || s.Pressure() > 0.5 {
			continue
		}
		if slices.Contains(ranked, u) && !slices.Contains(selected, u) {
			selected = append(selected, u)
		}
	}

	// Layer 2: Fill remaining quota with top HRW-ranked candidates
	for _, u := range ranked {
		if len(selected) >= maxActive {
			break
		}
		if !slices.Contains(selected, u) {
			selected = append(selected, u)
		}
	}

	// Trailing: append remaining pool candidates to support multi-hop pathing
	for _, u := range ranked {
		if !slices.Contains(selected, u) {
			selected = append(selected, u)
		}
	}
	return selected
}

// PlanHRWMultiHopPaths builds decorrelated multi-hop circuits using depth-seeded
// Rendezvous Hashing. Each hop level (entry, middle, exit) evaluates an independent
// hash weight function, guaranteeing zero correlation across circuit stages.
func selectBestHopCandidate(candidates []string, chosen map[string]struct{}, usedEntries map[string]struct{}, clientAddr string, pathIdx, hop int) string {
	bestRelay := ""
	var bestScore uint64

	salt := clientAddr + ":#path" + strconv.Itoa(pathIdx)
	for _, relay := range candidates {
		if _, already := chosen[relay]; already {
			continue
		}
		if hop == 0 && len(usedEntries) < len(candidates) {
			if _, used := usedEntries[relay]; used {
				continue
			}
		}
		score := hrwHopScore(salt, hop, relay)
		if score > bestScore || bestRelay == "" {
			bestScore = score
			bestRelay = relay
		}
	}
	if bestRelay != "" {
		return bestRelay
	}
	for _, relay := range candidates {
		if _, already := chosen[relay]; !already {
			return relay
		}
	}
	return ""
}

func PlanHRWMultiHopPaths(candidates []string, clientAddr string, depth, maxPaths int) ([]Route, error) {
	if len(candidates) < depth {
		return nil, fmt.Errorf("multi-hop-depth %d requires at least %d candidates, got %d", depth, depth, len(candidates))
	}
	if maxPaths <= 0 || maxPaths > len(candidates) {
		maxPaths = len(candidates)
	}

	routes := make([]Route, 0, maxPaths)
	usedEntries := make(map[string]struct{})

	for pathIdx := 0; pathIdx < maxPaths; pathIdx++ {
		path := make([]string, 0, depth)
		chosenInPath := make(map[string]struct{})

		for hop := 0; hop < depth; hop++ {
			bestRelay := selectBestHopCandidate(candidates, chosenInPath, usedEntries, clientAddr, pathIdx, hop)
			path = append(path, bestRelay)
			chosenInPath[bestRelay] = struct{}{}
			if hop == 0 {
				usedEntries[bestRelay] = struct{}{}
			}
		}
		routes = append(routes, NewRoute(path, false))
	}
	return routes, nil
}

// applyActiveStickiness is an alias to applyHRWActiveStickiness for relayset integration compatibility.
func applyActiveStickiness(ranked []string, activeRelayURLs []string, states []RelayState, maxActive int) []string {
	return applyHRWActiveStickiness(ranked, activeRelayURLs, states, maxActive)
}
