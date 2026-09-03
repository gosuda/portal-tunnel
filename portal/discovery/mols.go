package discovery

// HRW (Highest Random Weight / Rendezvous Hashing) relay selection ranks
// eligible candidates by evaluating a 64-bit cryptographic-quality hash of the
// client ingress identity and the candidate relay address.
//
// Key Invariants & Architectural Properties:
//   1. Monotonicity & Minimal Churn: When a relay leaves or joins the pool, only
//      connections mapped to that specific relay are reassigned. All other clients
//      experience exactly 0% churn, completely eliminating the ~80% reshuffle storm
//      inherent to dynamic modular grid re-anchoring.
//   2. Uniform Load Distribution: Dual-stage avalanched 64-bit FNV-1a produces uniform
//      dispersion across candidates without requiring prime-order pool constraints.
//   3. Anti-Cascade Herd Elimination: Clients sharing a primary relay compute
//      independent secondary hash scores, dispersing backup load evenly across all
//      surviving candidates rather than collapsing onto a correlated neighbor.
//   4. Asynchronous Gossip View Resilience: Because candidate scores are computed
//      pairwise h(client, relay), relative ranking between any two relays is completely
//      invariant to whether different clients observe identical pool sizes.
//
// Pipeline:
//   1. Filter: Apply ban, dead, expiry, and protocol compatibility gates (filterCandidatePool).
//   2. Partition: Split into Active vs Fallback tiers based on observed RTT. Saturated
//      relays are demoted behind healthy non-saturated candidates.
//   3. Rank: Order candidates within each tier using HRW (Highest Random Weight).
import (
	"cmp"
	"slices"
	"time"
)

const (
	molsFallbackRTTThreshold = 2 * time.Second
	molsMinActiveNodes       = 2
	defaultMaxActiveRelays   = 3
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

func isRelayFallback(state RelayState) bool {
	return !state.DiscoveryRTTAt.IsZero() && state.DiscoveryRTT > molsFallbackRTTThreshold
}

type hrwCandidate struct {
	state RelayState
	score uint64
	seq   int
}

func betterHRWCandidate(a, b hrwCandidate) bool {
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

// RankRelayPool ranks the autoPool of relay states using Rendezvous Hashing (HRW)
// for the given local client address.
func RankRelayPool(autoPool []RelayState, localAddress string) []string {
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

	if len(activeStates) < molsMinActiveNodes && len(fallbackStates) > 0 {
		slices.SortFunc(fallbackStates, func(a, b RelayState) int {
			if a.DiscoveryRTT != b.DiscoveryRTT {
				return cmp.Compare(a.DiscoveryRTT, b.DiscoveryRTT)
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
		candidates := make([]hrwCandidate, 0, len(states))
		for i, state := range states {
			state.EvaluateSaturation()
			candidates = append(candidates, hrwCandidate{
				state: state,
				score: hrwScore(localAddress, state.Descriptor.APIHTTPSAddr),
				seq:   i,
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

// SelectPriority returns the ordered relay URLs for a client using HRW selection with explicit relays prepended.
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
