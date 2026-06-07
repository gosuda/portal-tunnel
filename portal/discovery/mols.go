package discovery

// MOLS selection ranks relays using a GF(64)-based MOLS grid with a
// non-invasive adaptive partition over local load telemetry.
//
// Ordering Pipeline:
//   1. Filter: Apply ban, expiry, and protocol compatibility gates.
//   2. Extract: Keep the top fixed-depth deterministic MOLS candidates.
//   3. Partition: Move saturated relays behind active relays.
//   4. Preserve: Keep intra-tier MOLS order unchanged.
import (
	"math"
	"slices"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/telemetry"
)

const (
	molsOrder         = 64
	molsMagicConstant = molsOrder*molsOrder + 1 // n^2+1 = 4097

	molsBaseM1    uint8 = 3
	molsBaseM2    uint8 = 5
	molsVariantM1 uint8 = 7
	molsVariantM2 uint8 = 11

	molsCongestionRTTThreshold = 500 * time.Millisecond
	molsCVThreshold            = 0.5
	molsFallbackRTTThreshold   = 2 * time.Second
	molsMinActiveNodes         = 2
	defaultMaxActiveRelays     = 3
	molsCandidateDepth         = 8
)

// gf64Mul performs multiplication in GF(2^6) with primitive polynomial x^6 + x + 1 (0x43).
func gf64Mul(a, b uint8) uint8 {
	a &= 0x3f
	b &= 0x3f
	var r uint8
	for b != 0 {
		if b&1 != 0 {
			r ^= a
		}
		if a&0x20 != 0 {
			a = ((a << 1) ^ 0x43) & 0x3f
		} else {
			a = (a << 1) & 0x3f
		}
		b >>= 1
	}
	return r
}

// gridOrderForSize returns the smallest supported MOLS grid order that can
// accommodate the relay pool size.
func gridOrderForSize(poolSize int) int {
	if poolSize <= molsOrder {
		return molsOrder
	}
	rem := poolSize % 32
	if rem == 0 {
		return poolSize
	}
	return poolSize + (32 - rem)
}

func molsScore(i, j, m1, m2, order int) int {
	if order == molsOrder {
		l1 := gf64Mul(uint8(m1), uint8(i)) ^ uint8(j)
		l2 := gf64Mul(uint8(m2), uint8(i)) ^ uint8(j)
		return int(l1)*order + int(l2) + 1
	}
	return ((m1*i+j)%order)*order + ((m2*i + j) % order) + 1
}

func molsCongestionScore(i, j, m1, m2, order int) int {
	return (order*order + 1) - molsScore(i, (order-1)-j, m1, m2, order)
}

func hashToGF64(s string) uint8 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return uint8(h & 0x3f)
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

	ingressIdx := hashToGF64(localAddress)
	avgRTT, cv := molsRTTStats(autoPool)
	congested := avgRTT > molsCongestionRTTThreshold
	nonLinear := cv > molsCVThreshold

	m1, m2 := molsBaseM1, molsBaseM2
	if nonLinear {
		m1, m2 = molsVariantM1, molsVariantM2
	}

	order := gridOrderForSize(len(autoPool))
	scoreFor := func(state RelayState) int {
		candidateIdx := hashToGF64(state.Descriptor.APIHTTPSAddr)
		row := int(ingressIdx) % order
		col := int(candidateIdx) % order
		if congested {
			return molsCongestionScore(row, col, int(m1), int(m2), order)
		}
		return molsScore(row, col, int(m1), int(m2), order)
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
		var candidates [molsCandidateDepth]molsCandidate
		count := 0
		for i, state := range states {
			state.EvaluateSaturation()
			candidate := molsCandidate{
				state: state,
				score: scoreFor(state),
				seq:   i,
			}
			insertAt := count
			for insertAt > 0 && betterMOLSCandidate(candidate, candidates[insertAt-1]) {
				if insertAt < molsCandidateDepth {
					candidates[insertAt] = candidates[insertAt-1]
				}
				insertAt--
			}
			if insertAt >= molsCandidateDepth {
				continue
			}
			candidates[insertAt] = candidate
			if count < molsCandidateDepth {
				count++
			}
		}

		tierOut := make([]string, 0, count)
		for i := 0; i < count; i++ {
			if !candidates[i].state.IsSaturated {
				tierOut = append(tierOut, candidates[i].state.Descriptor.APIHTTPSAddr)
			}
		}
		for i := 0; i < count; i++ {
			if candidates[i].state.IsSaturated {
				tierOut = append(tierOut, candidates[i].state.Descriptor.APIHTTPSAddr)
			}
		}
		return tierOut
	}

	activeURLs := rankTier(activeStates)
	fallbackURLs := rankTier(fallbackStates)
	return append(activeURLs, fallbackURLs...)
}

// selectPriorityWithTrace is the telemetry-instrumented sibling of
// SelectPriority. It returns the same ordered relay list plus a SelectionTrace.
func selectPriorityWithTrace(states []RelayState, cs RouteState) ([]string, telemetry.SelectionTrace) {
	start := time.Now()
	now := start.UTC()

	trace := telemetry.SelectionTrace{
		Timestamp:  start,
		ClientHash: hashToGF64(cs.LocalAddress),
		Mode:       "priority",
		PoolTotal:  len(states),
		Reasons:    make(map[string]string),
	}

	for _, state := range states {
		if state.Banned {
			url := state.Descriptor.APIHTTPSAddr
			trace.Suppressed = append(trace.Suppressed, url)
			trace.Reasons[url] = "banned"
		}
	}

	selected := selectAggregate(states)
	if len(selected) == 0 {
		trace.SelectionTook = time.Since(start)
		return nil, trace
	}

	explicit := make([]string, 0)
	autoPool := make([]RelayState, 0, len(selected))
	for _, state := range selected {
		relayURL := state.Descriptor.APIHTTPSAddr
		if slices.Contains(cs.ExplicitRelayURLs, relayURL) {
			if state.hasObservedDescriptor() && state.Descriptor.ExpiresAt.After(now) {
				if cs.RequireUDP && !state.Descriptor.SupportsUDP {
					trace.Suppressed = append(trace.Suppressed, relayURL)
					trace.Reasons[relayURL] = "require_udp"
					continue
				}
				if cs.RequireTCP && !state.Descriptor.SupportsTCP {
					trace.Suppressed = append(trace.Suppressed, relayURL)
					trace.Reasons[relayURL] = "require_tcp"
					continue
				}
			}
			explicit = append(explicit, relayURL)
			continue
		}
		if state.hasObservedDescriptor() {
			if !state.Descriptor.ExpiresAt.After(now) {
				trace.Suppressed = append(trace.Suppressed, relayURL)
				trace.Reasons[relayURL] = "expired"
				continue
			}
			if cs.RequireUDP && !state.Descriptor.SupportsUDP {
				trace.Suppressed = append(trace.Suppressed, relayURL)
				trace.Reasons[relayURL] = "require_udp"
				continue
			}
			if cs.RequireTCP && !state.Descriptor.SupportsTCP {
				trace.Suppressed = append(trace.Suppressed, relayURL)
				trace.Reasons[relayURL] = "require_tcp"
				continue
			}
		}
		if !state.suppressActiveUntil.IsZero() && state.suppressActiveUntil.After(now) {
			trace.Suppressed = append(trace.Suppressed, relayURL)
			trace.Reasons[relayURL] = "suppressed"
			continue
		}
		autoPool = append(autoPool, state)
	}

	avgRTT, cv := molsRTTStats(autoPool)
	trace.AvgRTT = avgRTT
	trace.CV = cv
	congested := avgRTT > molsCongestionRTTThreshold
	nonLinear := cv > molsCVThreshold
	trace.Congested = congested
	trace.NonLinear = nonLinear

	m1, m2 := molsBaseM1, molsBaseM2
	if nonLinear {
		m1, m2 = molsVariantM1, molsVariantM2
	}
	trace.M1, trace.M2 = m1, m2

	active, fallbacks := traceFallbackPartition(autoPool)
	trace.PoolEligible = len(autoPool)
	trace.PoolFallback = len(fallbacks)
	if len(active) < molsMinActiveNodes && len(fallbacks) > 0 {
		promote := min(molsMinActiveNodes-len(active), len(fallbacks))
		fallbacks = fallbacks[promote:]
	}
	demotedURLs := relayURLSet(fallbacks)

	ingressIdx := hashToGF64(cs.LocalAddress)
	order := gridOrderForSize(len(autoPool))
	for _, state := range autoPool {
		candidateIdx := hashToGF64(state.Descriptor.APIHTTPSAddr)
		row := int(ingressIdx) % order
		col := int(candidateIdx) % order
		score := molsScore(row, col, int(m1), int(m2), order)
		if congested {
			score = molsCongestionScore(row, col, int(m1), int(m2), order)
		}
		trace.Ranked = append(trace.Ranked, telemetry.TraceEntry{
			URL:       state.Descriptor.APIHTTPSAddr,
			Score:     score,
			Confirmed: state.Confirmed,
			RTT:       state.DiscoveryRTT,
			Demoted:   demotedURLs[state.Descriptor.APIHTTPSAddr],
		})
	}

	autoURLs := RankRelayPool(autoPool, cs.LocalAddress)
	maxActiveRelays := cs.MaxActiveRelays
	if maxActiveRelays <= 0 {
		maxActiveRelays = defaultMaxActiveRelays
	}
	if len(autoURLs) > maxActiveRelays {
		autoURLs = autoURLs[:maxActiveRelays]
	}
	result := append(explicit, autoURLs...)
	trace.OutputURLs = result
	trace.SelectionTook = time.Since(start)
	return result, trace
}

func traceFallbackPartition(autoPool []RelayState) ([]RelayState, []RelayState) {
	active := make([]RelayState, 0, len(autoPool))
	fallbacks := make([]RelayState, 0)
	for _, state := range autoPool {
		if isRelayFallback(state) {
			fallbacks = append(fallbacks, state)
		} else {
			active = append(active, state)
		}
	}
	return active, fallbacks
}

func relayURLSet(states []RelayState) map[string]bool {
	out := make(map[string]bool, len(states))
	for _, state := range states {
		out[state.Descriptor.APIHTTPSAddr] = true
	}
	return out
}

// SelectPriority returns the ordered list of relay URLs for a client using the
// MOLS selection. It delegates to selectPriorityWithTrace and discards the trace.
func SelectPriority(states []RelayState, routeState RouteState) []string {
	out, _ := selectPriorityWithTrace(states, routeState)
	return out
}
