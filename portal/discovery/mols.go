package discovery

// MOLS selection ranks the eligible relay pool on a dynamic NxN grid sized
// to the current pool. Rankings are deterministic per client, keyed with a
// per-client selection key, and stay stable across restarts. The grid is
// rebuilt on every selection, so eviction only shrinks the grid. Active
// listeners are protected from reshuffles by selection stickiness, which
// retains healthy active relays under the quota.
import (
	"cmp"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
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
	molsCVThreshold            = 0.6
	molsFallbackRTTThreshold   = 2 * time.Second
	molsMinActiveNodes         = 2
	// DefaultMaxActiveRelays is how many auto-selected relays a listener keeps
	// when its limit is zero or negative.
	DefaultMaxActiveRelays = 3
	molsP2CPressureDelta   = 0.3
)

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

func molsCongestionScore(row, col, j, m1, m2, order int, ok bool) int {
	maxScore := 3*order*order + order*order + order + 1
	return maxScore - molsScore(row, col, (order-1)-j, m1, m2, order, ok)
}

func molsDigest(key []byte, s string) [16]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(s))
	var out [16]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func molsCongestionMode(states []relayState) (congested, nonLinear bool) {
	active := make([]relayState, 0, len(states))
	for _, state := range states {
		if !isRelayFallback(state) {
			active = append(active, state)
		}
	}
	avgRTT, cv := molsRTTStats(active)
	return avgRTT > molsCongestionRTTThreshold, cv > molsCVThreshold
}

func molsRTTStats(states []relayState) (mean time.Duration, cv float64) {
	rtts := make([]float64, 0, len(states))
	for _, state := range states {
		if state.DiscoveryRTTAt.IsZero() {
			continue
		}
		rtts = append(rtts, float64(state.effectiveRTT()))
	}
	if len(rtts) == 0 {
		return 0, 0
	}
	var sum float64
	for _, rtt := range rtts {
		sum += rtt
	}
	avg := sum / float64(len(rtts))
	if len(rtts) == 1 {
		return time.Duration(avg), 0
	}
	var sq float64
	for _, rtt := range rtts {
		d := rtt - avg
		sq += d * d
	}
	stddev := math.Sqrt(sq / float64(len(rtts)))
	if avg > 0 {
		cv = stddev / avg
	}
	return time.Duration(avg), cv
}

func isRelayFallback(state relayState) bool {
	return !state.DiscoveryRTTAt.IsZero() && state.effectiveRTT() > molsFallbackRTTThreshold
}

type molsCandidate struct {
	state relayState
	score int
	seq   int
}

func betterMOLSCandidate(a, b molsCandidate) bool {
	if a.score != b.score {
		return a.score > b.score
	}
	aURL := a.state.Descriptor.APIHTTPSAddr
	bURL := b.state.Descriptor.APIHTTPSAddr
	if aURL != bURL {
		return aURL < bURL
	}
	return a.seq < b.seq
}

func rankRelayPool(autoPool []relayState, localAddress string, key []byte) []string {
	if len(autoPool) == 0 {
		return nil
	}

	congested, nonLinear := molsCongestionMode(autoPool)

	order := len(autoPool)
	m1, m2, ok := molsMultipliers(order, nonLinear)
	ingressDigest := molsDigest(key, localAddress)
	ingressRow := int(binary.BigEndian.Uint32(ingressDigest[0:4]) % uint32(order))
	ingressCol := int(binary.BigEndian.Uint32(ingressDigest[4:8]) % uint32(order))

	type relayHash struct {
		url    string
		digest [16]byte
	}
	sortedRelays := make([]relayHash, order)
	for i, state := range autoPool {
		sortedRelays[i] = relayHash{
			url:    state.Descriptor.APIHTTPSAddr,
			digest: molsDigest(key, state.Descriptor.APIHTTPSAddr),
		}
	}
	slices.SortFunc(sortedRelays, func(a, b relayHash) int {
		if a.digest != b.digest {
			return slices.Compare(a.digest[:], b.digest[:])
		}
		return cmp.Compare(a.url, b.url)
	})

	relayCols := make(map[string]int, order)
	for col, rh := range sortedRelays {
		relayCols[rh.url] = col
	}

	scoreFor := func(state relayState) int {
		col := relayCols[state.Descriptor.APIHTTPSAddr]
		if congested {
			return molsCongestionScore(ingressRow, ingressCol, col, m1, m2, order, ok)
		}
		return molsScore(ingressRow, ingressCol, col, m1, m2, order, ok)
	}

	activeStates := make([]relayState, 0, len(autoPool))
	fallbackStates := make([]relayState, 0)
	for _, state := range autoPool {
		if isRelayFallback(state) {
			fallbackStates = append(fallbackStates, state)
		} else {
			activeStates = append(activeStates, state)
		}
	}

	if len(activeStates) < molsMinActiveNodes && len(fallbackStates) > 0 {
		slices.SortFunc(fallbackStates, func(a, b relayState) int {
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

	rankTier := func(states []relayState) []string {
		if len(states) == 0 {
			return nil
		}
		candidates := make([]molsCandidate, 0, len(states))
		for i, state := range states {
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

		if len(candidates) >= 2 {
			p0 := candidates[0].state.pressure()
			p1 := candidates[1].state.pressure()
			if p0-p1 > molsP2CPressureDelta {
				candidates[0], candidates[1] = candidates[1], candidates[0]
			}
		}

		tierOut := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			tierOut = append(tierOut, candidate.state.Descriptor.APIHTTPSAddr)
		}
		return tierOut
	}

	activeURLs := rankTier(activeStates)
	fallbackURLs := rankTier(fallbackStates)
	return append(activeURLs, fallbackURLs...)
}

func selectPriority(states []relayState, routeState routeState) []string {
	now := time.Now().UTC()
	explicit := make([]string, 0, len(routeState.ExplicitRelayURLs))
	seen := make(map[string]struct{}, len(routeState.ExplicitRelayURLs))
	for _, relayURL := range routeState.ExplicitRelayURLs {
		if _, ok := seen[relayURL]; ok {
			continue
		}
		seen[relayURL] = struct{}{}
		eligible := true
		for _, state := range states {
			if state.Descriptor.APIHTTPSAddr != relayURL {
				continue
			}
			suppressed := !state.suppressActiveUntil.IsZero() && state.suppressActiveUntil.After(now)
			eligible = !state.Banned && !state.Dead && !suppressed && state.supportsRequiredTransports(routeState, now)
			break
		}
		if eligible {
			explicit = append(explicit, relayURL)
		}
	}
	auto := rankRelayPool(filterCandidatePool(states, routeState, now), routeState.LocalAddress, routeState.SelectionKey)
	maxActive := routeState.MaxActiveRelays
	if maxActive <= 0 {
		maxActive = DefaultMaxActiveRelays
	}
	auto = applyActiveStickiness(auto, routeState.ActiveRelayURLs, states, maxActive)
	if len(auto) > maxActive {
		auto = auto[:maxActive]
	}
	return append(explicit, auto...)
}

func applyActiveStickiness(ranked []string, activeRelayURLs []string, states []relayState, maxActive int) []string {
	if len(ranked) == 0 || maxActive <= 0 || len(activeRelayURLs) == 0 {
		return ranked
	}

	stateMap := make(map[string]relayState, len(states))
	for _, s := range states {
		stateMap[s.Descriptor.APIHTTPSAddr] = s
	}

	selected := make([]string, 0, len(ranked))
	for _, u := range activeRelayURLs {
		if len(selected) >= maxActive {
			break
		}
		s, ok := stateMap[u]
		if !ok || isRelayFallback(s) || s.pressure() > 0.5 {
			continue
		}
		if slices.Contains(ranked, u) && !slices.Contains(selected, u) {
			selected = append(selected, u)
		}
	}

	for _, u := range ranked {
		if !slices.Contains(selected, u) {
			selected = append(selected, u)
		}
	}
	return selected
}
