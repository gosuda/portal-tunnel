package discovery

// MOLSRelayPolicy ranks relays using a GF(64)-based MOLS grid with a
// non-invasive adaptive partition over local load telemetry.
//
// Ordering Pipeline:
//   1. Filter: Apply ban, expiry, and protocol compatibility gates.
//   2. Extract: Keep the top fixed-depth deterministic MOLS candidates.
//   3. Partition: Move saturated relays behind active relays.
//   4. Preserve: Keep intra-tier MOLS order unchanged.
//
import (
	"crypto/rand"
	"hash/fnv"
	"math"
	"math/big"
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

// gridOrderForSize returns the smallest supported MOLS grid order (64, 96, 128)
// that can accommodate the relay pool size.
func gridOrderForSize(poolSize int) int {
	if poolSize <= 64 {
		return 64
	}
	// Continuously scale up in increments of 32 to handle arbitrary pool sizes
	rem := poolSize % 32
	if rem == 0 {
		return poolSize
	}
	return poolSize + (32 - rem)
}

// NOTE: For orders 96 and 128, which are not powers of 2, the GF implementation
// needs to be treated as a composite or modular field. For this progressive
// scaling, we use a simple linear congruence as a fallback to preserve
// deterministic uniqueness when the standard GF(64) grid is exceeded.
func molsScore(i, j, m1, m2, order int) int {
	// Standard GF(64) case
	if order == 64 {
		l1 := gf64Mul(uint8(m1), uint8(i)) ^ uint8(j)
		l2 := gf64Mul(uint8(m2), uint8(i)) ^ uint8(j)
		return int(l1)*order + int(l2) + 1
	}

	// Fallback for non-power-of-two orders: Linear Congruential approach
	// to maintain deterministic uniqueness across larger relay sets.
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
	for _, s := range states {
		if s.DiscoveryRTTAt.IsZero() {
			continue
		}
		count++
		sum += float64(s.DiscoveryRTT)
	}
	if count == 0 {
		return 0, 0
	}
	avg := sum / float64(count)
	if count == 1 {
		return time.Duration(avg), 0
	}
	var sq float64
	for _, s := range states {
		if s.DiscoveryRTTAt.IsZero() {
			continue
		}
		d := float64(s.DiscoveryRTT) - avg
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

type MOLSRelayPolicy struct{}

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

func (p MOLSRelayPolicy) SelectAggregate(states []RelayState) []RelayState {
	out := make([]RelayState, 0, len(states))
	for _, s := range states {
		if !s.Banned {
			out = append(out, s)
		}
	}
	return out
}

func (p MOLSRelayPolicy) SelectConfirmed(states []RelayState) []RelayState {
	out := make([]RelayState, 0)
	for _, s := range states {
		if s.Confirmed {
			out = append(out, s)
		}
	}
	return out
}

func (p MOLSRelayPolicy) OnActiveConfirmed(state RelayState) RelayState {
	state.Confirmed = true
	state.activeFailures = 0
	state.suppressActiveUntil = time.Time{}
	return state
}

func (p MOLSRelayPolicy) OnUnconfirmed(state RelayState) RelayState {
	state.Confirmed = false
	return state
}

func (p MOLSRelayPolicy) OnDiscoveryConfirmed(state RelayState) RelayState {
	state.discoveryFailures = 0
	state.nextDiscoveryRefreshAt = time.Time{}
	return state
}

func (p MOLSRelayPolicy) OnDiscoveryFailure(state RelayState, err error, recoveryFailures int) (RelayState, bool, string) {
	state.discoveryFailures++

	if recoveryFailures <= 0 || state.discoveryFailures < recoveryFailures {
		return state, false, "retry"
	}
	failuresOverBudget := state.discoveryFailures - recoveryFailures
	backoff := defaultDirectRecoveryBackoff << min(failuresOverBudget, 3)
	if backoff > maxDirectRecoveryBackoff {
		backoff = maxDirectRecoveryBackoff
	}
	state.nextDiscoveryRefreshAt = time.Now().Add(backoff)
	return state, true, "discovery"
}

func (p MOLSRelayPolicy) OnActiveFailure(state RelayState, err error, recoveryFailures int) (RelayState, bool, string) {
	state.activeFailures++

	if recoveryFailures <= 0 || state.activeFailures < recoveryFailures {
		return state, false, "retry"
	}
	failuresOverBudget := state.activeFailures - recoveryFailures
	backoff := defaultDirectRecoveryBackoff << min(failuresOverBudget, 3)
	if backoff > maxDirectRecoveryBackoff {
		backoff = maxDirectRecoveryBackoff
	}
	state.suppressActiveUntil = time.Now().Add(backoff)
	return state, true, "active"
}

func (p MOLSRelayPolicy) OnBanned(state RelayState) RelayState {
	state.Banned = true
	return state
}

func (p MOLSRelayPolicy) rankRelayPool(autoPool []RelayState, localAddress string) []string {
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
		idx := int(candidateIdx) % order
		if congested {
			return molsCongestionScore(int(ingressIdx)%order, idx, int(m1), int(m2), order)
		}
		return molsScore(int(ingressIdx)%order, idx, int(m1), int(m2), order)
	}

	// Partition by fallback status and promote to meet minimum active nodes.
	activeStates := make([]RelayState, 0, len(autoPool))
	fallbackStates := make([]RelayState, 0)
	for _, s := range autoPool {
		if isRelayFallback(s) {
			fallbackStates = append(fallbackStates, s)
		} else {
			activeStates = append(activeStates, s)
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

// SelectPriorityWithTrace is the telemetry-instrumented sibling of
// SelectPriority. It returns the same ordered relay list plus a SelectionTrace
// that captures pool statistics, eligibility classification, and the scoring
// parameters used for this specific call. The returned OutputURLs slice is
// byte-identical to what SelectPriority returns for the same inputs.
//
// Banned relays are recorded in SelectionTrace.Suppressed / Reasons with
// reason "banned" even though SelectAggregate removes them before further
// processing. Explicit relays are not included in Ranked (they bypass MOLS
// scoring entirely). PoolFallback reflects the fallback count before the
// minimum-active-node promotion step.
func (p MOLSRelayPolicy) SelectPriorityWithTrace(states []RelayState, cs ClientState) ([]string, telemetry.SelectionTrace) {
	start := time.Now()
	now := start.UTC()

	trace := telemetry.SelectionTrace{
		Timestamp:  start,
		ClientHash: hashToGF64(cs.LocalAddress),
		Mode:       "priority",
		PoolTotal:  len(states),
		Reasons:    make(map[string]string),
	}

	// Record banned relays before SelectAggregate strips them.
	for _, state := range states {
		if state.Banned {
			url := state.Descriptor.APIHTTPSAddr
			trace.Suppressed = append(trace.Suppressed, url)
			trace.Reasons[url] = "banned"
		}
	}

	selected := p.SelectAggregate(states)
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

	// Compute pool statistics before promotion.
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

	// Replicate the partition+promotion logic from rankRelayPool to determine
	// which relays remain as fallbacks after the minimum-active-node promotion
	// step. Demoted=true only for relays that stay in the fallback section after
	// promotion (i.e., were not promoted to meet molsMinActiveNodes).
	trActive := make([]RelayState, 0, len(autoPool))
	trFallbacks := make([]RelayState, 0)
	for _, state := range autoPool {
		if isRelayFallback(state) {
			trFallbacks = append(trFallbacks, state)
		} else {
			trActive = append(trActive, state)
		}
	}
	// PoolFallback is counted before promotion (reflects raw slow-relay count).
	trace.PoolEligible = len(autoPool)
	trace.PoolFallback = len(trFallbacks)
	if len(trActive) < molsMinActiveNodes && len(trFallbacks) > 0 {
		promote := min(molsMinActiveNodes-len(trActive), len(trFallbacks))
		trFallbacks = trFallbacks[promote:]
	}

	// Build a set of relay URLs that remain demoted (survive as fallbacks after promotion).
	demotedURLs := make(map[string]bool, len(trFallbacks))
	for _, s := range trFallbacks {
		demotedURLs[s.Descriptor.APIHTTPSAddr] = true
	}

	// Build Ranked entries for all candidates in the auto pool.
	ingressIdx := hashToGF64(cs.LocalAddress)
	order := gridOrderForSize(len(autoPool))
	for _, state := range autoPool {
		candidateIdx := hashToGF64(state.Descriptor.APIHTTPSAddr)
		var score int
		if congested {
			score = molsCongestionScore(int(ingressIdx), int(candidateIdx), int(m1), int(m2), order)
		} else {
			score = molsScore(int(ingressIdx), int(candidateIdx), int(m1), int(m2), order)
		}
		trace.Ranked = append(trace.Ranked, telemetry.TraceEntry{
			URL:       state.Descriptor.APIHTTPSAddr,
			Score:     score,
			Confirmed: state.Confirmed,
			RTT:       state.DiscoveryRTT,
			Demoted:   demotedURLs[state.Descriptor.APIHTTPSAddr],
		})
	}

	autoURLs := p.rankRelayPool(autoPool, cs.LocalAddress)
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

// SelectPriority returns the ordered list of relay URLs for a client using the
// MOLS policy. It delegates to SelectPriorityWithTrace and discards the trace.
func (p MOLSRelayPolicy) SelectPriority(states []RelayState, clientState ClientState) []string {
	out, _ := p.SelectPriorityWithTrace(states, clientState)
	return out
}

// SelectMultiHopWithTrace is the telemetry-instrumented sibling of
// SelectMultiHop. It returns the same ordered relay list plus a SelectionTrace.
// The returned OutputURLs slice is byte-identical to what SelectMultiHop
// returns for the same inputs.
//
// Relays excluded by eligibility gates (no descriptor, expired, no overlay
// peer, UDP/TCP mismatch, suppressed, banned) are recorded in
// SelectionTrace.Suppressed / Reasons. PoolFallback reflects the fallback count
// before the minimum-active-node promotion step.
func (p MOLSRelayPolicy) SelectMultiHopWithTrace(states []RelayState, cs ClientState) ([]string, telemetry.SelectionTrace) {
	start := time.Now()
	now := start.UTC()

	trace := telemetry.SelectionTrace{
		Timestamp:  start,
		ClientHash: hashToGF64(cs.LocalAddress),
		Mode:       "multihop",
		PoolTotal:  len(states),
		Reasons:    make(map[string]string),
	}

	if cs.MultiHopDepth <= 1 {
		trace.SelectionTook = time.Since(start)
		return nil, trace
	}

	// Record banned relays before SelectAggregate strips them.
	for _, state := range states {
		if state.Banned {
			url := state.Descriptor.APIHTTPSAddr
			trace.Suppressed = append(trace.Suppressed, url)
			trace.Reasons[url] = "banned"
		}
	}

	selected := p.SelectAggregate(states)
	if len(selected) == 0 {
		trace.SelectionTook = time.Since(start)
		return nil, trace
	}

	autoPool := make([]RelayState, 0, len(selected))
	for _, state := range selected {
		relayURL := state.Descriptor.APIHTTPSAddr
		if cs.RequireUDP && state.hasObservedDescriptor() && !state.Descriptor.SupportsUDP {
			trace.Suppressed = append(trace.Suppressed, relayURL)
			trace.Reasons[relayURL] = "require_udp"
			continue
		}
		if cs.RequireTCP && state.hasObservedDescriptor() && !state.Descriptor.SupportsTCP {
			trace.Suppressed = append(trace.Suppressed, relayURL)
			trace.Reasons[relayURL] = "require_tcp"
			continue
		}
		if !state.hasObservedDescriptor() {
			trace.Suppressed = append(trace.Suppressed, relayURL)
			trace.Reasons[relayURL] = "no_descriptor"
			continue
		}
		if !state.Descriptor.ExpiresAt.After(now) {
			trace.Suppressed = append(trace.Suppressed, relayURL)
			trace.Reasons[relayURL] = "expired"
			continue
		}
		if !state.Descriptor.HasOverlayPeer() {
			trace.Suppressed = append(trace.Suppressed, relayURL)
			trace.Reasons[relayURL] = "no_overlay_peer"
			continue
		}
		if !state.suppressActiveUntil.IsZero() && state.suppressActiveUntil.After(now) {
			trace.Suppressed = append(trace.Suppressed, relayURL)
			trace.Reasons[relayURL] = "suppressed"
			continue
		}
		autoPool = append(autoPool, state)
	}

	// Compute pool statistics before promotion.
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

	// Replicate the partition+promotion logic from rankRelayPool to determine
	// which relays remain as fallbacks after the minimum-active-node promotion
	// step. Demoted=true only for relays that stay in the fallback section after
	// promotion (i.e., were not promoted to meet molsMinActiveNodes).
	mhActive := make([]RelayState, 0, len(autoPool))
	mhFallbacks := make([]RelayState, 0)
	for _, state := range autoPool {
		if isRelayFallback(state) {
			mhFallbacks = append(mhFallbacks, state)
		} else {
			mhActive = append(mhActive, state)
		}
	}
	// PoolFallback is counted before promotion (reflects raw slow-relay count).
	trace.PoolEligible = len(autoPool)
	trace.PoolFallback = len(mhFallbacks)
	if len(mhActive) < molsMinActiveNodes && len(mhFallbacks) > 0 {
		promote := min(molsMinActiveNodes-len(mhActive), len(mhFallbacks))
		mhFallbacks = mhFallbacks[promote:]
	}

	// Build a set of relay URLs that remain demoted (survive as fallbacks after promotion).
	mhDemotedURLs := make(map[string]bool, len(mhFallbacks))
	for _, s := range mhFallbacks {
		mhDemotedURLs[s.Descriptor.APIHTTPSAddr] = true
	}

	// Build Ranked entries for all candidates in the auto pool.
	ingressIdx := hashToGF64(cs.LocalAddress)
	order := gridOrderForSize(len(autoPool))
	for _, state := range autoPool {
		candidateIdx := hashToGF64(state.Descriptor.APIHTTPSAddr)
		var score int
		if congested {
			score = molsCongestionScore(int(ingressIdx), int(candidateIdx), int(m1), int(m2), order)
		} else {
			score = molsScore(int(ingressIdx), int(candidateIdx), int(m1), int(m2), order)
		}
		trace.Ranked = append(trace.Ranked, telemetry.TraceEntry{
			URL:       state.Descriptor.APIHTTPSAddr,
			Score:     score,
			Confirmed: state.Confirmed,
			RTT:       state.DiscoveryRTT,
			Demoted:   mhDemotedURLs[state.Descriptor.APIHTTPSAddr],
		})
	}

	multiHop := p.rankRelayPool(autoPool, cs.LocalAddress)
	if len(multiHop) > cs.MultiHopDepth {
		multiHop = multiHop[:cs.MultiHopDepth]
	}
	trace.OutputURLs = multiHop
	trace.SelectionTook = time.Since(start)
	return multiHop, trace
}

// SelectMultiHop returns the ordered list of relay URLs for multi-hop routing.
// It delegates to SelectMultiHopWithTrace and discards the trace.
func (p MOLSRelayPolicy) SelectMultiHop(states []RelayState, clientState ClientState) []string {
	out, _ := p.SelectMultiHopWithTrace(states, clientState)
	return out
}

func (p MOLSRelayPolicy) SelectRandomMultiHop(states []RelayState, clientState ClientState) []string {
	if clientState.MultiHopDepth <= 1 {
		return nil
	}

	selected := p.SelectAggregate(states)
	if len(selected) == 0 {
		return nil
	}

	now := time.Now().UTC()
	autoPool := make([]RelayState, 0, len(selected))
	for _, state := range selected {
		if !state.hasObservedDescriptor() || !state.Descriptor.ExpiresAt.After(now) || !state.Descriptor.HasOverlayPeer() {
			continue
		}
		if !state.suppressActiveUntil.IsZero() && state.suppressActiveUntil.After(now) {
			continue
		}
		autoPool = append(autoPool, state)
	}

	for i := len(autoPool) - 1; i > 0; i-- {
		j, err := cryptoIndex(i + 1)
		if err != nil {
			return nil
		}
		autoPool[i], autoPool[j] = autoPool[j], autoPool[i]
	}

	if len(autoPool) > clientState.MultiHopDepth {
		autoPool = autoPool[:clientState.MultiHopDepth]
	}
	out := make([]string, 0, len(autoPool))
	for _, state := range autoPool {
		out = append(out, state.Descriptor.APIHTTPSAddr)
	}
	return out
}

func cryptoIndex(limit int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(limit)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}
