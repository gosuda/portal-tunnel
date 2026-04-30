package mols

// MOLS uses a GF(64) MOLS-derived score as the primary
// deterministic ordering for eligible relays. Health and freshness gates decide
// eligibility before the MOLS score is applied.

// # Core Design
//
// The engine uses an order-64 grid derived from Galois Field GF(64). The
// composite score is deterministic for a (client identity, relay URL) pair and
// drives ordering after freshness and failure-suppression gates. Confirmation
// and RTT remain tie-breakers for equal scores.
//
//      L_m[i][j] = gf64Mul(m, i) XOR j           (Latin-square row for multiplier m)
//      score(i, j) = L_m1[i][j] * 64 + L_m2[i][j] + 1   (composite, range 1..4096)
//
// # Congestion Switching (Reverse-Siamese)
//
// When the mean discovery RTT across the auto pool exceeds
// molsCongestionRTTThreshold, the engine applies:
//
//      congestionScore(i, j) = (n^2+1) - score(i, 63-j)
//
// This mirrors the deterministic tie-break order when the whole observed pool
// appears slow.
//
// # Non-Linear Load (Variant Grid)
//
// When the coefficient of variation of per-relay discovery RTTs exceeds
// molsCVThreshold, the engine switches multipliers from (3, 5) to (7, 11).
// Non-linear detection takes precedence over congestion switching.
//
// # Health & Fallback
//
// Relays whose measured discovery RTT exceeds molsFallbackRTTThreshold are
// treated as Fallback and placed at the end of the priority queue. Discovery
// polling failures and SDK listener failures are tracked separately so a
// discovery retry delay does not by itself remove an otherwise active relay
// candidate.

import (
	"context"
	"hash/fnv"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
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
)

// Compile-time assertion: *MOLS must satisfy discovery.Selector.
var _ discovery.Selector = (*MOLS)(nil)

// MOLS is the pluggable relay-selection policy that implements
// discovery.Selector using a GF(64) MOLS-derived score.
type MOLS struct{}

// New returns a new MOLS selector.
func New() *MOLS {
	return &MOLS{}
}

// Name returns the canonical name of this selector.
func (p *MOLS) Name() string { return "mols" }

// SelectPriority implements discovery.Selector. It delegates to
// SelectPriorityWithTrace. ctx is accepted but currently unused.
func (p *MOLS) SelectPriority(ctx context.Context, pool []discovery.RelayState, client discovery.ClientState) ([]string, discovery.SelectionTrace) {
	return p.SelectPriorityWithTrace(pool, client)
}

// SelectMultiHop implements discovery.Selector. It delegates to
// SelectMultiHopWithTrace. ctx is accepted but currently unused.
func (p *MOLS) SelectMultiHop(ctx context.Context, pool []discovery.RelayState, client discovery.ClientState) ([]string, discovery.SelectionTrace) {
	return p.SelectMultiHopWithTrace(pool, client)
}

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

func molsScore(i, j, m1, m2 uint8) int {
	// L1, L2 form the orthogonal latin squares.
	l1 := gf64Mul(m1, i) ^ j
	l2 := gf64Mul(m2, i) ^ j

	score := int(l1)*molsOrder + int(l2) + 1
	return score
}

func molsCongestionScore(i, j, m1, m2 uint8) int {
	return molsMagicConstant - molsScore(i, (molsOrder-1)-j, m1, m2)
}

func hashToGF64(s string) uint8 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return uint8(h.Sum32() & 0x3f)
}

func molsRTTStats(states []discovery.RelayState) (mean time.Duration, cv float64) {
	var samples []float64
	for _, s := range states {
		if s.DiscoveryRTTAt.IsZero() {
			continue
		}
		samples = append(samples, float64(s.DiscoveryRTT))
	}
	if len(samples) == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range samples {
		sum += v
	}
	avg := sum / float64(len(samples))
	if len(samples) == 1 {
		return time.Duration(avg), 0
	}
	var sq float64
	for _, v := range samples {
		d := v - avg
		sq += d * d
	}
	stddev := math.Sqrt(sq / float64(len(samples)))
	if avg > 0 {
		cv = stddev / avg
	}
	return time.Duration(avg), cv
}

func isRelayFallback(state discovery.RelayState) bool {
	return !state.DiscoveryRTTAt.IsZero() && state.DiscoveryRTT > molsFallbackRTTThreshold
}

// SelectAggregate is a thin wrapper around discovery.FilterUnbanned retained
// only for test call sites. It is not part of any interface.
func (p *MOLS) SelectAggregate(states []discovery.RelayState) []discovery.RelayState {
	return discovery.FilterUnbanned(states)
}

// SelectConfirmed is a thin wrapper around discovery.FilterConfirmed retained
// only for test call sites. It is not part of any interface.
func (p *MOLS) SelectConfirmed(states []discovery.RelayState) []discovery.RelayState {
	return discovery.FilterConfirmed(states)
}

func (p *MOLS) rankRelayPool(autoPool []discovery.RelayState, localAddress string) []string {
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

	active := make([]discovery.RelayState, 0, len(autoPool))
	fallbacks := make([]discovery.RelayState, 0)
	for _, state := range autoPool {
		if isRelayFallback(state) {
			fallbacks = append(fallbacks, state)
		} else {
			active = append(active, state)
		}
	}

	if len(active) < molsMinActiveNodes && len(fallbacks) > 0 {
		promote := min(molsMinActiveNodes-len(active), len(fallbacks))
		active = append(active, fallbacks[:promote]...)
		fallbacks = fallbacks[promote:]
	}

	scoreFor := func(state discovery.RelayState) int {
		candidateIdx := hashToGF64(state.Descriptor.APIHTTPSAddr)
		if congested {
			return molsCongestionScore(ingressIdx, candidateIdx, m1, m2)
		}
		return molsScore(ingressIdx, candidateIdx, m1, m2)
	}

	rank := func(pool []discovery.RelayState) []string {
		type item struct {
			url   string
			conf  bool
			rtt   time.Duration
			score int
		}
		items := make([]item, len(pool))
		for i, st := range pool {
			items[i] = item{
				url:   st.Descriptor.APIHTTPSAddr,
				conf:  st.Confirmed,
				rtt:   st.DiscoveryRTT,
				score: scoreFor(st),
			}
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].score != items[j].score {
				return items[i].score > items[j].score
			}
			if items[i].conf != items[j].conf {
				return items[i].conf
			}
			if items[i].rtt != items[j].rtt {
				if items[i].rtt == 0 {
					return false
				}
				if items[j].rtt == 0 {
					return true
				}
				return items[i].rtt < items[j].rtt
			}
			return items[i].url < items[j].url
		})
		res := make([]string, len(items))
		for i, v := range items {
			res[i] = v.url
		}
		return res
	}

	autoURLs := append(rank(active), rank(fallbacks)...)
	if len(autoURLs) == 0 {
		return nil
	}
	return autoURLs
}

// SelectPriorityWithTrace is the telemetry-instrumented sibling of the legacy
// SelectPriority. It returns the same ordered relay list plus a SelectionTrace
// that captures pool statistics, eligibility classification, and the scoring
// parameters used for this specific call. The returned OutputURLs slice is
// byte-identical to what SelectPriority (no-trace) returns for the same inputs.
//
// Banned relays are recorded in SelectionTrace.Suppressed / Reasons with
// reason "banned" even though SelectAggregate removes them before further
// processing. Explicit relays are not included in Ranked (they bypass MOLS
// scoring entirely). PoolFallback reflects the fallback count before the
// minimum-active-node promotion step.
func (p *MOLS) SelectPriorityWithTrace(states []discovery.RelayState, cs discovery.ClientState) ([]string, discovery.SelectionTrace) {
	start := time.Now()
	now := start.UTC()

	trace := discovery.SelectionTrace{
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

	selected := discovery.FilterUnbanned(states)
	if len(selected) == 0 {
		trace.SelectionTook = time.Since(start)
		return nil, trace
	}

	explicit := make([]string, 0)
	autoPool := make([]discovery.RelayState, 0, len(selected))
	for _, state := range selected {
		relayURL := state.Descriptor.APIHTTPSAddr
		if slices.Contains(cs.ExplicitRelayURLs, relayURL) {
			if state.HasObservedDescriptor() && state.Descriptor.ExpiresAt.After(now) {
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

		if state.HasObservedDescriptor() {
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
		if state.IsSuppressedActive(now) {
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
	trActive := make([]discovery.RelayState, 0, len(autoPool))
	trFallbacks := make([]discovery.RelayState, 0)
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
	for _, state := range autoPool {
		candidateIdx := hashToGF64(state.Descriptor.APIHTTPSAddr)
		var score int
		if congested {
			score = molsCongestionScore(ingressIdx, candidateIdx, m1, m2)
		} else {
			score = molsScore(ingressIdx, candidateIdx, m1, m2)
		}
		trace.Ranked = append(trace.Ranked, discovery.TraceEntry{
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

// SelectMultiHopWithTrace is the telemetry-instrumented sibling of
// SelectMultiHop. It returns the same ordered relay list plus a SelectionTrace.
// The returned OutputURLs slice is byte-identical to what SelectMultiHop
// returns for the same inputs.
//
// Relays excluded by eligibility gates (no descriptor, expired, no overlay
// peer, UDP/TCP mismatch, suppressed, banned) are recorded in
// SelectionTrace.Suppressed / Reasons. PoolFallback reflects the fallback count
// before the minimum-active-node promotion step.
func (p *MOLS) SelectMultiHopWithTrace(states []discovery.RelayState, cs discovery.ClientState) ([]string, discovery.SelectionTrace) {
	start := time.Now()
	now := start.UTC()

	trace := discovery.SelectionTrace{
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

	selected := discovery.FilterUnbanned(states)
	if len(selected) == 0 {
		trace.SelectionTook = time.Since(start)
		return nil, trace
	}

	autoPool := make([]discovery.RelayState, 0, len(selected))
	for _, state := range selected {
		relayURL := state.Descriptor.APIHTTPSAddr
		if cs.RequireUDP && state.HasObservedDescriptor() && !state.Descriptor.SupportsUDP {
			trace.Suppressed = append(trace.Suppressed, relayURL)
			trace.Reasons[relayURL] = "require_udp"
			continue
		}
		if cs.RequireTCP && state.HasObservedDescriptor() && !state.Descriptor.SupportsTCP {
			trace.Suppressed = append(trace.Suppressed, relayURL)
			trace.Reasons[relayURL] = "require_tcp"
			continue
		}
		if !state.HasObservedDescriptor() {
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
		if state.IsSuppressedActive(now) {
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
	mhActive := make([]discovery.RelayState, 0, len(autoPool))
	mhFallbacks := make([]discovery.RelayState, 0)
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
	for _, state := range autoPool {
		candidateIdx := hashToGF64(state.Descriptor.APIHTTPSAddr)
		var score int
		if congested {
			score = molsCongestionScore(ingressIdx, candidateIdx, m1, m2)
		} else {
			score = molsScore(ingressIdx, candidateIdx, m1, m2)
		}
		trace.Ranked = append(trace.Ranked, discovery.TraceEntry{
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
