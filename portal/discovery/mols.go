package discovery

// MOLSRelayPolicy uses a GF(64) MOLS-derived score as the primary
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
	"crypto/rand"
	"hash/fnv"
	"math"
	"math/big"
	"slices"
	"sort"
	"time"
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

func molsRTTStats(states []RelayState) (mean time.Duration, cv float64) {
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

func isRelayFallback(state RelayState) bool {
	return !state.DiscoveryRTTAt.IsZero() && state.DiscoveryRTT > molsFallbackRTTThreshold
}

type MOLSRelayPolicy struct{}

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

	active := make([]RelayState, 0, len(autoPool))
	fallbacks := make([]RelayState, 0)
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

	scoreFor := func(state RelayState) int {
		candidateIdx := hashToGF64(state.Descriptor.APIHTTPSAddr)
		if congested {
			return molsCongestionScore(ingressIdx, candidateIdx, m1, m2)
		}
		return molsScore(ingressIdx, candidateIdx, m1, m2)
	}

	rank := func(pool []RelayState) []string {
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

func (p MOLSRelayPolicy) SelectPriority(states []RelayState, clientState ClientState) []string {
	selected := p.SelectAggregate(states)
	if len(selected) == 0 {
		return nil
	}

	now := time.Now().UTC()
	explicit := make([]string, 0)
	autoPool := make([]RelayState, 0, len(selected))
	for _, state := range selected {
		relayURL := state.Descriptor.APIHTTPSAddr
		if slices.Contains(clientState.ExplicitRelayURLs, relayURL) {
			if state.hasObservedDescriptor() && state.Descriptor.ExpiresAt.After(now) {
				if clientState.RequireUDP && !state.Descriptor.SupportsUDP {
					continue
				}
				if clientState.RequireTCP && !state.Descriptor.SupportsTCP {
					continue
				}
			}
			explicit = append(explicit, relayURL)
			continue
		}
		if slices.Contains(clientState.SuppressedRelayURLs, relayURL) {
			continue
		}

		if state.hasObservedDescriptor() {
			if !state.Descriptor.ExpiresAt.After(now) {
				continue
			}
			if clientState.RequireUDP && !state.Descriptor.SupportsUDP {
				continue
			}
			if clientState.RequireTCP && !state.Descriptor.SupportsTCP {
				continue
			}
		}
		if !state.suppressActiveUntil.IsZero() && state.suppressActiveUntil.After(now) {
			continue
		}
		autoPool = append(autoPool, state)
	}

	autoURLs := p.rankRelayPool(autoPool, clientState.LocalAddress)
	maxActiveRelays := clientState.MaxActiveRelays
	if maxActiveRelays <= 0 {
		maxActiveRelays = defaultMaxActiveRelays
	}
	if len(autoURLs) > maxActiveRelays {
		autoURLs = autoURLs[:maxActiveRelays]
	}
	return append(explicit, autoURLs...)
}

func (p MOLSRelayPolicy) SelectMultiHop(states []RelayState, clientState ClientState) []string {
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
		if slices.Contains(clientState.SuppressedRelayURLs, state.Descriptor.APIHTTPSAddr) {
			continue
		}
		if clientState.RequireUDP && state.hasObservedDescriptor() && !state.Descriptor.SupportsUDP {
			continue
		}
		if clientState.RequireTCP && state.hasObservedDescriptor() && !state.Descriptor.SupportsTCP {
			continue
		}
		if !state.hasObservedDescriptor() || !state.Descriptor.ExpiresAt.After(now) || !state.Descriptor.HasOverlayPeer() {
			continue
		}
		if !state.suppressActiveUntil.IsZero() && state.suppressActiveUntil.After(now) {
			continue
		}
		autoPool = append(autoPool, state)
	}

	multiHop := p.rankRelayPool(autoPool, clientState.LocalAddress)
	if len(multiHop) > clientState.MultiHopDepth {
		multiHop = multiHop[:clientState.MultiHopDepth]
	}
	return multiHop
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
