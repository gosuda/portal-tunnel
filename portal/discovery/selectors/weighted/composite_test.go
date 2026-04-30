package weighted

import (
	"context"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery/selectors/mols"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// simpleRelayState returns a minimal RelayState with the given URL and load
// signals. It uses Bootstrap=true so that MOLS treats it as an always-present
// pool member regardless of descriptor freshness, and leaves IsSuppressedActive
// false (zero suppressActiveUntil) so the relay enters the MOLS auto pool.
func simpleRelayState(url string, loadFactor, failureRate float64) discovery.RelayState {
	return discovery.RelayState{
		Descriptor: types.RelayDescriptor{
			APIHTTPSAddr: url,
		},
		Bootstrap:   true,
		LoadFactor:  loadFactor,
		FailureRate: failureRate,
	}
}

// overlayRelayState returns a RelayState that passes all SelectMultiHop
// eligibility gates: HasObservedDescriptor (non-zero LastSeenAt), non-expired
// ExpiresAt, SupportsOverlay=true, non-empty WireGuardPublicKey, WireGuardPort>0.
// No cryptographic signing is required — MOLS's SelectMultiHop only inspects
// the descriptor fields, not the signature.
func overlayRelayState(url string, loadFactor, failureRate float64) discovery.RelayState {
	now := time.Now().UTC()
	return discovery.RelayState{
		Descriptor: types.RelayDescriptor{
			APIHTTPSAddr:       url,
			IssuedAt:           now,
			ExpiresAt:          now.Add(time.Hour),
			SupportsOverlay:    true,
			WireGuardPublicKey: "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleTA=", // non-empty placeholder
			WireGuardPort:      51820,
		},
		Confirmed:   true,
		LastSeenAt:  now,
		LoadFactor:  loadFactor,
		FailureRate: failureRate,
	}
}

// mustSelectPriorityURLs is a test convenience that calls SelectPriority and
// returns the URLs, failing the test if the pool is empty and n>0 was expected.
func mustSelectPriorityURLs(t *testing.T, sel discovery.Selector, pool []discovery.RelayState, client discovery.ClientState) []string {
	t.Helper()
	urls, _ := sel.SelectPriority(context.Background(), pool, client)
	return urls
}

// indexOf returns the 0-based position of url in urls, or -1 if not found.
func indexOf(urls []string, url string) int {
	for i, u := range urls {
		if u == url {
			return i
		}
	}
	return -1
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestCompositeEqualWeightMatchesMOLS verifies that when all relays carry zero
// load (LoadFactor=0, FailureRate=0), the Composite output is identical to the
// plain MOLS output. This is the degeneration-to-inner-selector invariant.
func TestCompositeEqualWeightMatchesMOLS(t *testing.T) {
	relays := []string{
		"https://relay-a.example.com",
		"https://relay-b.example.com",
		"https://relay-c.example.com",
	}
	pool := make([]discovery.RelayState, len(relays))
	for i, u := range relays {
		pool[i] = simpleRelayState(u, 0.0, 0.0)
	}

	client := discovery.ClientState{
		LocalAddress:    "client-addr-1",
		MaxActiveRelays: len(relays),
	}

	inner := mols.New()
	composite := New(inner)

	molsURLs := mustSelectPriorityURLs(t, inner, pool, client)
	compositeURLs := mustSelectPriorityURLs(t, composite, pool, client)

	if len(molsURLs) != len(compositeURLs) {
		t.Fatalf("len mismatch: mols=%d composite=%d", len(molsURLs), len(compositeURLs))
	}
	for i := range molsURLs {
		if molsURLs[i] != compositeURLs[i] {
			t.Fatalf("position %d differs: mols=%q composite=%q", i, molsURLs[i], compositeURLs[i])
		}
	}
}

// TestCompositeLoadImbalanceDiverts verifies that a relay with a high LoadFactor
// drops in rank relative to its MOLS position when the Composite applies the
// additive penalty.
func TestCompositeLoadImbalanceDiverts(t *testing.T) {
	// Use enough relays so that the high-load relay's MOLS position is not last.
	// We pick three relays; we will assert that the high-load relay ranks worse
	// in composite output than in the inner MOLS output.
	relays := []string{
		"https://relay-x.example.com",
		"https://relay-y.example.com",
		"https://relay-z.example.com",
	}

	inner := mols.New()
	client := discovery.ClientState{
		LocalAddress:    "client-addr-divert",
		MaxActiveRelays: len(relays),
	}

	// First find MOLS order with zero load to establish baseline positions.
	zeroPool := make([]discovery.RelayState, len(relays))
	for i, u := range relays {
		zeroPool[i] = simpleRelayState(u, 0.0, 0.0)
	}
	molsURLs := mustSelectPriorityURLs(t, inner, zeroPool, client)
	if len(molsURLs) < 2 {
		t.Fatalf("MOLS returned fewer than 2 URLs from 3-relay pool: %v — bootstrap relay construction broken", molsURLs)
	}

	// Pick the relay that MOLS ranks first (position 0) and give it a very
	// high load. After the composite penalty it should be demoted.
	highLoadURL := molsURLs[0]
	molsTopPos := 0

	pool := make([]discovery.RelayState, len(relays))
	for i, u := range relays {
		lf := 0.0
		if u == highLoadURL {
			lf = 5.0 // very high — quantized tier will greatly exceed lambda*tier
		}
		pool[i] = simpleRelayState(u, lf, 0.0)
	}

	composite := New(inner, WithLambda(1.0), WithEpsilon(0.1))
	compositeURLs := mustSelectPriorityURLs(t, composite, pool, client)

	compositePos := indexOf(compositeURLs, highLoadURL)
	if compositePos == -1 {
		t.Fatalf("high-load relay %q missing from composite output", highLoadURL)
	}
	if compositePos <= molsTopPos {
		t.Fatalf("expected high-load relay %q to demote below position %d; got composite position %d",
			highLoadURL, molsTopPos, compositePos)
	}
}

// TestCompositeQuantizationWithinTier verifies that two relays whose LoadFactor
// values fall in the same quantization tier produce identical tier_load values,
// so their relative ordering does not change as load shifts within the tier.
func TestCompositeQuantizationWithinTier(t *testing.T) {
	// epsilon=1.0 → tier boundaries at 0, 1, 2, ...
	// loads 0.4 and 0.6 both floor to tier 0.0; loads 0.55 also floors to 0.0.
	epsilon := 1.0
	composite := New(mols.New(), WithEpsilon(epsilon), WithLambda(1.0))

	urlA := "https://relay-tier-a.example.com"
	urlB := "https://relay-tier-b.example.com"
	client := discovery.ClientState{
		LocalAddress:    "client-tier",
		MaxActiveRelays: 2,
	}

	// Baseline: both zero load — establish who MOLS puts first.
	basePool := []discovery.RelayState{
		simpleRelayState(urlA, 0.0, 0.0),
		simpleRelayState(urlB, 0.0, 0.0),
	}
	baseURLs := mustSelectPriorityURLs(t, composite, basePool, client)
	if len(baseURLs) < 2 {
		t.Fatalf("baseline pool returned fewer than 2 URLs: %v — bootstrap relay construction broken", baseURLs)
	}
	// Record the baseline rank of urlA.
	baseRankA := indexOf(baseURLs, urlA)

	// Within-tier load variations: all loads < 1.0 floor to tier 0.0.
	loadVariations := [][2]float64{
		{0.4, 0.6},
		{0.6, 0.4},
		{0.55, 0.55},
		{0.99, 0.01},
	}

	for _, lv := range loadVariations {
		pool := []discovery.RelayState{
			simpleRelayState(urlA, lv[0], 0.0),
			simpleRelayState(urlB, lv[1], 0.0),
		}
		urls := mustSelectPriorityURLs(t, composite, pool, client)
		if len(urls) < 2 {
			t.Fatalf("within-tier pool (%.2f, %.2f) returned fewer than 2 URLs: %v", lv[0], lv[1], urls)
		}
		gotRankA := indexOf(urls, urlA)
		if gotRankA != baseRankA {
			t.Errorf("within-tier load variation (%.2f, %.2f): rank of %q changed from %d to %d",
				lv[0], lv[1], urlA, baseRankA, gotRankA)
		}
	}
}

// TestCompositeQuantizationBoundary verifies that a single tier-boundary
// crossing (load 0.99 → 1.01 with epsilon=1.0) produces exactly one rank swap
// and no double-flap. A lambda of 2.0 ensures the penalty strictly exceeds the
// position gap between the two relays after crossing.
func TestCompositeQuantizationBoundary(t *testing.T) {
	// Setup: epsilon=1.0, lambda=2.0
	//   relay A at MOLS position 0 (determined dynamically)
	//   relay B at MOLS position 1
	//
	// Before boundary cross (load_A = 0.99):
	//   tier_A = floor(0.99/1.0)*1.0 = 0.0
	//   final_A = 0 + 2.0*0.0 = 0.0
	//   final_B = 1 + 2.0*0.0 = 1.0
	//   Order: [A, B]
	//
	// After boundary cross (load_A = 1.01):
	//   tier_A = floor(1.01/1.0)*1.0 = 1.0
	//   final_A = 0 + 2.0*1.0 = 2.0
	//   final_B = 1 + 2.0*0.0 = 1.0
	//   Order: [B, A] — exactly one swap.
	epsilon := 1.0
	lambda := 2.0
	composite := New(mols.New(), WithEpsilon(epsilon), WithLambda(lambda))

	urlA := "https://relay-boundary-a.example.com"
	urlB := "https://relay-boundary-b.example.com"
	client := discovery.ClientState{
		LocalAddress:    "client-boundary",
		MaxActiveRelays: 2,
	}

	// Determine the MOLS order for these two relays (both zero load).
	zeroPool := []discovery.RelayState{
		simpleRelayState(urlA, 0.0, 0.0),
		simpleRelayState(urlB, 0.0, 0.0),
	}
	inner := mols.New()
	molsURLs := mustSelectPriorityURLs(t, inner, zeroPool, client)
	if len(molsURLs) < 2 {
		t.Fatalf("MOLS returned fewer than 2 URLs: %v — bootstrap relay construction broken", molsURLs)
	}
	// firstURL is the one MOLS ranks at position 0; it will receive the high load.
	firstURL := molsURLs[0]
	secondURL := molsURLs[1]

	// Before crossing: load just below boundary.
	poolBefore := []discovery.RelayState{
		simpleRelayState(firstURL, 0.99, 0.0),
		simpleRelayState(secondURL, 0.0, 0.0),
	}
	urlsBefore := mustSelectPriorityURLs(t, composite, poolBefore, client)
	if len(urlsBefore) < 2 {
		t.Fatalf("expected 2 URLs, got %d", len(urlsBefore))
	}
	if urlsBefore[0] != firstURL {
		t.Fatalf("before boundary: expected %q at position 0, got %q", firstURL, urlsBefore[0])
	}

	// After crossing: load just above boundary.
	poolAfter := []discovery.RelayState{
		simpleRelayState(firstURL, 1.01, 0.0),
		simpleRelayState(secondURL, 0.0, 0.0),
	}
	urlsAfter := mustSelectPriorityURLs(t, composite, poolAfter, client)
	if len(urlsAfter) < 2 {
		t.Fatalf("expected 2 URLs, got %d", len(urlsAfter))
	}
	if urlsAfter[0] != secondURL {
		t.Fatalf("after boundary: expected %q at position 0 (swapped), got %q", secondURL, urlsAfter[0])
	}
	if urlsAfter[1] != firstURL {
		t.Fatalf("after boundary: expected %q at position 1 (demoted), got %q", firstURL, urlsAfter[1])
	}

	// Verify no oscillation: second call with same inputs produces same result.
	urlsAfter2 := mustSelectPriorityURLs(t, composite, poolAfter, client)
	for i := range urlsAfter {
		if urlsAfter[i] != urlsAfter2[i] {
			t.Errorf("oscillation at position %d: got %q then %q", i, urlsAfter[i], urlsAfter2[i])
		}
	}
}

// TestCompositeWithBetaComposesFailureRate verifies that a relay with a high
// FailureRate but zero LoadFactor is demoted when beta>0, because the composite
// load formula is load = LoadFactor + FailureRate*beta.
func TestCompositeWithBetaComposesFailureRate(t *testing.T) {
	urlA := "https://relay-beta-a.example.com"
	urlB := "https://relay-beta-b.example.com"
	urlC := "https://relay-beta-c.example.com"

	inner := mols.New()
	client := discovery.ClientState{
		LocalAddress:    "client-beta",
		MaxActiveRelays: 3,
	}

	// Zero-load baseline to determine MOLS ranking.
	zeroPool := []discovery.RelayState{
		simpleRelayState(urlA, 0.0, 0.0),
		simpleRelayState(urlB, 0.0, 0.0),
		simpleRelayState(urlC, 0.0, 0.0),
	}
	molsURLs := mustSelectPriorityURLs(t, inner, zeroPool, client)
	if len(molsURLs) < 2 {
		t.Fatalf("MOLS returned fewer than 2 URLs from 3-relay pool: %v — bootstrap relay construction broken", molsURLs)
	}

	// Give the MOLS top-ranked relay a high failure rate with zero load factor.
	highFailURL := molsURLs[0]
	molsTopPos := 0

	pool := []discovery.RelayState{
		simpleRelayState(highFailURL, 0.0, 5.0), // high failure rate, zero load
	}
	for _, u := range []string{urlA, urlB, urlC} {
		if u != highFailURL {
			pool = append(pool, simpleRelayState(u, 0.0, 0.0))
		}
	}

	// beta=1.0 means failure rate contributes directly to load penalty.
	composite := New(inner, WithLambda(1.0), WithEpsilon(0.1), WithBeta(1.0))
	compositeURLs := mustSelectPriorityURLs(t, composite, pool, client)

	compositePos := indexOf(compositeURLs, highFailURL)
	if compositePos == -1 {
		t.Fatalf("relay %q missing from composite output", highFailURL)
	}
	if compositePos <= molsTopPos {
		t.Fatalf("expected high-failure relay %q to demote below position %d; got composite position %d",
			highFailURL, molsTopPos, compositePos)
	}
}

// TestCompositeName verifies the canonical selector name.
func TestCompositeName(t *testing.T) {
	c := New(mols.New())
	if got := c.Name(); got != "weighted" {
		t.Fatalf("Name() = %q, want %q", got, "weighted")
	}
}

// TestCompositeSelectMultiHopDelegates verifies that SelectMultiHop applies the
// load-penalty reordering to multi-hop relay lists in the same way SelectPriority
// does. The test:
//
//  1. Confirms MultiHopDepth<=1 propagates nil (inner MOLS contract).
//  2. Uses MultiHopDepth=2 with overlay-eligible relays and verifies that a
//     high-load relay that ranks first in the inner MOLS result is demoted by
//     the Composite penalty.
func TestCompositeSelectMultiHopDelegates(t *testing.T) {
	t.Run("nil_for_depth_zero", func(t *testing.T) {
		pool := []discovery.RelayState{
			overlayRelayState("https://relay-mh-a.example.com", 0.0, 0.0),
			overlayRelayState("https://relay-mh-b.example.com", 0.0, 0.0),
		}
		c := New(mols.New())
		urls, _ := c.SelectMultiHop(context.Background(), pool, discovery.ClientState{
			LocalAddress:  "client-mh-nil",
			MultiHopDepth: 0,
		})
		if len(urls) != 0 {
			t.Fatalf("expected nil/empty for MultiHopDepth=0, got %v", urls)
		}
	})

	t.Run("penalty_applied_multihop", func(t *testing.T) {
		urlA := "https://relay-mha.example.com"
		urlB := "https://relay-mhb.example.com"
		urlC := "https://relay-mhc.example.com"

		inner := mols.New()
		client := discovery.ClientState{
			LocalAddress:  "client-mh-penalty",
			MultiHopDepth: 3,
		}

		// Determine MOLS multi-hop order with zero load.
		zeroPool := []discovery.RelayState{
			overlayRelayState(urlA, 0.0, 0.0),
			overlayRelayState(urlB, 0.0, 0.0),
			overlayRelayState(urlC, 0.0, 0.0),
		}
		molsURLs, _ := inner.SelectMultiHop(context.Background(), zeroPool, client)
		if len(molsURLs) < 2 {
			t.Fatalf("inner multi-hop returned fewer than 2 relays: %v — overlay relay construction broken", molsURLs)
		}

		// Give the MOLS top multi-hop relay a very high load.
		highLoadURL := molsURLs[0]

		pool := []discovery.RelayState{
			overlayRelayState(urlA, 0.0, 0.0),
			overlayRelayState(urlB, 0.0, 0.0),
			overlayRelayState(urlC, 0.0, 0.0),
		}
		for i, s := range pool {
			if s.Descriptor.APIHTTPSAddr == highLoadURL {
				pool[i].LoadFactor = 5.0
			}
		}

		composite := New(inner, WithLambda(1.0), WithEpsilon(0.1))
		compositeURLs, _ := composite.SelectMultiHop(context.Background(), pool, client)
		if len(compositeURLs) < 2 {
			t.Fatalf("composite multi-hop returned fewer than 2 relays: %v", compositeURLs)
		}

		compositePos := indexOf(compositeURLs, highLoadURL)
		if compositePos == -1 {
			t.Fatalf("high-load relay %q missing from composite multi-hop output", highLoadURL)
		}
		if compositePos == 0 {
			t.Fatalf("expected high-load relay %q to be demoted from position 0; stayed at %d",
				highLoadURL, compositePos)
		}
	})
}

// TestCompositeDefaultOptions verifies that default option values are applied
// correctly (lambda=1.0, epsilon=0.1, beta=1.0).
func TestCompositeDefaultOptions(t *testing.T) {
	c := New(mols.New())
	if c.lambda != 1.0 {
		t.Errorf("default lambda = %v, want 1.0", c.lambda)
	}
	if c.epsilon != 0.1 {
		t.Errorf("default epsilon = %v, want 0.1", c.epsilon)
	}
	if c.beta != 1.0 {
		t.Errorf("default beta = %v, want 1.0", c.beta)
	}

	// Verify options override defaults.
	c2 := New(mols.New(), WithLambda(2.5), WithEpsilon(0.5), WithBeta(3.0))
	if c2.lambda != 2.5 {
		t.Errorf("WithLambda: got %v, want 2.5", c2.lambda)
	}
	if c2.epsilon != 0.5 {
		t.Errorf("WithEpsilon: got %v, want 0.5", c2.epsilon)
	}
	if c2.beta != 3.0 {
		t.Errorf("WithBeta: got %v, want 3.0", c2.beta)
	}
}
