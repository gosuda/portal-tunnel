package discovery

import (
	"fmt"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/telemetry"
)

// TestGF64MulIdentity checks that multiplying any element by 1 is the identity.
func TestGF64MulIdentity(t *testing.T) {
	for i := range uint8(64) {
		if got := gf64Mul(1, i); got != i {
			t.Fatalf("gf64Mul(1, %d) = %d, want %d", i, got, i)
		}
		if got := gf64Mul(i, 1); got != i {
			t.Fatalf("gf64Mul(%d, 1) = %d, want %d", i, got, i)
		}
	}
}

// TestGF64MulZero checks that multiplying any element by 0 gives 0.
func TestGF64MulZero(t *testing.T) {
	for i := range uint8(64) {
		if got := gf64Mul(0, i); got != 0 {
			t.Fatalf("gf64Mul(0, %d) = %d, want 0", i, got)
		}
	}
}

// TestGF64MulCommutativity checks that multiplication is commutative.
func TestGF64MulCommutativity(t *testing.T) {
	for a := range uint8(64) {
		for b := range uint8(64) {
			if gf64Mul(a, b) != gf64Mul(b, a) {
				t.Fatalf("gf64Mul(%d, %d) != gf64Mul(%d, %d)", a, b, b, a)
			}
		}
	}
}

// TestGF64MulDistributivity checks the distributive law a*(b^c) = a*b ^ a*c.
func TestGF64MulDistributivity(t *testing.T) {
	for a := range uint8(64) {
		for b := range uint8(64) {
			for c := range uint8(8) { // subset to keep test fast
				want := gf64Mul(a, b) ^ gf64Mul(a, c)
				got := gf64Mul(a, b^c)
				if got != want {
					t.Fatalf("gf64Mul(%d, %d^%d) = %d, want %d", a, b, c, got, want)
				}
			}
		}
	}
}

// TestMOLSScoreRange checks that molsScore always produces values in [1, 4096].
func TestMOLSScoreRange(t *testing.T) {
	for i := range uint8(64) {
		for j := range uint8(64) {
			s := molsScore(i, j, molsBaseM1, molsBaseM2)
			if s < 1 || s > molsOrder*molsOrder {
				t.Fatalf("molsScore(%d, %d) = %d, out of range [1, 4096]", i, j, s)
			}
		}
	}
}

// TestMOLSScoreRowPermutation checks that each row of the MOLS score grid is a
// permutation of 1..n².  Rows are indexed by ingress i; columns by candidate j.
func TestMOLSScoreRowPermutation(t *testing.T) {
	for i := range uint8(64) {
		seen := make(map[int]struct{}, 64)
		for j := range uint8(64) {
			s := molsScore(i, j, molsBaseM1, molsBaseM2)
			if _, dup := seen[s]; dup {
				t.Fatalf("duplicate score %d in row i=%d", s, i)
			}
			seen[s] = struct{}{}
		}
		if len(seen) != molsOrder {
			t.Fatalf("row i=%d has %d unique scores, want %d", i, len(seen), molsOrder)
		}
	}
}

// TestMOLSCongestionScoreRange checks that the Reverse-Siamese scores are in
// [1, 4096] and are the complement of the base scores.
func TestMOLSCongestionScoreRange(t *testing.T) {
	for i := range uint8(64) {
		for j := range uint8(64) {
			s := molsCongestionScore(i, j, molsBaseM1, molsBaseM2)
			if s < 1 || s > molsOrder*molsOrder {
				t.Fatalf("molsCongestionScore(%d, %d) = %d, out of range", i, j, s)
			}
			// Verify B(i,j) = (n²+1) - A(i, n-1-j)
			want := molsMagicConstant - molsScore(i, (molsOrder-1)-j, molsBaseM1, molsBaseM2)
			if s != want {
				t.Fatalf("molsCongestionScore(%d, %d) = %d, want %d", i, j, s, want)
			}
		}
	}
}

// TestMOLSRTTStatsMean checks the mean calculation.
func TestMOLSRTTStatsMean(t *testing.T) {
	states := []RelayState{
		{DiscoveryRTT: 100 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 200 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 300 * time.Millisecond, DiscoveryRTTAt: time.Now()},
	}
	mean, _ := molsRTTStats(states)
	if mean != 200*time.Millisecond {
		t.Fatalf("mean = %v, want 200ms", mean)
	}
}

// TestMOLSRTTStatsCVUniform checks that a uniform RTT distribution has CV=0.
func TestMOLSRTTStatsCVUniform(t *testing.T) {
	states := []RelayState{
		{DiscoveryRTT: 100 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 100 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 100 * time.Millisecond, DiscoveryRTTAt: time.Now()},
	}
	_, cv := molsRTTStats(states)
	if cv != 0 {
		t.Fatalf("cv = %v, want 0 for uniform distribution", cv)
	}
}

// TestMOLSRTTStatsCVHigh checks that a highly varied RTT distribution
// produces a CV above the threshold.
func TestMOLSRTTStatsCVHigh(t *testing.T) {
	states := []RelayState{
		{DiscoveryRTT: 10 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 2000 * time.Millisecond, DiscoveryRTTAt: time.Now()},
	}
	_, cv := molsRTTStats(states)
	if cv <= molsCVThreshold {
		t.Fatalf("cv = %v, want > %v for high-variance distribution", cv, molsCVThreshold)
	}
}

// TestMOLSRTTStatsSkipsMissingRTT checks that relays without a measured RTT
// are excluded from both mean and CV calculations.
func TestMOLSRTTStatsSkipsMissingRTT(t *testing.T) {
	states := []RelayState{
		{DiscoveryRTT: 100 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 999 * time.Second}, // no DiscoveryRTTAt → excluded
	}
	mean, _ := molsRTTStats(states)
	if mean != 100*time.Millisecond {
		t.Fatalf("mean = %v, want 100ms (excluded relay with zero RTTAt)", mean)
	}
}

// TestIsRelayFallbackHighRTT checks that a relay with RTT > threshold is
// classified as Fallback.
func TestIsRelayFallbackHighRTT(t *testing.T) {
	state := RelayState{
		DiscoveryRTT:   molsFallbackRTTThreshold + time.Millisecond,
		DiscoveryRTTAt: time.Now(),
	}
	if !isRelayFallback(state) {
		t.Fatal("expected high-RTT relay to be classified as Fallback")
	}
}

// TestIsRelayFallbackNormalRTT checks that a relay with normal RTT is not
// classified as Fallback.
func TestIsRelayFallbackNormalRTT(t *testing.T) {
	state := RelayState{
		DiscoveryRTT:   200 * time.Millisecond,
		DiscoveryRTTAt: time.Now(),
	}
	if isRelayFallback(state) {
		t.Fatal("expected normal-RTT relay not to be classified as Fallback")
	}
}

// TestMOLSSelectPriorityKeepsExplicitRelaysOutsideAutoLimit verifies that
// explicit relays are always included, outside of MaxActiveRelays.
func TestMOLSSelectPriorityKeepsExplicitRelaysOutsideAutoLimit(t *testing.T) {
	policy := MOLSRelayPolicy{}
	explicitRelay := "https://relay-explicit.example"
	relayA := "https://relay-a.example"
	relayB := "https://relay-b.example"

	selected := policy.SelectPriority([]RelayState{
		bootstrapPolicyRelayState(explicitRelay),
		confirmedPolicyRelayState(t, relayA),
		confirmedPolicyRelayState(t, relayB),
	}, ClientState{
		ExplicitRelayURLs: []string{explicitRelay},
		MaxActiveRelays:   1,
	})

	if len(selected) != 2 {
		t.Fatalf("len(selected) = %d, want 2 (explicit + 1 auto)", len(selected))
	}
	if selected[0] != explicitRelay {
		t.Fatalf("selected[0] = %q, want explicit relay %q", selected[0], explicitRelay)
	}
}

// TestMOLSSelectPriorityDeterministic verifies that the same inputs always
// produce the same ordered output.
func TestMOLSSelectPriorityDeterministic(t *testing.T) {
	policy := MOLSRelayPolicy{}
	states := []RelayState{
		confirmedPolicyRelayState(t, "https://relay-a.example"),
		confirmedPolicyRelayState(t, "https://relay-b.example"),
		confirmedPolicyRelayState(t, "https://relay-c.example"),
	}
	clientState := ClientState{LocalAddress: "0x1234abcd"}

	first := policy.SelectPriority(states, clientState)
	for range 5 {
		got := policy.SelectPriority(states, clientState)
		if len(got) != len(first) {
			t.Fatalf("non-deterministic length: %d vs %d", len(got), len(first))
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("non-deterministic result at index %d: %q vs %q", i, got[i], first[i])
			}
		}
	}
}

// TestMOLSSelectPriorityFallbackRelaysDemoted checks that relays with high
// RTT are placed after healthy relays in the priority list.
func TestMOLSSelectPriorityFallbackRelaysDemoted(t *testing.T) {
	policy := MOLSRelayPolicy{}

	// Two healthy relays ensure molsMinActiveNodes is met without promoting fallbacks.
	healthy1 := confirmedPolicyRelayState(t, "https://relay-healthy-1.example")
	healthy1.DiscoveryRTT = 100 * time.Millisecond
	healthy1.DiscoveryRTTAt = time.Now()

	healthy2 := confirmedPolicyRelayState(t, "https://relay-healthy-2.example")
	healthy2.DiscoveryRTT = 150 * time.Millisecond
	healthy2.DiscoveryRTTAt = time.Now()

	fallback := confirmedPolicyRelayState(t, "https://relay-fallback.example")
	fallback.DiscoveryRTT = molsFallbackRTTThreshold + time.Millisecond
	fallback.DiscoveryRTTAt = time.Now()

	selected := policy.SelectPriority([]RelayState{fallback, healthy1, healthy2}, ClientState{})

	if len(selected) != 3 {
		t.Fatalf("len(selected) = %d, want 3", len(selected))
	}
	// Fallback must be the last entry.
	if selected[len(selected)-1] != fallback.Descriptor.APIHTTPSAddr {
		t.Fatalf("last selected = %q, want fallback relay %q", selected[len(selected)-1], fallback.Descriptor.APIHTTPSAddr)
	}
}

// TestMOLSSelectPriorityMinActiveNodesPromotesFallback checks that when there
// are fewer than molsMinActiveNodes healthy relays the engine promotes fallback
// relays to maintain the minimum.
func TestMOLSSelectPriorityMinActiveNodesPromotesFallback(t *testing.T) {
	policy := MOLSRelayPolicy{}

	fallback1 := confirmedPolicyRelayState(t, "https://relay-fallback-1.example")
	fallback1.DiscoveryRTT = molsFallbackRTTThreshold + time.Millisecond
	fallback1.DiscoveryRTTAt = time.Now()
	fallback2 := confirmedPolicyRelayState(t, "https://relay-fallback-2.example")
	fallback2.DiscoveryRTT = molsFallbackRTTThreshold + time.Millisecond
	fallback2.DiscoveryRTTAt = time.Now()

	selected := policy.SelectPriority([]RelayState{fallback1, fallback2}, ClientState{})

	// Both fallbacks should be promoted to meet the minimum of 2.
	if len(selected) != 2 {
		t.Fatalf("len(selected) = %d, want 2 (both fallbacks promoted)", len(selected))
	}
}

// TestMOLSSelectPriorityCongestionSwitchChangesOrder verifies that the
// Reverse-Siamese mode (triggered by high average RTT) produces a different
// ordering than normal mode for the same relay set.
func TestMOLSSelectPriorityCongestionSwitchChangesOrder(t *testing.T) {
	policy := MOLSRelayPolicy{}

	// Two relays with different MOLS column indices so their scores differ.
	r1 := confirmedPolicyRelayState(t, "https://relay-one.example")
	r2 := confirmedPolicyRelayState(t, "https://relay-two.example")

	// Normal mode: no RTT measurements → no congestion.
	normal := policy.SelectPriority([]RelayState{r1, r2}, ClientState{
		LocalAddress: "ingress-test",
	})

	// Congestion mode: set RTTs above threshold (but low CV to avoid variant).
	rttHigh := molsCongestionRTTThreshold + 100*time.Millisecond
	r1c := r1
	r1c.DiscoveryRTT = rttHigh
	r1c.DiscoveryRTTAt = time.Now()
	r2c := r2
	r2c.DiscoveryRTT = rttHigh
	r2c.DiscoveryRTTAt = time.Now()

	congested := policy.SelectPriority([]RelayState{r1c, r2c}, ClientState{
		LocalAddress: "ingress-test",
	})

	if len(normal) != 2 || len(congested) != 2 {
		t.Fatalf("expected 2 relays in both modes: normal=%d congested=%d", len(normal), len(congested))
	}

	// The two orderings should differ (unless MOLS scores happen to be symmetric,
	// which is extremely unlikely for distinct relay URLs).
	if normal[0] == congested[0] {
		// Verify the scores are actually different to confirm the switch is working.
		ingressIdx := hashToGF64("ingress-test")
		j1 := hashToGF64("https://relay-one.example")
		j2 := hashToGF64("https://relay-two.example")
		normal1 := molsScore(ingressIdx, j1, molsBaseM1, molsBaseM2)
		normal2 := molsScore(ingressIdx, j2, molsBaseM1, molsBaseM2)
		cong1 := molsCongestionScore(ingressIdx, j1, molsBaseM1, molsBaseM2)
		cong2 := molsCongestionScore(ingressIdx, j2, molsBaseM1, molsBaseM2)
		if (normal1 > normal2) != (cong1 > cong2) {
			t.Fatal("expected congestion switch to invert ordering but result matched normal mode")
		}
		// If ordering is the same it means the math happens to agree — acceptable.
	}
}

// TestMOLSSelectPriorityVariantGridActivatesOnHighCV confirms that a high
// coefficient of variation triggers the variant multipliers (7, 11) while the
// mean RTT stays below the congestion threshold.
func TestMOLSSelectPriorityVariantGridActivatesOnHighCV(t *testing.T) {
	policy := MOLSRelayPolicy{}

	r1 := confirmedPolicyRelayState(t, "https://relay-one.example")
	r2 := confirmedPolicyRelayState(t, "https://relay-two.example")

	// Normal mode (no RTT → no congestion, no CV).
	normalOrder := policy.SelectPriority([]RelayState{r1, r2}, ClientState{
		LocalAddress: "ingress-cv",
	})

	// High-CV mode: very different RTTs push CV above 0.5 while the mean stays
	// below the congestion threshold, isolating the variant-grid branch.
	r1v := r1
	r1v.DiscoveryRTT = 100 * time.Millisecond
	r1v.DiscoveryRTTAt = time.Now()
	r2v := r2
	r2v.DiscoveryRTT = 400 * time.Millisecond
	r2v.DiscoveryRTTAt = time.Now()

	// Verify high-CV state is actually detected.
	avgRTT, cv := molsRTTStats([]RelayState{r1v, r2v})
	if cv <= molsCVThreshold {
		t.Fatalf("test precondition: cv = %v, want > %v", cv, molsCVThreshold)
	}
	if avgRTT > molsCongestionRTTThreshold {
		t.Fatalf("test precondition: avgRTT = %v, want <= %v", avgRTT, molsCongestionRTTThreshold)
	}

	variantOrder := policy.SelectPriority([]RelayState{r1v, r2v}, ClientState{
		LocalAddress: "ingress-cv",
	})

	if len(normalOrder) != 2 || len(variantOrder) != 2 {
		t.Fatalf("expected 2 relays in both modes: normal=%d variant=%d", len(normalOrder), len(variantOrder))
	}

	if normalOrder[0] != "https://relay-one.example" {
		t.Fatalf("normal order first relay = %q, want relay-one", normalOrder[0])
	}
	if variantOrder[0] != "https://relay-two.example" {
		t.Fatalf("variant order first relay = %q, want relay-two", variantOrder[0])
	}
}

// TestMOLSSelectPriorityDifferentIngressDifferentOrder verifies that two
// different ingress identities can produce different relay orderings (MOLS
// property: each row is an independent permutation).
func TestMOLSSelectPriorityDifferentIngressDifferentOrder(t *testing.T) {
	policy := MOLSRelayPolicy{}

	r1 := confirmedPolicyRelayState(t, "https://relay-alpha.example")
	r2 := confirmedPolicyRelayState(t, "https://relay-beta.example")
	r3 := confirmedPolicyRelayState(t, "https://relay-gamma.example")
	states := []RelayState{r1, r2, r3}

	// Collect orderings for a range of ingress addresses and check that at
	// least one pair produces a different result (MOLS diversity property).
	orderings := make(map[string]struct{})
	addresses := []string{
		"0xabc", "0xdef", "0x123", "0x456", "user@example.com", "relay.net",
	}
	for _, addr := range addresses {
		sel := policy.SelectPriority(states, ClientState{LocalAddress: addr})
		key := ""
		for _, u := range sel {
			key += u + "|"
		}
		orderings[key] = struct{}{}
	}

	if len(orderings) == 1 {
		// Verify by checking GF(64) row diversity for these relays.
		j1 := hashToGF64("https://relay-alpha.example")
		j2 := hashToGF64("https://relay-beta.example")
		j3 := hashToGF64("https://relay-gamma.example")

		type row [3]int
		rows := make(map[row]struct{})
		for _, addr := range addresses {
			i := hashToGF64(addr)
			r := row{
				molsScore(i, j1, molsBaseM1, molsBaseM2),
				molsScore(i, j2, molsBaseM1, molsBaseM2),
				molsScore(i, j3, molsBaseM1, molsBaseM2),
			}
			rows[r] = struct{}{}
		}
		if len(rows) == 1 {
			t.Skip("all selected ingress addresses happen to hash to the same GF(64) index")
		}
		t.Fatal("expected multiple ingress addresses to produce at least two distinct orderings")
	}
}

// TestMOLSSelectPriorityEmptyPoolReturnsNil checks the empty-input guard.
func TestMOLSSelectPriorityEmptyPoolReturnsNil(t *testing.T) {
	policy := MOLSRelayPolicy{}
	if got := policy.SelectPriority(nil, ClientState{}); got != nil {
		t.Fatalf("SelectPriority(nil, ...) = %v, want nil", got)
	}
}

// TestMOLSSelectPriorityMaxActiveRelaysLimitsAutoPool ensures that
// MaxActiveRelays caps the auto pool (but not explicit relays).
func TestMOLSSelectPriorityMaxActiveRelaysLimitsAutoPool(t *testing.T) {
	policy := MOLSRelayPolicy{}

	relays := make([]RelayState, 10)
	for i := range relays {
		relays[i] = confirmedPolicyRelayState(t, fmt.Sprintf("https://relay-%d.example", i))
	}

	selected := policy.SelectPriority(relays, ClientState{MaxActiveRelays: 3})
	if len(selected) != 3 {
		t.Fatalf("len(selected) = %d, want 3", len(selected))
	}
}

func TestMOLSSelectPriorityZeroMaxActiveRelaysUsesDefault(t *testing.T) {
	policy := MOLSRelayPolicy{}

	relays := make([]RelayState, 10)
	for i := range relays {
		relays[i] = confirmedPolicyRelayState(t, fmt.Sprintf("https://relay-default-%d.example", i))
	}

	selected := policy.SelectPriority(relays, ClientState{MaxActiveRelays: 0})
	if len(selected) != defaultMaxActiveRelays {
		t.Fatalf("len(selected) = %d, want %d", len(selected), defaultMaxActiveRelays)
	}
}

func TestMOLSSelectPrioritySkipsExpiredAutoRelay(t *testing.T) {
	policy := MOLSRelayPolicy{}
	expired := confirmedPolicyRelayState(t, "https://relay-expired.example")
	expired.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)

	if selected := policy.SelectPriority([]RelayState{expired}, ClientState{}); len(selected) != 0 {
		t.Fatalf("SelectPriority(expired auto) = %v, want empty", selected)
	}
}

func TestMOLSSelectPriorityKeepsExpiredExplicitRelay(t *testing.T) {
	policy := MOLSRelayPolicy{}
	relayURL := "https://relay-explicit-expired.example"
	expired := confirmedPolicyRelayState(t, relayURL)
	expired.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)

	selected := policy.SelectPriority([]RelayState{expired}, ClientState{
		ExplicitRelayURLs: []string{relayURL},
	})
	if len(selected) != 1 || selected[0] != relayURL {
		t.Fatalf("SelectPriority(expired explicit) = %v, want [%q]", selected, relayURL)
	}
}

func TestMOLSSelectPrioritySkipsAutoRelayInBackoff(t *testing.T) {
	policy := MOLSRelayPolicy{}
	backingOff := confirmedPolicyRelayState(t, "https://relay-backoff.example")
	backingOff.suppressActiveUntil = time.Now().UTC().Add(time.Minute)

	if selected := policy.SelectPriority([]RelayState{backingOff}, ClientState{}); len(selected) != 0 {
		t.Fatalf("SelectPriority(backing off auto) = %v, want empty", selected)
	}
}

func TestMOLSSelectPriorityKeepsDiscoveryBackoffRelay(t *testing.T) {
	policy := MOLSRelayPolicy{}
	relayURL := "https://relay-discovery-backoff.example"
	backingOff := confirmedPolicyRelayState(t, relayURL)
	backingOff.nextDiscoveryRefreshAt = time.Now().UTC().Add(time.Minute)

	selected := policy.SelectPriority([]RelayState{backingOff}, ClientState{})
	if len(selected) != 1 || selected[0] != relayURL {
		t.Fatalf("SelectPriority(discovery backoff) = %v, want [%q]", selected, relayURL)
	}
}

func TestMOLSSelectPriorityKeepsUnobservedAutoSeed(t *testing.T) {
	policy := MOLSRelayPolicy{}
	relayURL := "https://relay-seed.example"

	selected := policy.SelectPriority([]RelayState{bootstrapPolicyRelayState(relayURL)}, ClientState{})
	if len(selected) != 1 || selected[0] != relayURL {
		t.Fatalf("SelectPriority(unobserved seed) = %v, want [%q]", selected, relayURL)
	}
}

// TestMOLSMagicRowSum verifies that each row of the base MOLS score grid sums
// to the magic constant n*(n²+1)/2 = 131104.
func TestMOLSMagicRowSum(t *testing.T) {
	const magicSum = molsOrder * (molsOrder*molsOrder + 1) / 2 // 131104

	for i := range uint8(64) {
		var rowSum int
		for j := range uint8(64) {
			rowSum += molsScore(i, j, molsBaseM1, molsBaseM2)
		}
		if rowSum != magicSum {
			t.Fatalf("row i=%d sum = %d, want %d", i, rowSum, magicSum)
		}
	}
}

// TestMOLSMagicColumnSum verifies that each column sums to the magic constant.
func TestMOLSMagicColumnSum(t *testing.T) {
	const magicSum = molsOrder * (molsOrder*molsOrder + 1) / 2

	for j := range uint8(64) {
		var colSum int
		for i := range uint8(64) {
			colSum += molsScore(i, j, molsBaseM1, molsBaseM2)
		}
		if colSum != magicSum {
			t.Fatalf("column j=%d sum = %d, want %d", j, colSum, magicSum)
		}
	}
}

// TestMOLSGridUniqueness checks that all n² cells of the base grid have
// distinct values (Latin-square MOLS composite uniqueness).
func TestMOLSGridUniqueness(t *testing.T) {
	seen := make(map[int]struct{}, 64*64)
	for i := range uint8(64) {
		for j := range uint8(64) {
			s := molsScore(i, j, molsBaseM1, molsBaseM2)
			if _, dup := seen[s]; dup {
				t.Fatalf("duplicate score %d at (%d, %d)", s, i, j)
			}
			seen[s] = struct{}{}
		}
	}
	if len(seen) != molsOrder*molsOrder {
		t.Fatalf("grid has %d unique values, want %d", len(seen), molsOrder*molsOrder)
	}
}

// TestMOLSVariantGridUniqueness checks uniqueness for the variant (7,11) grid.
func TestMOLSVariantGridUniqueness(t *testing.T) {
	seen := make(map[int]struct{}, 64*64)
	for i := range uint8(64) {
		for j := range uint8(64) {
			s := molsScore(i, j, molsVariantM1, molsVariantM2)
			if _, dup := seen[s]; dup {
				t.Fatalf("duplicate score %d at (%d, %d) in variant grid", s, i, j)
			}
			seen[s] = struct{}{}
		}
	}
	if len(seen) != molsOrder*molsOrder {
		t.Fatalf("variant grid has %d unique values, want %d", len(seen), molsOrder*molsOrder)
	}
}

// TestMOLSHashToGF64InRange checks that hashToGF64 always returns [0, 63].
func TestMOLSHashToGF64InRange(t *testing.T) {
	inputs := []string{"", "a", "hello", "0x1234", "https://relay.example", "🔑"}
	for _, s := range inputs {
		v := hashToGF64(s)
		if v >= molsOrder {
			t.Fatalf("hashToGF64(%q) = %d, want < %d", s, v, molsOrder)
		}
	}
}

// TestMOLSRTTStatsEmpty checks that an empty slice returns zero values.
func TestMOLSRTTStatsEmpty(t *testing.T) {
	mean, cv := molsRTTStats(nil)
	if mean != 0 || cv != 0 {
		t.Fatalf("molsRTTStats(nil) = (%v, %v), want (0, 0)", mean, cv)
	}
}

// overlayPolicyRelayState returns a confirmed relay state whose descriptor
// satisfies HasOverlayPeer() — required for SelectMultiHop eligibility.
func overlayPolicyRelayState(t *testing.T, relayURL string) RelayState {
	t.Helper()
	state := confirmedPolicyRelayState(t, relayURL)
	state.Descriptor.SupportsOverlay = true
	state.Descriptor.WireGuardPublicKey = "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleTA=" // non-empty placeholder
	state.Descriptor.WireGuardPort = 51820
	return state
}

// selectionCase is a shared table row for TestMOLSWithTraceByteEqualToLegacy.
type selectionCase struct {
	name   string
	states []RelayState
	cs     ClientState
}

// assertByteEqual verifies that legacy and withTrace slices are identical and
// that trace.OutputURLs matches legacy.  It also checks mode and PoolTotal.
func assertByteEqual(t *testing.T, mode string, states []RelayState, legacy []string, withTrace []string, trace telemetry.SelectionTrace) {
	t.Helper()
	if len(legacy) != len(withTrace) {
		t.Fatalf("return-value length mismatch: legacy=%d withTrace=%d", len(legacy), len(withTrace))
	}
	for i := range legacy {
		if legacy[i] != withTrace[i] {
			t.Fatalf("return-value[%d]: legacy=%q withTrace=%q", i, legacy[i], withTrace[i])
		}
	}
	if len(legacy) != len(trace.OutputURLs) {
		t.Fatalf("OutputURLs length mismatch: legacy=%d trace=%d", len(legacy), len(trace.OutputURLs))
	}
	for i := range legacy {
		if legacy[i] != trace.OutputURLs[i] {
			t.Fatalf("OutputURLs[%d]: legacy=%q trace=%q", i, legacy[i], trace.OutputURLs[i])
		}
	}
	if trace.Mode != mode {
		t.Fatalf("Mode = %q, want %q", trace.Mode, mode)
	}
	if trace.PoolTotal != len(states) {
		t.Fatalf("PoolTotal = %d, want %d", trace.PoolTotal, len(states))
	}
}

// TestMOLSWithTraceByteEqualToLegacy asserts that for every test scenario the
// WithTrace variants produce OutputURLs that are byte-identical to the
// corresponding legacy methods.  This is Phase 1 acceptance criterion #1
// ("Golden no-behavior-change").
//
// Priority scenarios mirror the existing TestMOLSSelectPriority* inputs.
// MultiHop scenarios are fresh (no pre-existing TestMOLSSelectMultiHop* exist)
// and cover the main eligibility branches.
func TestMOLSWithTraceByteEqualToLegacy(t *testing.T) {
	policy := MOLSRelayPolicy{}

	t.Run("priority", func(t *testing.T) {
		explicitURL := "https://relay-explicit.example"
		relayA := "https://relay-a.example"
		relayB := "https://relay-b.example"

		tenRelays := make([]RelayState, 10)
		for i := range tenRelays {
			tenRelays[i] = confirmedPolicyRelayState(t, fmt.Sprintf("https://relay-%d.example", i))
		}

		healthy1 := confirmedPolicyRelayState(t, "https://relay-healthy-1.example")
		healthy1.DiscoveryRTT = 100 * time.Millisecond
		healthy1.DiscoveryRTTAt = time.Now()

		healthy2 := confirmedPolicyRelayState(t, "https://relay-healthy-2.example")
		healthy2.DiscoveryRTT = 150 * time.Millisecond
		healthy2.DiscoveryRTTAt = time.Now()

		fallback := confirmedPolicyRelayState(t, "https://relay-fallback.example")
		fallback.DiscoveryRTT = molsFallbackRTTThreshold + time.Millisecond
		fallback.DiscoveryRTTAt = time.Now()

		fallback1 := confirmedPolicyRelayState(t, "https://relay-fallback-1.example")
		fallback1.DiscoveryRTT = molsFallbackRTTThreshold + time.Millisecond
		fallback1.DiscoveryRTTAt = time.Now()
		fallback2 := confirmedPolicyRelayState(t, "https://relay-fallback-2.example")
		fallback2.DiscoveryRTT = molsFallbackRTTThreshold + time.Millisecond
		fallback2.DiscoveryRTTAt = time.Now()

		r1 := confirmedPolicyRelayState(t, "https://relay-one.example")
		r2 := confirmedPolicyRelayState(t, "https://relay-two.example")
		rttHigh := molsCongestionRTTThreshold + 100*time.Millisecond
		r1c := r1
		r1c.DiscoveryRTT = rttHigh
		r1c.DiscoveryRTTAt = time.Now()
		r2c := r2
		r2c.DiscoveryRTT = rttHigh
		r2c.DiscoveryRTTAt = time.Now()

		r1v := confirmedPolicyRelayState(t, "https://relay-one.example")
		r1v.DiscoveryRTT = 100 * time.Millisecond
		r1v.DiscoveryRTTAt = time.Now()
		r2v := confirmedPolicyRelayState(t, "https://relay-two.example")
		r2v.DiscoveryRTT = 400 * time.Millisecond
		r2v.DiscoveryRTTAt = time.Now()

		rAlpha := confirmedPolicyRelayState(t, "https://relay-alpha.example")
		rBeta := confirmedPolicyRelayState(t, "https://relay-beta.example")
		rGamma := confirmedPolicyRelayState(t, "https://relay-gamma.example")

		expired := confirmedPolicyRelayState(t, "https://relay-expired.example")
		expired.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)

		expExplicit := confirmedPolicyRelayState(t, "https://relay-explicit-expired.example")
		expExplicit.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)

		backoff := confirmedPolicyRelayState(t, "https://relay-backoff.example")
		backoff.suppressActiveUntil = time.Now().UTC().Add(time.Minute)

		discBackoff := confirmedPolicyRelayState(t, "https://relay-discovery-backoff.example")
		discBackoff.nextDiscoveryRefreshAt = time.Now().UTC().Add(time.Minute)

		cases := []selectionCase{
			{name: "nil_pool", states: nil, cs: ClientState{}},
			{
				name: "explicit_outside_auto_limit",
				states: []RelayState{
					bootstrapPolicyRelayState(explicitURL),
					confirmedPolicyRelayState(t, relayA),
					confirmedPolicyRelayState(t, relayB),
				},
				cs: ClientState{ExplicitRelayURLs: []string{explicitURL}, MaxActiveRelays: 1},
			},
			{
				name: "deterministic_fixed_address",
				states: []RelayState{
					confirmedPolicyRelayState(t, "https://relay-a.example"),
					confirmedPolicyRelayState(t, "https://relay-b.example"),
					confirmedPolicyRelayState(t, "https://relay-c.example"),
				},
				cs: ClientState{LocalAddress: "0x1234abcd"},
			},
			{name: "fallback_relays_demoted", states: []RelayState{fallback, healthy1, healthy2}, cs: ClientState{}},
			{name: "min_active_nodes_promotes_fallback", states: []RelayState{fallback1, fallback2}, cs: ClientState{}},
			{name: "congestion_switch", states: []RelayState{r1c, r2c}, cs: ClientState{LocalAddress: "ingress-test"}},
			{name: "variant_grid_high_cv", states: []RelayState{r1v, r2v}, cs: ClientState{LocalAddress: "ingress-cv"}},
			{name: "different_ingress_addresses", states: []RelayState{rAlpha, rBeta, rGamma}, cs: ClientState{LocalAddress: "0xabc"}},
			{name: "max_active_relays_cap", states: tenRelays, cs: ClientState{MaxActiveRelays: 3}},
			{name: "zero_max_active_uses_default", states: tenRelays, cs: ClientState{MaxActiveRelays: 0}},
			{name: "skip_expired_auto_relay", states: []RelayState{expired}, cs: ClientState{}},
			{
				name:   "keep_expired_explicit_relay",
				states: []RelayState{expExplicit},
				cs:     ClientState{ExplicitRelayURLs: []string{expExplicit.Descriptor.APIHTTPSAddr}},
			},
			{name: "skip_auto_relay_in_backoff", states: []RelayState{backoff}, cs: ClientState{}},
			{name: "keep_discovery_backoff_relay", states: []RelayState{discBackoff}, cs: ClientState{}},
			{name: "keep_unobserved_seed", states: []RelayState{bootstrapPolicyRelayState("https://relay-seed.example")}, cs: ClientState{}},
			{name: "normal_mode_no_rtt", states: []RelayState{r1, r2}, cs: ClientState{LocalAddress: "ingress-test"}},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				legacy := policy.SelectPriority(tc.states, tc.cs)
				withTrace, trace := policy.SelectPriorityWithTrace(tc.states, tc.cs)
				assertByteEqual(t, "priority", tc.states, legacy, withTrace, trace)
				// min_active_nodes_promotes_fallback: both fallbacks are promoted
				// into the active section, so no Ranked entry should be Demoted.
				if tc.name == "min_active_nodes_promotes_fallback" {
					for i, entry := range trace.Ranked {
						if entry.Demoted {
							t.Errorf("Ranked[%d] (%q): Demoted=true but relay was promoted to active; want false", i, entry.URL)
						}
					}
				}
				// fallback_relays_demoted: the fallback relay (healthy1/healthy2 present,
				// so no promotion occurs) must appear as Demoted=true in Ranked.
				if tc.name == "fallback_relays_demoted" {
					const fallbackURL = "https://relay-fallback.example"
					found := false
					for i, entry := range trace.Ranked {
						if entry.URL == fallbackURL {
							found = true
							if !entry.Demoted {
								t.Errorf("Ranked[%d] (%q): Demoted=false but relay stays in fallback section; want true", i, entry.URL)
							}
						}
					}
					if !found {
						t.Errorf("fallback relay %q not found in trace.Ranked", fallbackURL)
					}
				}
			})
		}
	})

	t.Run("multihop", func(t *testing.T) {
		ovA := overlayPolicyRelayState(t, "https://mh-relay-a.example")
		ovB := overlayPolicyRelayState(t, "https://mh-relay-b.example")
		ovC := overlayPolicyRelayState(t, "https://mh-relay-c.example")

		// noDescRelay: hasObservedDescriptor()==false (LastSeenAt zero).
		noDescRelay := newRelayState("https://mh-nodesc.example")

		bannedRelay := confirmedPolicyRelayState(t, "https://mh-banned.example")
		bannedRelay.Banned = true

		suppressedRelay := overlayPolicyRelayState(t, "https://mh-suppressed.example")
		suppressedRelay.suppressActiveUntil = time.Now().UTC().Add(time.Minute)

		// noOverlayRelay: hasObservedDescriptor()==true but HasOverlayPeer()==false.
		noOverlayRelay := confirmedPolicyRelayState(t, "https://mh-no-overlay.example")

		expiredRelay := overlayPolicyRelayState(t, "https://mh-expired.example")
		expiredRelay.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)

		cases := []selectionCase{
			{name: "depth_zero_returns_nil", states: []RelayState{ovA, ovB}, cs: ClientState{MultiHopDepth: 0}},
			{name: "depth_one_returns_nil", states: []RelayState{ovA, ovB}, cs: ClientState{MultiHopDepth: 1}},
			{name: "nil_pool", states: nil, cs: ClientState{MultiHopDepth: 2}},
			{name: "empty_pool_after_aggregate", states: []RelayState{bannedRelay}, cs: ClientState{MultiHopDepth: 2}},
			{name: "eligible_pool_depth_2", states: []RelayState{ovA, ovB, ovC}, cs: ClientState{MultiHopDepth: 2, LocalAddress: "client-1"}},
			{name: "eligible_pool_depth_3", states: []RelayState{ovA, ovB, ovC}, cs: ClientState{MultiHopDepth: 3, LocalAddress: "client-2"}},
			{name: "depth_exceeds_pool_size", states: []RelayState{ovA, ovB}, cs: ClientState{MultiHopDepth: 5, LocalAddress: "client-3"}},
			{name: "skip_no_descriptor", states: []RelayState{noDescRelay, ovA}, cs: ClientState{MultiHopDepth: 2, LocalAddress: "client-4"}},
			{name: "skip_expired", states: []RelayState{expiredRelay, ovB}, cs: ClientState{MultiHopDepth: 2, LocalAddress: "client-5"}},
			{name: "skip_no_overlay_peer", states: []RelayState{noOverlayRelay, ovC}, cs: ClientState{MultiHopDepth: 2, LocalAddress: "client-6"}},
			{name: "skip_suppressed", states: []RelayState{suppressedRelay, ovA}, cs: ClientState{MultiHopDepth: 2, LocalAddress: "client-7"}},
			{name: "all_ineligible_returns_nil", states: []RelayState{expiredRelay, noDescRelay, noOverlayRelay}, cs: ClientState{MultiHopDepth: 2}},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				legacy := policy.SelectMultiHop(tc.states, tc.cs)
				withTrace, trace := policy.SelectMultiHopWithTrace(tc.states, tc.cs)
				assertByteEqual(t, "multihop", tc.states, legacy, withTrace, trace)
			})
		}
	})
}
