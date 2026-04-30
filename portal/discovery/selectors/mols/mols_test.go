package mols

import (
	"fmt"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func mustPolicyRelayDescriptor(t *testing.T, relayURL string) types.RelayDescriptor {
	t.Helper()
	signing, err := utils.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("ResolveSecp256k1Identity() error = %v", err)
	}
	now := time.Now().UTC()
	signed, err := auth.SignRelayDescriptor(types.RelayDescriptor{
		Address:      signing.Address,
		Version:      types.DiscoveryVersion,
		IssuedAt:     now,
		ExpiresAt:    now.Add(time.Hour),
		APIHTTPSAddr: relayURL,
	}, signing.PrivateKey)
	if err != nil {
		t.Fatalf("SignRelayDescriptor() error = %v", err)
	}
	return signed
}

func bootstrapPolicyRelayState(relayURL string) discovery.RelayState {
	return discovery.RelayState{
		Descriptor: types.RelayDescriptor{
			APIHTTPSAddr: relayURL,
		},
		Bootstrap: true,
	}
}

func confirmedPolicyRelayState(t *testing.T, relayURL string) discovery.RelayState {
	t.Helper()
	return discovery.RelayState{
		Descriptor: mustPolicyRelayDescriptor(t, relayURL),
		Confirmed:  true,
		LastSeenAt: time.Now().UTC(),
	}
}

func overlayPolicyRelayState(t *testing.T, relayURL string) discovery.RelayState {
	t.Helper()
	state := confirmedPolicyRelayState(t, relayURL)
	state.Descriptor.SupportsOverlay = true
	state.Descriptor.WireGuardPublicKey = "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleTA=" // non-empty placeholder
	state.Descriptor.WireGuardPort = 51820
	return state
}

// ---------------------------------------------------------------------------
// GF(64) math tests
// ---------------------------------------------------------------------------

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

func TestGF64MulZero(t *testing.T) {
	for i := range uint8(64) {
		if got := gf64Mul(0, i); got != 0 {
			t.Fatalf("gf64Mul(0, %d) = %d, want 0", i, got)
		}
	}
}

func TestGF64MulCommutativity(t *testing.T) {
	for a := range uint8(64) {
		for b := range uint8(64) {
			if gf64Mul(a, b) != gf64Mul(b, a) {
				t.Fatalf("gf64Mul(%d, %d) != gf64Mul(%d, %d)", a, b, b, a)
			}
		}
	}
}

func TestGF64MulDistributivity(t *testing.T) {
	for a := range uint8(64) {
		for b := range uint8(64) {
			for c := range uint8(8) {
				want := gf64Mul(a, b) ^ gf64Mul(a, c)
				got := gf64Mul(a, b^c)
				if got != want {
					t.Fatalf("gf64Mul(%d, %d^%d) = %d, want %d", a, b, c, got, want)
				}
			}
		}
	}
}

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

func TestMOLSCongestionScoreRange(t *testing.T) {
	for i := range uint8(64) {
		for j := range uint8(64) {
			s := molsCongestionScore(i, j, molsBaseM1, molsBaseM2)
			if s < 1 || s > molsOrder*molsOrder {
				t.Fatalf("molsCongestionScore(%d, %d) = %d, out of range", i, j, s)
			}
			want := molsMagicConstant - molsScore(i, (molsOrder-1)-j, molsBaseM1, molsBaseM2)
			if s != want {
				t.Fatalf("molsCongestionScore(%d, %d) = %d, want %d", i, j, s, want)
			}
		}
	}
}

func TestMOLSRTTStatsMean(t *testing.T) {
	states := []discovery.RelayState{
		{DiscoveryRTT: 100 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 200 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 300 * time.Millisecond, DiscoveryRTTAt: time.Now()},
	}
	mean, _ := molsRTTStats(states)
	if mean != 200*time.Millisecond {
		t.Fatalf("mean = %v, want 200ms", mean)
	}
}

func TestMOLSRTTStatsCVUniform(t *testing.T) {
	states := []discovery.RelayState{
		{DiscoveryRTT: 100 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 100 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 100 * time.Millisecond, DiscoveryRTTAt: time.Now()},
	}
	_, cv := molsRTTStats(states)
	if cv != 0 {
		t.Fatalf("cv = %v, want 0 for uniform distribution", cv)
	}
}

func TestMOLSRTTStatsCVHigh(t *testing.T) {
	states := []discovery.RelayState{
		{DiscoveryRTT: 10 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 2000 * time.Millisecond, DiscoveryRTTAt: time.Now()},
	}
	_, cv := molsRTTStats(states)
	if cv <= molsCVThreshold {
		t.Fatalf("cv = %v, want > %v for high-variance distribution", cv, molsCVThreshold)
	}
}

func TestMOLSRTTStatsSkipsMissingRTT(t *testing.T) {
	states := []discovery.RelayState{
		{DiscoveryRTT: 100 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 999 * time.Second}, // no DiscoveryRTTAt → excluded
	}
	mean, _ := molsRTTStats(states)
	if mean != 100*time.Millisecond {
		t.Fatalf("mean = %v, want 100ms (excluded relay with zero RTTAt)", mean)
	}
}

func TestIsRelayFallbackHighRTT(t *testing.T) {
	state := discovery.RelayState{
		DiscoveryRTT:   molsFallbackRTTThreshold + time.Millisecond,
		DiscoveryRTTAt: time.Now(),
	}
	if !isRelayFallback(state) {
		t.Fatal("expected high-RTT relay to be classified as Fallback")
	}
}

func TestIsRelayFallbackNormalRTT(t *testing.T) {
	state := discovery.RelayState{
		DiscoveryRTT:   200 * time.Millisecond,
		DiscoveryRTTAt: time.Now(),
	}
	if isRelayFallback(state) {
		t.Fatal("expected normal-RTT relay not to be classified as Fallback")
	}
}

func TestMOLSMagicRowSum(t *testing.T) {
	const magicSum = molsOrder * (molsOrder*molsOrder + 1) / 2

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

func TestMOLSHashToGF64InRange(t *testing.T) {
	inputs := []string{"", "a", "hello", "0x1234", "https://relay.example", "🔑"}
	for _, s := range inputs {
		v := hashToGF64(s)
		if v >= molsOrder {
			t.Fatalf("hashToGF64(%q) = %d, want < %d", s, v, molsOrder)
		}
	}
}

func TestMOLSRTTStatsEmpty(t *testing.T) {
	mean, cv := molsRTTStats(nil)
	if mean != 0 || cv != 0 {
		t.Fatalf("molsRTTStats(nil) = (%v, %v), want (0, 0)", mean, cv)
	}
}

// ---------------------------------------------------------------------------
// Policy tests (no unexported RelayState fields)
// ---------------------------------------------------------------------------

func TestMOLSSelectPriorityKeepsExplicitRelaysOutsideAutoLimit(t *testing.T) {
	policy := New()
	explicitRelay := "https://relay-explicit.example"
	relayA := "https://relay-a.example"
	relayB := "https://relay-b.example"

	selected, _ := policy.SelectPriorityWithTrace([]discovery.RelayState{
		bootstrapPolicyRelayState(explicitRelay),
		confirmedPolicyRelayState(t, relayA),
		confirmedPolicyRelayState(t, relayB),
	}, discovery.ClientState{
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

func TestMOLSSelectPriorityDeterministic(t *testing.T) {
	policy := New()
	states := []discovery.RelayState{
		confirmedPolicyRelayState(t, "https://relay-a.example"),
		confirmedPolicyRelayState(t, "https://relay-b.example"),
		confirmedPolicyRelayState(t, "https://relay-c.example"),
	}
	clientState := discovery.ClientState{LocalAddress: "0x1234abcd"}

	first, _ := policy.SelectPriorityWithTrace(states, clientState)
	for range 5 {
		got, _ := policy.SelectPriorityWithTrace(states, clientState)
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

func TestMOLSSelectPriorityFallbackRelaysDemoted(t *testing.T) {
	policy := New()

	healthy1 := confirmedPolicyRelayState(t, "https://relay-healthy-1.example")
	healthy1.DiscoveryRTT = 100 * time.Millisecond
	healthy1.DiscoveryRTTAt = time.Now()

	healthy2 := confirmedPolicyRelayState(t, "https://relay-healthy-2.example")
	healthy2.DiscoveryRTT = 150 * time.Millisecond
	healthy2.DiscoveryRTTAt = time.Now()

	fallback := confirmedPolicyRelayState(t, "https://relay-fallback.example")
	fallback.DiscoveryRTT = molsFallbackRTTThreshold + time.Millisecond
	fallback.DiscoveryRTTAt = time.Now()

	selected, trace := policy.SelectPriorityWithTrace([]discovery.RelayState{fallback, healthy1, healthy2}, discovery.ClientState{})

	if len(selected) != 3 {
		t.Fatalf("len(selected) = %d, want 3", len(selected))
	}
	if selected[len(selected)-1] != fallback.Descriptor.APIHTTPSAddr {
		t.Fatalf("last selected = %q, want fallback relay %q", selected[len(selected)-1], fallback.Descriptor.APIHTTPSAddr)
	}

	if len(trace.Ranked) != 3 {
		t.Fatalf("len(trace.Ranked) = %d, want 3", len(trace.Ranked))
	}
	fallbackURL := fallback.Descriptor.APIHTTPSAddr
	foundFallback := false
	for _, entry := range trace.Ranked {
		if entry.URL == fallbackURL {
			foundFallback = true
			if !entry.Demoted {
				t.Errorf("trace.Ranked entry for fallback URL %q has Demoted=false, want true", fallbackURL)
			}
		} else if entry.Demoted {
			t.Errorf("trace.Ranked entry for non-fallback URL %q has Demoted=true, want false", entry.URL)
		}
	}
	if !foundFallback {
		t.Errorf("fallback URL %q not found in trace.Ranked", fallbackURL)
	}
}

func TestMOLSSelectPriorityMinActiveNodesPromotesFallback(t *testing.T) {
	policy := New()

	fallback1 := confirmedPolicyRelayState(t, "https://relay-fallback-1.example")
	fallback1.DiscoveryRTT = molsFallbackRTTThreshold + time.Millisecond
	fallback1.DiscoveryRTTAt = time.Now()
	fallback2 := confirmedPolicyRelayState(t, "https://relay-fallback-2.example")
	fallback2.DiscoveryRTT = molsFallbackRTTThreshold + time.Millisecond
	fallback2.DiscoveryRTTAt = time.Now()

	selected, trace := policy.SelectPriorityWithTrace([]discovery.RelayState{fallback1, fallback2}, discovery.ClientState{})

	if len(selected) != 2 {
		t.Fatalf("len(selected) = %d, want 2 (both fallbacks promoted)", len(selected))
	}

	if len(trace.Ranked) != 2 {
		t.Fatalf("len(trace.Ranked) = %d, want 2", len(trace.Ranked))
	}
	rankedURLs := map[string]bool{
		fallback1.Descriptor.APIHTTPSAddr: false,
		fallback2.Descriptor.APIHTTPSAddr: false,
	}
	for _, entry := range trace.Ranked {
		if _, ok := rankedURLs[entry.URL]; !ok {
			t.Errorf("unexpected URL %q in trace.Ranked", entry.URL)
		}
		rankedURLs[entry.URL] = true
		if entry.Demoted {
			t.Errorf("trace.Ranked entry for URL %q has Demoted=true, want false (all fallbacks promoted)", entry.URL)
		}
	}
	for url, seen := range rankedURLs {
		if !seen {
			t.Errorf("expected URL %q missing from trace.Ranked", url)
		}
	}
}

func TestMOLSSelectPriorityCongestionSwitchChangesOrder(t *testing.T) {
	policy := New()

	r1 := confirmedPolicyRelayState(t, "https://relay-one.example")
	r2 := confirmedPolicyRelayState(t, "https://relay-two.example")

	normal, _ := policy.SelectPriorityWithTrace([]discovery.RelayState{r1, r2}, discovery.ClientState{
		LocalAddress: "ingress-test",
	})

	rttHigh := molsCongestionRTTThreshold + 100*time.Millisecond
	r1c := r1
	r1c.DiscoveryRTT = rttHigh
	r1c.DiscoveryRTTAt = time.Now()
	r2c := r2
	r2c.DiscoveryRTT = rttHigh
	r2c.DiscoveryRTTAt = time.Now()

	congested, _ := policy.SelectPriorityWithTrace([]discovery.RelayState{r1c, r2c}, discovery.ClientState{
		LocalAddress: "ingress-test",
	})

	if len(normal) != 2 || len(congested) != 2 {
		t.Fatalf("expected 2 relays in both modes: normal=%d congested=%d", len(normal), len(congested))
	}

	if normal[0] == congested[0] {
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
	}
}

func TestMOLSSelectPriorityVariantGridActivatesOnHighCV(t *testing.T) {
	policy := New()

	r1 := confirmedPolicyRelayState(t, "https://relay-one.example")
	r2 := confirmedPolicyRelayState(t, "https://relay-two.example")

	normalOrder, _ := policy.SelectPriorityWithTrace([]discovery.RelayState{r1, r2}, discovery.ClientState{
		LocalAddress: "ingress-cv",
	})

	r1v := r1
	r1v.DiscoveryRTT = 100 * time.Millisecond
	r1v.DiscoveryRTTAt = time.Now()
	r2v := r2
	r2v.DiscoveryRTT = 400 * time.Millisecond
	r2v.DiscoveryRTTAt = time.Now()

	avgRTT, cv := molsRTTStats([]discovery.RelayState{r1v, r2v})
	if cv <= molsCVThreshold {
		t.Fatalf("test precondition: cv = %v, want > %v", cv, molsCVThreshold)
	}
	if avgRTT > molsCongestionRTTThreshold {
		t.Fatalf("test precondition: avgRTT = %v, want <= %v", avgRTT, molsCongestionRTTThreshold)
	}

	variantOrder, _ := policy.SelectPriorityWithTrace([]discovery.RelayState{r1v, r2v}, discovery.ClientState{
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

func TestMOLSSelectPriorityDifferentIngressDifferentOrder(t *testing.T) {
	policy := New()

	r1 := confirmedPolicyRelayState(t, "https://relay-alpha.example")
	r2 := confirmedPolicyRelayState(t, "https://relay-beta.example")
	r3 := confirmedPolicyRelayState(t, "https://relay-gamma.example")
	states := []discovery.RelayState{r1, r2, r3}

	orderings := make(map[string]struct{})
	addresses := []string{
		"0xabc", "0xdef", "0x123", "0x456", "user@example.com", "relay.net",
	}
	for _, addr := range addresses {
		sel, _ := policy.SelectPriorityWithTrace(states, discovery.ClientState{LocalAddress: addr})
		key := ""
		for _, u := range sel {
			key += u + "|"
		}
		orderings[key] = struct{}{}
	}

	if len(orderings) == 1 {
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

func TestMOLSSelectPriorityEmptyPoolReturnsNil(t *testing.T) {
	policy := New()
	got, _ := policy.SelectPriorityWithTrace(nil, discovery.ClientState{})
	if got != nil {
		t.Fatalf("SelectPriorityWithTrace(nil, ...) = %v, want nil", got)
	}
}

func TestMOLSSelectPriorityMaxActiveRelaysLimitsAutoPool(t *testing.T) {
	policy := New()

	relays := make([]discovery.RelayState, 10)
	for i := range relays {
		relays[i] = confirmedPolicyRelayState(t, fmt.Sprintf("https://relay-%d.example", i))
	}

	selected, _ := policy.SelectPriorityWithTrace(relays, discovery.ClientState{MaxActiveRelays: 3})
	if len(selected) != 3 {
		t.Fatalf("len(selected) = %d, want 3", len(selected))
	}
}

func TestMOLSSelectPriorityZeroMaxActiveRelaysUsesDefault(t *testing.T) {
	policy := New()

	relays := make([]discovery.RelayState, 10)
	for i := range relays {
		relays[i] = confirmedPolicyRelayState(t, fmt.Sprintf("https://relay-default-%d.example", i))
	}

	selected, _ := policy.SelectPriorityWithTrace(relays, discovery.ClientState{MaxActiveRelays: 0})
	if len(selected) != defaultMaxActiveRelays {
		t.Fatalf("len(selected) = %d, want %d", len(selected), defaultMaxActiveRelays)
	}
}

func TestMOLSSelectPrioritySkipsExpiredAutoRelay(t *testing.T) {
	policy := New()
	expired := confirmedPolicyRelayState(t, "https://relay-expired.example")
	expired.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)

	selected, _ := policy.SelectPriorityWithTrace([]discovery.RelayState{expired}, discovery.ClientState{})
	if len(selected) != 0 {
		t.Fatalf("SelectPriorityWithTrace(expired auto) = %v, want empty", selected)
	}
}

func TestMOLSSelectPriorityKeepsExpiredExplicitRelay(t *testing.T) {
	policy := New()
	relayURL := "https://relay-explicit-expired.example"
	expired := confirmedPolicyRelayState(t, relayURL)
	expired.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)

	selected, _ := policy.SelectPriorityWithTrace([]discovery.RelayState{expired}, discovery.ClientState{
		ExplicitRelayURLs: []string{relayURL},
	})
	if len(selected) != 1 || selected[0] != relayURL {
		t.Fatalf("SelectPriorityWithTrace(expired explicit) = %v, want [%q]", selected, relayURL)
	}
}

func TestMOLSSelectAggregateKeepsBootstrapRelayWhenDescriptorExpired(t *testing.T) {
	policy := New()
	relayURL := "https://relay-bootstrap.example"

	state := bootstrapPolicyRelayState(relayURL)
	state.LastSeenAt = time.Now().UTC().Add(-time.Minute)
	state.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Second)

	selected := policy.SelectAggregate([]discovery.RelayState{state})

	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d, want 1", len(selected))
	}
	if got := selected[0].Descriptor.APIHTTPSAddr; got != relayURL {
		t.Fatalf("selected[0] = %q, want %q", got, relayURL)
	}
}

func TestMOLSSelectPriorityKeepsUnobservedAutoSeed(t *testing.T) {
	policy := New()
	relayURL := "https://relay-seed.example"

	selected, _ := policy.SelectPriorityWithTrace([]discovery.RelayState{bootstrapPolicyRelayState(relayURL)}, discovery.ClientState{})
	if len(selected) != 1 || selected[0] != relayURL {
		t.Fatalf("SelectPriorityWithTrace(unobserved seed) = %v, want [%q]", selected, relayURL)
	}
}

// ---------------------------------------------------------------------------
// SelectMultiHop tests
// ---------------------------------------------------------------------------

func TestMOLSSelectMultiHopDepthZeroReturnsNil(t *testing.T) {
	policy := New()
	ovA := overlayPolicyRelayState(t, "https://mh-relay-a.example")
	ovB := overlayPolicyRelayState(t, "https://mh-relay-b.example")

	selected, _ := policy.SelectMultiHopWithTrace([]discovery.RelayState{ovA, ovB}, discovery.ClientState{MultiHopDepth: 0})
	if selected != nil {
		t.Fatalf("SelectMultiHopWithTrace(depth=0) = %v, want nil", selected)
	}
}

func TestMOLSSelectMultiHopDepthOneReturnsNil(t *testing.T) {
	policy := New()
	ovA := overlayPolicyRelayState(t, "https://mh-relay-a.example")
	ovB := overlayPolicyRelayState(t, "https://mh-relay-b.example")

	selected, _ := policy.SelectMultiHopWithTrace([]discovery.RelayState{ovA, ovB}, discovery.ClientState{MultiHopDepth: 1})
	if selected != nil {
		t.Fatalf("SelectMultiHopWithTrace(depth=1) = %v, want nil", selected)
	}
}

func TestMOLSSelectMultiHopEligiblePool(t *testing.T) {
	policy := New()
	ovA := overlayPolicyRelayState(t, "https://mh-relay-a.example")
	ovB := overlayPolicyRelayState(t, "https://mh-relay-b.example")
	ovC := overlayPolicyRelayState(t, "https://mh-relay-c.example")

	selected, _ := policy.SelectMultiHopWithTrace([]discovery.RelayState{ovA, ovB, ovC}, discovery.ClientState{MultiHopDepth: 2, LocalAddress: "client-1"})
	if len(selected) != 2 {
		t.Fatalf("len(selected) = %d, want 2", len(selected))
	}
}

func TestMOLSSelectMultiHopDepthExceedsPool(t *testing.T) {
	policy := New()
	ovA := overlayPolicyRelayState(t, "https://mh-relay-a.example")
	ovB := overlayPolicyRelayState(t, "https://mh-relay-b.example")

	selected, _ := policy.SelectMultiHopWithTrace([]discovery.RelayState{ovA, ovB}, discovery.ClientState{MultiHopDepth: 5, LocalAddress: "client-3"})
	if len(selected) > 2 {
		t.Fatalf("len(selected) = %d, want <= 2", len(selected))
	}
}

func TestMOLSSelectMultiHopSkipsNoOverlayPeer(t *testing.T) {
	policy := New()
	noOverlayRelay := confirmedPolicyRelayState(t, "https://mh-no-overlay.example")
	ovC := overlayPolicyRelayState(t, "https://mh-relay-c.example")

	selected, _ := policy.SelectMultiHopWithTrace([]discovery.RelayState{noOverlayRelay, ovC}, discovery.ClientState{MultiHopDepth: 2, LocalAddress: "client-6"})
	for _, url := range selected {
		if url == noOverlayRelay.Descriptor.APIHTTPSAddr {
			t.Fatalf("no-overlay relay should be excluded from multihop selection")
		}
	}
}
