package diversity_test

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery/selectors/diversity"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery/selectors/mols"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery/selectortest"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// overlayState returns a RelayState that passes all SelectMultiHop eligibility
// gates (HasObservedDescriptor, non-expired ExpiresAt, HasOverlayPeer).
func overlayState(url string) discovery.RelayState {
	now := time.Now().UTC()
	return discovery.RelayState{
		Descriptor: types.RelayDescriptor{
			APIHTTPSAddr:       url,
			IssuedAt:           now,
			ExpiresAt:          now.Add(time.Hour),
			SupportsOverlay:    true,
			WireGuardPublicKey: "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleTA=",
			WireGuardPort:      51820,
		},
		Confirmed:  true,
		LastSeenAt: now,
	}
}

// overlayStateWith returns an overlayState with Family and Subnet16 set.
func overlayStateWith(url, family, subnet16 string) discovery.RelayState {
	rs := overlayState(url)
	rs.Descriptor.Family = family
	rs.Descriptor.Subnet16 = subnet16
	return rs
}

// diversityMOLS returns a fresh diversity.Diversity wrapping a new mols.MOLS.
// Used as the factory for the contract harness.
func diversityMOLS() discovery.Selector {
	return diversity.New(mols.New())
}

// ---------------------------------------------------------------------------
// Contract harness
// ---------------------------------------------------------------------------

// TestDiversityContract runs the full Selector invariant suite (~13 sub-tests)
// against diversity.New(mols.New()).
func TestDiversityContract(t *testing.T) {
	selectortest.Contract(t, "diversity_mols", diversityMOLS)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

// TestDiversityName verifies that Name() returns "<inner>+diversity".
func TestDiversityName(t *testing.T) {
	d := diversity.New(mols.New())
	got := d.Name()
	want := "mols+diversity"
	if got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
}

// TestDiversityPassthroughSelectPriority confirms SelectPriority delegates
// unchanged to the inner selector.
func TestDiversityPassthroughSelectPriority(t *testing.T) {
	inner := mols.New()
	d := diversity.New(inner)
	ctx := context.Background()

	now := time.Now().UTC()
	pool := []discovery.RelayState{
		{
			Descriptor: types.RelayDescriptor{
				APIHTTPSAddr: "https://relay-a.example",
				IssuedAt:     now,
				ExpiresAt:    now.Add(time.Hour),
			},
			Bootstrap: true,
		},
		{
			Descriptor: types.RelayDescriptor{
				APIHTTPSAddr: "https://relay-b.example",
				IssuedAt:     now,
				ExpiresAt:    now.Add(time.Hour),
			},
			Bootstrap: true,
		},
	}
	client := discovery.ClientState{LocalAddress: "passthrough-test"}

	innerURLs, _ := inner.SelectPriority(ctx, pool, client)
	dURLs, _ := d.SelectPriority(ctx, pool, client)

	if len(innerURLs) != len(dURLs) {
		t.Fatalf("SelectPriority length mismatch: inner=%d diversity=%d", len(innerURLs), len(dURLs))
	}
	for i := range innerURLs {
		if innerURLs[i] != dURLs[i] {
			t.Fatalf("SelectPriority[%d]: inner=%q diversity=%q; want identical output", i, innerURLs[i], dURLs[i])
		}
	}
}

// TestDiversityNoOpWhenAllDisabled verifies that when DisableDiversityRoles=true
// and AnonymityGrade=false, SelectMultiHop output equals inner.SelectMultiHop.
func TestDiversityNoOpWhenAllDisabled(t *testing.T) {
	inner := mols.New()
	d := diversity.New(inner)
	ctx := context.Background()

	pool := []discovery.RelayState{
		overlayState("https://relay-1.example"),
		overlayState("https://relay-2.example"),
		overlayState("https://relay-3.example"),
	}
	client := discovery.ClientState{
		LocalAddress:          "noop-test",
		MultiHopDepth:         3,
		DisableDiversityRoles: true,
		AnonymityGrade:        false,
	}

	innerURLs, _ := inner.SelectMultiHop(ctx, pool, client)
	dURLs, _ := d.SelectMultiHop(ctx, pool, client)

	if len(innerURLs) != len(dURLs) {
		t.Fatalf("NoOp: length mismatch: inner=%d diversity=%d", len(innerURLs), len(dURLs))
	}
	for i := range innerURLs {
		if innerURLs[i] != dURLs[i] {
			t.Fatalf("NoOp: output[%d]: inner=%q diversity=%q; want identical output when all constraints disabled", i, innerURLs[i], dURLs[i])
		}
	}
}

// TestDiversityZeroDuplicateRelays verifies that with 3 distinct overlay relays
// and MultiHopDepth=3, the output has 3 distinct URLs.
func TestDiversityZeroDuplicateRelays(t *testing.T) {
	d := diversity.New(mols.New())
	ctx := context.Background()

	pool := []discovery.RelayState{
		overlayState("https://relay-a.example"),
		overlayState("https://relay-b.example"),
		overlayState("https://relay-c.example"),
	}
	client := discovery.ClientState{
		LocalAddress:  "dedup-test",
		MultiHopDepth: 3,
	}

	urls, _ := d.SelectMultiHop(ctx, pool, client)
	if len(urls) != 3 {
		t.Fatalf("want 3 URLs, got %d: %v", len(urls), urls)
	}
	seen := make(map[string]struct{}, 3)
	for _, u := range urls {
		if _, dup := seen[u]; dup {
			t.Fatalf("duplicate URL in output: %q (full output: %v)", u, urls)
		}
		seen[u] = struct{}{}
	}
}

// TestDiversityZeroSubnet16Collisions verifies that with AnonymityGrade=true
// and MultiHopDepth=2, the two selected relays have distinct Subnet16 values.
// Pool has 3 relays with distinct Subnet16 and 3 with the same Subnet16.
func TestDiversityZeroSubnet16Collisions(t *testing.T) {
	d := diversity.New(mols.New())
	ctx := context.Background()

	pool := []discovery.RelayState{
		overlayStateWith("https://diverse-a.example", "op-a", "10.1"),
		overlayStateWith("https://diverse-b.example", "op-b", "10.2"),
		overlayStateWith("https://diverse-c.example", "op-c", "10.3"),
		overlayStateWith("https://same-1.example", "op-d", "10.0"),
		overlayStateWith("https://same-2.example", "op-e", "10.0"),
		overlayStateWith("https://same-3.example", "op-f", "10.0"),
	}
	client := discovery.ClientState{
		LocalAddress:   "subnet16-test",
		MultiHopDepth:  2,
		AnonymityGrade: true,
	}

	urls, _ := d.SelectMultiHop(ctx, pool, client)
	if len(urls) != 2 {
		t.Fatalf("want 2 URLs, got %d: %v", len(urls), urls)
	}

	// Collect Subnet16 values; assert uniqueness.
	stateByURL := make(map[string]discovery.RelayState, len(pool))
	for _, rs := range pool {
		stateByURL[rs.Descriptor.APIHTTPSAddr] = rs
	}
	usedSubnets := make(map[string]struct{}, 2)
	for _, u := range urls {
		rs, ok := stateByURL[u]
		if !ok {
			t.Fatalf("output URL %q not found in pool; selector returned an unknown relay", u)
		}
		s := rs.Descriptor.Subnet16
		if s == "" {
			continue
		}
		if _, dup := usedSubnets[s]; dup {
			t.Fatalf("Subnet16 collision: %q appears more than once in output %v", s, urls)
		}
		usedSubnets[s] = struct{}{}
	}
}

// TestDiversitySubnet16ForcesRelaxation verifies that when ALL relays share the
// same Subnet16, AnonymityGrade triggers relaxation for MultiHopDepth=2.
// The counter portal_discovery_diversity_relaxed_total{reason="anonymity_grade"}
// must increment by exactly 1.
func TestDiversitySubnet16ForcesRelaxation(t *testing.T) {
	d := diversity.New(mols.New())
	ctx := context.Background()

	// All 3 relays share the same Subnet16 — impossible to satisfy anonymity_grade.
	pool := []discovery.RelayState{
		overlayStateWith("https://same-subnet-a.example", "op-a", "10.99"),
		overlayStateWith("https://same-subnet-b.example", "op-b", "10.99"),
		overlayStateWith("https://same-subnet-c.example", "op-c", "10.99"),
	}
	client := discovery.ClientState{
		LocalAddress:   "relaxation-test",
		MultiHopDepth:  2,
		AnonymityGrade: true,
	}

	// Capture baseline counter value before the call.
	counterBefore := testutil.ToFloat64(
		discovery.DiversityRelaxedTotal.WithLabelValues("anonymity_grade"),
	)

	urls, _ := d.SelectMultiHop(ctx, pool, client)

	// Must still return a non-empty result after relaxation.
	if len(urls) == 0 {
		t.Fatal("want non-empty result after AnonymityGrade relaxation, got empty")
	}

	// Counter must have incremented by exactly 1.
	counterAfter := testutil.ToFloat64(
		discovery.DiversityRelaxedTotal.WithLabelValues("anonymity_grade"),
	)
	if delta := counterAfter - counterBefore; delta != 1.0 {
		t.Fatalf("portal_discovery_diversity_relaxed_total{reason=anonymity_grade} delta = %.0f, want 1", delta)
	}
}

// TestDiversityFamilyDedup verifies that with AnonymityGrade=true and a pool
// containing relays with various Family values, no two selected relays share
// the same Family.
func TestDiversityFamilyDedup(t *testing.T) {
	d := diversity.New(mols.New())
	ctx := context.Background()

	// 3 relays with distinct families, 2 extras sharing one of those families.
	pool := []discovery.RelayState{
		overlayStateWith("https://family-a1.example", "op-a", "10.1"),
		overlayStateWith("https://family-b1.example", "op-b", "10.2"),
		overlayStateWith("https://family-c1.example", "op-c", "10.3"),
		overlayStateWith("https://family-a2.example", "op-a", "10.4"), // same family as a1
		overlayStateWith("https://family-a3.example", "op-a", "10.5"), // same family as a1
	}
	client := discovery.ClientState{
		LocalAddress:   "family-test",
		MultiHopDepth:  3,
		AnonymityGrade: true,
	}

	urls, _ := d.SelectMultiHop(ctx, pool, client)
	if len(urls) != 3 {
		t.Fatalf("want 3 URLs, got %d: %v", len(urls), urls)
	}

	stateByURL := make(map[string]discovery.RelayState, len(pool))
	for _, rs := range pool {
		stateByURL[rs.Descriptor.APIHTTPSAddr] = rs
	}

	usedFamilies := make(map[string]struct{}, 3)
	for _, u := range urls {
		rs, ok := stateByURL[u]
		if !ok {
			t.Fatalf("output URL %q not found in pool; selector returned an unknown relay", u)
		}
		f := rs.Descriptor.Family
		if f == "" {
			continue
		}
		if _, dup := usedFamilies[f]; dup {
			t.Fatalf("Family collision: %q appears more than once in output %v", f, urls)
		}
		usedFamilies[f] = struct{}{}
	}
}
