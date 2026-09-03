package discovery

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// TestMOLSSelectPriorityKeepsExplicitRelaysOutsideAutoLimit verifies that
// explicit relays are always included, outside of MaxActiveRelays.
func TestMOLSSelectPriorityKeepsExplicitRelaysOutsideAutoLimit(t *testing.T) {
	explicitRelay := "https://relay-explicit.example"
	relayA := "https://relay-a.example"
	relayB := "https://relay-b.example"

	selected := SelectPriority([]RelayState{
		bootstrapRelayState(explicitRelay),
		confirmedRelayState(t, relayA),
		confirmedRelayState(t, relayB),
	}, RouteState{
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

// TestMOLSSelectPriorityMaxActiveRelaysLimitsAutoPool ensures that
// MaxActiveRelays caps the auto pool (but not explicit relays).
func TestMOLSSelectPriorityMaxActiveRelaysLimitsAutoPool(t *testing.T) {

	relays := make([]RelayState, 10)
	for i := range relays {
		relays[i] = confirmedRelayState(t, fmt.Sprintf("https://relay-%d.example", i))
	}

	selected := SelectPriority(relays, RouteState{MaxActiveRelays: 3})
	if len(selected) != 3 {
		t.Fatalf("len(selected) = %d, want 3", len(selected))
	}
}

// An unset MaxActiveRelays still bounds automatic selection: fan-out is never
// unlimited by default.
func TestMOLSSelectPriorityZeroMaxActiveRelaysUsesDefault(t *testing.T) {

	relays := make([]RelayState, 10)
	for i := range relays {
		relays[i] = confirmedRelayState(t, fmt.Sprintf("https://relay-default-%d.example", i))
	}

	selected := SelectPriority(relays, RouteState{MaxActiveRelays: 0})
	if len(selected) != defaultMaxActiveRelays {
		t.Fatalf("len(selected) = %d, want %d", len(selected), defaultMaxActiveRelays)
	}
}

func TestMOLSSelectPrioritySkipsExpiredAutoRelay(t *testing.T) {
	expired := confirmedRelayState(t, "https://relay-expired.example")
	expired.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)

	if selected := SelectPriority([]RelayState{expired}, RouteState{}); len(selected) != 0 {
		t.Fatalf("SelectPriority(expired auto) = %v, want empty", selected)
	}
}

func TestMOLSSelectPrioritySkipsBannedRelay(t *testing.T) {
	banned := confirmedRelayState(t, "https://relay-banned.example")
	banned.Banned = true

	if selected := SelectPriority([]RelayState{banned}, RouteState{}); len(selected) != 0 {
		t.Fatalf("SelectPriority(banned) = %v, want empty", selected)
	}
}

func TestMOLSSelectPriorityKeepsExpiredExplicitRelay(t *testing.T) {
	relayURL := "https://relay-explicit-expired.example"
	expired := confirmedRelayState(t, relayURL)
	expired.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)

	selected := SelectPriority([]RelayState{expired}, RouteState{
		ExplicitRelayURLs: []string{relayURL},
	})
	if len(selected) != 1 || selected[0] != relayURL {
		t.Fatalf("SelectPriority(expired explicit) = %v, want [%q]", selected, relayURL)
	}
}

func TestMOLSSelectPriorityKeepsUnobservedAutoSeed(t *testing.T) {
	relayURL := "https://relay-seed.example"

	selected := SelectPriority([]RelayState{bootstrapRelayState(relayURL)}, RouteState{})
	if len(selected) != 1 || selected[0] != relayURL {
		t.Fatalf("SelectPriority(unobserved seed) = %v, want [%q]", selected, relayURL)
	}
}

func TestHashToGridIndexDistribution(t *testing.T) {
	const buckets = 7
	counts := make(map[int]int, buckets)
	for i := 0; i < 1000; i++ {
		addr := fmt.Sprintf("192.168.1.%d:8080", i)
		idx := int(hashToGridIndex(addr) % buckets)
		counts[idx]++
	}
	// Every bucket must receive at least some items without starving
	for b := 0; b < buckets; b++ {
		if counts[b] == 0 {
			t.Errorf("bucket %d received 0 items", b)
		}
	}
}

func TestMOLSP2CPressurePromotion(t *testing.T) {
	relayA := confirmedRelayState(t, "https://relay-a.example")
	relayB := confirmedRelayState(t, "https://relay-b.example")

	// relayA: High load momentum and tail inflation (P90=100ms, P50=10ms)
	relayA.LoadFactor = 0.75
	relayA.EWMALoad = 0.75
	relayA.LoadDelta = 0.2
	for i := 0; i < 90; i++ {
		relayA.RTTTracker.Add(10 * time.Millisecond)
	}
	for i := 0; i < 10; i++ {
		relayA.RTTTracker.Add(100 * time.Millisecond)
	}

	// relayB: Low load and uniform RTT (P90=20ms, P50=20ms)
	relayB.LoadFactor = 0.1
	relayB.EWMALoad = 0.1
	for i := 0; i < 100; i++ {
		relayB.RTTTracker.Add(20 * time.Millisecond)
	}

	if relayA.Pressure() <= relayB.Pressure()+molsP2CPressureDelta {
		t.Fatalf("relayA pressure (%.2f) should exceed relayB pressure (%.2f) + delta (%.2f)",
			relayA.Pressure(), relayB.Pressure(), molsP2CPressureDelta)
	}

	// Behavioral assertion: In SelectPriority with MaxActiveRelays=1, low-pressure relayB
	// must be promoted over high-pressure relayA regardless of initial MOLS order.
	selected := SelectPriority([]RelayState{relayA, relayB}, RouteState{MaxActiveRelays: 1})
	if len(selected) != 1 || selected[0] != "https://relay-b.example" {
		t.Fatalf("SelectPriority with pressure delta = %v, want [%q]", selected, "https://relay-b.example")
	}
}

func TestMOLSSelectPriorityActiveStickiness(t *testing.T) {
	relays := make([]RelayState, 10)
	for i := range relays {
		relays[i] = confirmedRelayState(t, fmt.Sprintf("https://relay-stick-%d.example", i))
	}

	// First selection without active relays
	firstPick := SelectPriority(relays, RouteState{MaxActiveRelays: 2})
	if len(firstPick) != 2 {
		t.Fatalf("len(firstPick) = %d, want 2", len(firstPick))
	}

	// Suppose relay 9 was currently connected and is healthy
	activeRelay := "https://relay-stick-9.example"
	secondPick := SelectPriority(relays, RouteState{
		ActiveRelayURLs: []string{activeRelay},
		MaxActiveRelays: 2,
	})

	if len(secondPick) != 2 {
		t.Fatalf("len(secondPick) = %d, want 2", len(secondPick))
	}
	if !slices.Contains(secondPick, activeRelay) {
		t.Fatalf("secondPick %v should contain activeRelay %q due to stickiness", secondPick, activeRelay)
	}
}

func TestMOLSSelectPriorityEpochRotation(t *testing.T) {
	relays := make([]RelayState, 10)
	for i := range relays {
		relays[i] = confirmedRelayState(t, fmt.Sprintf("https://relay-epoch-%d.example", i))
	}

	routeStateEpoch0 := RouteState{LocalAddress: "192.168.1.50:5000", SelectionEpoch: 0}
	routeStateEpoch1 := RouteState{LocalAddress: "192.168.1.50:5000", SelectionEpoch: 1}

	rank0a := SelectPriority(relays, routeStateEpoch0)
	rank0b := SelectPriority(relays, routeStateEpoch0)
	// Deterministic for same epoch
	if !slices.Equal(rank0a, rank0b) {
		t.Fatalf("rank0a != rank0b: %v vs %v", rank0a, rank0b)
	}

	rank1 := SelectPriority(relays, routeStateEpoch1)
	// Rotation should yield a different primary ranking for non-trivial pool
	if slices.Equal(rank0a, rank1) {
		t.Fatalf("rank1 should differ from rank0, got identical %v", rank1)
	}
}

func TestMOLSVirtualLatencyPenalty(t *testing.T) {
	now := time.Now().UTC()
	relayA := confirmedRelayState(t, "https://relay-a.example")
	relayA.DiscoveryRTT = 50 * time.Millisecond
	relayA.DiscoveryRTTAt = now
	// 7 failures * 300ms = 2.1s penalty => EffectiveRTT = 2.15s (> 2s fallback threshold)
	relayA.activeFailures = 7

	relayB := confirmedRelayState(t, "https://relay-b.example")
	relayB.DiscoveryRTT = 100 * time.Millisecond
	relayB.DiscoveryRTTAt = now

	relayC := confirmedRelayState(t, "https://relay-c.example")
	relayC.DiscoveryRTT = 120 * time.Millisecond
	relayC.DiscoveryRTTAt = now

	relays := []RelayState{relayA, relayB, relayC}
	selected := SelectPriority(relays, RouteState{MaxActiveRelays: 2})

	// relayA should be demoted to fallback tier due to virtual latency, so active picks should be B and C
	if slices.Contains(selected, "https://relay-a.example") {
		t.Fatalf("selected %v should not contain relayA in top 2 due to virtual latency penalty", selected)
	}
	if len(selected) != 2 {
		t.Fatalf("len(selected) = %d, want 2", len(selected))
	}
}

func TestMOLSStickinessDoesNotResurrectSaturatedOrFallback(t *testing.T) {
	now := time.Now().UTC()
	activeSaturated := confirmedRelayState(t, "https://active-sat.example")
	activeSaturated.IsSaturated = true
	activeSaturated.LoadFactor = 0.95

	activeFallback := confirmedRelayState(t, "https://active-fb.example")
	activeFallback.DiscoveryRTT = 3 * time.Second
	activeFallback.DiscoveryRTTAt = now

	healthyA := confirmedRelayState(t, "https://healthy-a.example")
	healthyA.DiscoveryRTT = 50 * time.Millisecond
	healthyA.DiscoveryRTTAt = now

	healthyB := confirmedRelayState(t, "https://healthy-b.example")
	healthyB.DiscoveryRTT = 60 * time.Millisecond
	healthyB.DiscoveryRTTAt = now

	relays := []RelayState{activeSaturated, activeFallback, healthyA, healthyB}

	// ActiveRelayURLs includes the saturated and fallback relays.
	// Stickiness MUST NOT resurrect them over the healthy candidates.
	selected := SelectPriority(relays, RouteState{
		ActiveRelayURLs: []string{"https://active-sat.example", "https://active-fb.example"},
		MaxActiveRelays: 2,
	})

	if len(selected) != 2 {
		t.Fatalf("len(selected) = %d, want 2", len(selected))
	}
	for _, u := range selected {
		if u == "https://active-sat.example" || u == "https://active-fb.example" {
			t.Fatalf("selected %v should not contain demoted relays despite stickiness", selected)
		}
	}
}

func TestMOLSMultiHopEntryStickiness(t *testing.T) {
	now := time.Now().UTC()
	set := NewRelaySet(nil)
	var activeEntry string
	for i := 0; i < 5; i++ {
		url := fmt.Sprintf("https://relay-mh-%d.example", i)
		st := confirmedRelayState(t, url)
		st.Descriptor.SupportsOverlay = true
		st.Descriptor.ExpiresAt = now.Add(time.Hour)
		st.Descriptor.WireGuardPublicKey = "wg-key"
		st.Descriptor.WireGuardPort = 51820
		st.LastSeenAt = now
		set.relays[url] = st
		if i == 4 {
			activeEntry = url
		}
	}

	routes, err := set.PlanRoutes(nil, RouteState{
		ActiveRelayURLs: []string{activeEntry},
		MultiHopDepth:   2,
		MaxActiveRelays: 2,
		LocalAddress:    "client",
	})
	if err != nil {
		t.Fatalf("PlanRoutes failed: %v", err)
	}
	if len(routes) == 0 {
		t.Fatalf("routes is empty")
	}
	// The first entry hop should preserve the active entry relay due to stickiness
	if entry := routes[0].ListenerRelayURL(); entry != activeEntry {
		t.Fatalf("first entry hop = %q, want activeEntry %q due to stickiness", entry, activeEntry)
	}
}

func BenchmarkMOLSRankRelayPool(b *testing.B) {
	localAddr := "test-client-address"
	relays := make([]RelayState, 100)
	for i := range 100 {
		relays[i] = RelayState{
			Descriptor:     types.RelayDescriptor{APIHTTPSAddr: "test"},
			DiscoveryRTT:   100 * time.Millisecond,
			DiscoveryRTTAt: time.Now(),
			Confirmed:      true,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RankRelayPool(relays, localAddr, 0)
	}
}

func BenchmarkMOLSSelectPriorityMassiveScale(b *testing.B) {
	const numRelays = 256
	relayStates := make([]RelayState, numRelays)
	for i := range relayStates {
		relayStates[i] = RelayState{Descriptor: types.RelayDescriptor{APIHTTPSAddr: fmt.Sprintf("https://test-%d.example", i)}}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		routeState := RouteState{LocalAddress: fmt.Sprintf("client-%d", i)}
		SelectPriority(relayStates, routeState)
	}
}

func TestMOLSPressureEvictionAndHealthyStickiness(t *testing.T) {
	now := time.Now().UTC()
	// R0: High pressure active relay
	r0 := confirmedRelayState(t, "https://relay-0.example")
	r0.LoadFactor = 0.8
	r0.EWMALoad = 0.8
	r0.LoadDelta = 0.3
	r0.DiscoveryRTT = 30 * time.Millisecond
	r0.DiscoveryRTTAt = now
	for i := 0; i < 90; i++ {
		r0.RTTTracker.Add(10 * time.Millisecond)
	}
	for i := 0; i < 10; i++ {
		r0.RTTTracker.Add(150 * time.Millisecond)
	}

	// R1, R2, R3, R4: Healthy idle relays
	healthyRelays := make([]RelayState, 4)
	for i := range healthyRelays {
		url := fmt.Sprintf("https://relay-%d.example", i+1)
		st := confirmedRelayState(t, url)
		st.LoadFactor = 0.1
		st.EWMALoad = 0.1
		st.DiscoveryRTT = 40 * time.Millisecond
		st.DiscoveryRTTAt = now
		for j := 0; j < 100; j++ {
			st.RTTTracker.Add(20 * time.Millisecond)
		}
		healthyRelays[i] = st
	}

	// R5: Saturated relay
	r5 := confirmedRelayState(t, "https://relay-5.example")
	r5.IsSaturated = true
	r5.LoadFactor = 0.95

	allRelays := []RelayState{r0, healthyRelays[0], healthyRelays[1], healthyRelays[2], healthyRelays[3], r5}

	// RouteState with MaxActiveRelays = 3, ActiveRelayURLs = [R0, R1, R2]
	rs := RouteState{
		ActiveRelayURLs: []string{
			"https://relay-0.example",
			"https://relay-1.example",
			"https://relay-2.example",
		},
		MaxActiveRelays: 3,
		LocalAddress:    "client-test-addr",
	}

	selected := SelectPriority(allRelays, rs)

	// 1. High-pressure r0 MUST be evicted from active set (membership migration)
	if slices.Contains(selected, "https://relay-0.example") {
		t.Fatalf("high-pressure relay-0 was NOT evicted from active set: %v", selected)
	}

	// 2. Saturated r5 MUST NOT be resurrected
	if slices.Contains(selected, "https://relay-5.example") {
		t.Fatalf("saturated relay-5 was resurrected: %v", selected)
	}

	// 3. Healthy active relays (relay-1, relay-2) MUST be preserved by stickiness
	if !slices.Contains(selected, "https://relay-1.example") || !slices.Contains(selected, "https://relay-2.example") {
		t.Fatalf("healthy active relays were not preserved by stickiness: %v", selected)
	}

	// 4. Exactly MaxActiveRelays (3) selected
	if len(selected) != 3 {
		t.Fatalf("expected 3 selected relays, got %d: %v", len(selected), selected)
	}
}

func TestMOLSSkipsIneligibleRelaysWhenComputingPressureBaseline(t *testing.T) {
	now := time.Now().UTC()

	// Ineligible banned relay with artificially low pressure (0.0)
	banned := confirmedRelayState(t, "https://relay-banned.example")
	banned.Banned = true
	banned.LoadFactor = 0.0
	banned.EWMALoad = 0.0

	// Eligible active relay with moderate pressure (0.35)
	active := confirmedRelayState(t, "https://relay-active.example")
	active.LoadFactor = 0.35
	active.EWMALoad = 0.35
	active.DiscoveryRTT = 50 * time.Millisecond
	active.DiscoveryRTTAt = now

	// Eligible peer with same moderate pressure (0.35)
	peer := confirmedRelayState(t, "https://relay-peer.example")
	peer.LoadFactor = 0.35
	peer.EWMALoad = 0.35
	peer.DiscoveryRTT = 50 * time.Millisecond
	peer.DiscoveryRTTAt = now

	relays := []RelayState{banned, active, peer}
	rs := RouteState{
		ActiveRelayURLs: []string{"https://relay-active.example"},
		MaxActiveRelays: 1,
		LocalAddress:    "client-baseline-test",
	}

	selected := SelectPriority(relays, rs)

	// If banned relay distorted minPressure to 0.0, active (0.35) would be evicted (> 0.30 delta).
	// Because banned is excluded from ranked pool, baseline is 0.35, so active MUST be preserved.
	if len(selected) != 1 || selected[0] != "https://relay-active.example" {
		t.Fatalf("active relay should be preserved by stickiness, got %v", selected)
	}
}
