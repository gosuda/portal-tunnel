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
		RankRelayPool(relays, localAddr)
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
