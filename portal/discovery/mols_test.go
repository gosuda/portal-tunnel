package discovery

import (
	"fmt"
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

// TestMOLSSelectPriorityDeterministic verifies that the same inputs always
// produce the same ordered output.
func TestMOLSSelectPriorityDeterministic(t *testing.T) {
	states := []RelayState{
		confirmedRelayState(t, "https://relay-a.example"),
		confirmedRelayState(t, "https://relay-b.example"),
		confirmedRelayState(t, "https://relay-c.example"),
	}
	routeState := RouteState{LocalAddress: "0x1234abcd"}

	first := SelectPriority(states, routeState)
	for range 5 {
		got := SelectPriority(states, routeState)
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
// RTT are demoted behind healthy relays instead of being dropped.
func TestMOLSSelectPriorityFallbackRelaysDemoted(t *testing.T) {

	// Two healthy relays ensure molsMinActiveNodes is met without promoting fallbacks.
	healthy1 := confirmedRelayState(t, "https://relay-healthy-1.example")
	healthy1.DiscoveryRTT = 100 * time.Millisecond
	healthy1.DiscoveryRTTAt = time.Now()
	healthy1.LoadFactor = 0.1 // Explicitly healthy

	healthy2 := confirmedRelayState(t, "https://relay-healthy-2.example")
	healthy2.DiscoveryRTT = 150 * time.Millisecond
	healthy2.DiscoveryRTTAt = time.Now()
	healthy2.LoadFactor = 0.1 // Explicitly healthy

	fallback := confirmedRelayState(t, "https://relay-fallback.example")
	fallback.DiscoveryRTT = molsFallbackRTTThreshold + time.Millisecond
	fallback.DiscoveryRTTAt = time.Now()
	fallback.LoadFactor = 0.1 // Explicitly healthy, but will be demoted by high RTT (isRelayFallback)

	selected := SelectPriority([]RelayState{fallback, healthy1, healthy2}, RouteState{})

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

	fallback1 := confirmedRelayState(t, "https://relay-fallback-1.example")
	fallback1.DiscoveryRTT = molsFallbackRTTThreshold + time.Millisecond
	fallback1.DiscoveryRTTAt = time.Now()
	fallback2 := confirmedRelayState(t, "https://relay-fallback-2.example")
	fallback2.DiscoveryRTT = molsFallbackRTTThreshold + time.Millisecond
	fallback2.DiscoveryRTTAt = time.Now()

	selected := SelectPriority([]RelayState{fallback1, fallback2}, RouteState{})

	// Both fallbacks should be promoted to meet the minimum of 2.
	if len(selected) != 2 {
		t.Fatalf("len(selected) = %d, want 2 (both fallbacks promoted)", len(selected))
	}
}

// TestMOLSSelectPriorityDifferentIngressDifferentOrder verifies that different
// ingress identities can produce different relay orderings, so selection
// spreads load across clients instead of herding everyone to one relay.
func TestMOLSSelectPriorityDifferentIngressDifferentOrder(t *testing.T) {

	states := []RelayState{
		confirmedRelayState(t, "https://relay-alpha.example"),
		confirmedRelayState(t, "https://relay-beta.example"),
		confirmedRelayState(t, "https://relay-gamma.example"),
	}

	orderings := make(map[string]struct{})
	addresses := []string{
		"0xabc", "0xdef", "0x123", "0x456", "0x789", "0xfed",
		"user@example.com", "relay.net", "client-a", "client-b", "client-c", "client-d",
	}
	for _, addr := range addresses {
		sel := SelectPriority(states, RouteState{LocalAddress: addr})
		key := ""
		for _, u := range sel {
			key += u + "|"
		}
		orderings[key] = struct{}{}
	}

	if len(orderings) == 1 {
		t.Fatal("expected multiple ingress addresses to produce at least two distinct orderings")
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

func TestRankRelayPoolIncludesEveryEligibleRelay(t *testing.T) {
	relays := make([]RelayState, 12)
	for i := range relays {
		relays[i] = confirmedRelayState(t, fmt.Sprintf("https://relay-all-%d.example", i))
	}

	if ranked := RankRelayPool(relays, "client"); len(ranked) != len(relays) {
		t.Fatalf("len(RankRelayPool()) = %d, want %d", len(ranked), len(relays))
	}
}

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

func TestMOLSSelectPrioritySkipsAutoRelayInBackoff(t *testing.T) {
	backingOff := confirmedRelayState(t, "https://relay-backoff.example")
	backingOff.suppressActiveUntil = time.Now().UTC().Add(time.Minute)

	if selected := SelectPriority([]RelayState{backingOff}, RouteState{}); len(selected) != 0 {
		t.Fatalf("SelectPriority(backing off auto) = %v, want empty", selected)
	}
}

func TestMOLSSelectPriorityKeepsDiscoveryBackoffRelay(t *testing.T) {
	relayURL := "https://relay-discovery-backoff.example"
	backingOff := confirmedRelayState(t, relayURL)
	backingOff.nextDiscoveryRefreshAt = time.Now().UTC().Add(time.Minute)

	selected := SelectPriority([]RelayState{backingOff}, RouteState{})
	if len(selected) != 1 || selected[0] != relayURL {
		t.Fatalf("SelectPriority(discovery backoff) = %v, want [%q]", selected, relayURL)
	}
}

func TestMOLSSelectPriorityKeepsUnobservedAutoSeed(t *testing.T) {
	relayURL := "https://relay-seed.example"

	selected := SelectPriority([]RelayState{bootstrapRelayState(relayURL)}, RouteState{})
	if len(selected) != 1 || selected[0] != relayURL {
		t.Fatalf("SelectPriority(unobserved seed) = %v, want [%q]", selected, relayURL)
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
