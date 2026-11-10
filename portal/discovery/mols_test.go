package discovery

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

func TestSelectPriorityKeepsExplicitRelaysOutsideAutoLimit(t *testing.T) {
	explicitRelay := "https://relay-explicit.example"
	relayA := "https://relay-a.example"
	relayB := "https://relay-b.example"

	selected := selectPriority([]relayState{
		bootstrapRelayState(explicitRelay),
		verifiedRelayState(t, relayA),
		verifiedRelayState(t, relayB),
	}, routeState{
		ExplicitRelayURLs: []string{explicitRelay},
		MaxActiveRelays:   1,
	})

	if len(selected) != 2 || selected[0] != explicitRelay {
		t.Fatalf("selectPriority() = %v, want explicit relay followed by one automatic relay", selected)
	}
}

func TestSelectPriorityLimitsAutomaticRelays(t *testing.T) {
	relays := make([]relayState, 10)
	for i := range relays {
		relays[i] = verifiedRelayState(t, fmt.Sprintf("https://relay-%d.example", i))
	}

	if selected := selectPriority(relays, routeState{MaxActiveRelays: 3}); len(selected) != 3 {
		t.Fatalf("len(selectPriority()) = %d, want 3", len(selected))
	}
	if selected := selectPriority(relays, routeState{}); len(selected) != DefaultMaxActiveRelays {
		t.Fatalf("len(selectPriority()) = %d, want default limit %d", len(selected), DefaultMaxActiveRelays)
	}
}

func TestSelectPriorityExcludesIneligibleAutomaticRelays(t *testing.T) {
	expired := verifiedRelayState(t, "https://relay-expired.example")
	expired.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	banned := verifiedRelayState(t, "https://relay-banned.example")
	banned.Banned = true

	if selected := selectPriority([]relayState{expired, banned}, routeState{}); len(selected) != 0 {
		t.Fatalf("selectPriority() = %v, want no ineligible automatic relays", selected)
	}
}

func TestSelectPriorityKeepsExplicitRelayIndependentOfDiscoveryState(t *testing.T) {
	relayURL := "https://relay-explicit.example"
	expired := verifiedRelayState(t, relayURL)
	expired.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)

	selected := selectPriority([]relayState{expired}, routeState{ExplicitRelayURLs: []string{relayURL}})
	if len(selected) != 1 || selected[0] != relayURL {
		t.Fatalf("selectPriority() = %v, want explicit relay %q", selected, relayURL)
	}

	seedURL := "https://relay-seed.example"
	selected = selectPriority([]relayState{bootstrapRelayState(seedURL)}, routeState{})
	if len(selected) != 1 || selected[0] != seedURL {
		t.Fatalf("selectPriority() = %v, want unobserved seed %q", selected, seedURL)
	}
}

func TestSelectPriorityKeepsExplicitRelayAbsentFromDiscovery(t *testing.T) {
	const explicitURL = "https://explicit.example"
	for _, states := range [][]relayState{
		nil,
		{bootstrapRelayState("https://bootstrap.example")},
	} {
		selected := selectPriority(states, routeState{
			ExplicitRelayURLs: []string{explicitURL, explicitURL},
		})
		if len(selected) != len(states)+1 || selected[0] != explicitURL {
			t.Fatalf("selectPriority() = %v, want the explicit relay once before discovered relays", selected)
		}
	}
}

func TestSelectPriorityStickinessDoesNotRestoreFallbackRelays(t *testing.T) {
	now := time.Now().UTC()
	fallback := verifiedRelayState(t, "https://fallback.example")
	fallback.DiscoveryRTT = 3 * time.Second
	fallback.DiscoveryRTTAt = now

	healthyA := verifiedRelayState(t, "https://healthy-a.example")
	healthyA.DiscoveryRTT = 50 * time.Millisecond
	healthyA.DiscoveryRTTAt = now
	healthyB := verifiedRelayState(t, "https://healthy-b.example")
	healthyB.DiscoveryRTT = 60 * time.Millisecond
	healthyB.DiscoveryRTTAt = now

	selected := selectPriority([]relayState{fallback, healthyA, healthyB}, routeState{
		ActiveRelayURLs: []string{fallback.Descriptor.APIHTTPSAddr},
		MaxActiveRelays: 2,
	})
	if len(selected) != 2 {
		t.Fatalf("len(selectPriority()) = %d, want 2", len(selected))
	}
	if slices.Contains(selected, fallback.Descriptor.APIHTTPSAddr) {
		t.Fatalf("selectPriority() restored ineligible active relays: %v", selected)
	}
}

func TestSelectPriorityStickinessRetainsEligibleActiveRelay(t *testing.T) {
	relayA := "https://relay-a.example"
	relayB := "https://relay-b.example"

	selected := selectPriority([]relayState{
		verifiedRelayState(t, relayA),
		verifiedRelayState(t, relayB),
	}, routeState{
		ActiveRelayURLs: []string{relayA},
		MaxActiveRelays: 1,
	})

	if len(selected) != 1 || selected[0] != relayA {
		t.Fatalf("selectPriority() = %v, want the healthy active relay %q retained under the active cap", selected, relayA)
	}
}

func TestMOLSCongestionModeExcludesFallbackRelays(t *testing.T) {
	now := time.Now().UTC()
	healthy := verifiedRelayState(t, "https://healthy.example")
	healthy.DiscoveryRTT = 80 * time.Millisecond
	healthy.DiscoveryRTTAt = now
	fallback := verifiedRelayState(t, "https://fallback.example")
	fallback.DiscoveryRTT = 5 * time.Second
	fallback.DiscoveryRTTAt = now

	if congested, _ := molsCongestionMode([]relayState{healthy, fallback}); congested {
		t.Fatal("molsCongestionMode() = true, want false: a fallback relay's RTT must not trigger congestion")
	}

	slowA := verifiedRelayState(t, "https://slow-a.example")
	slowA.DiscoveryRTT = 600 * time.Millisecond
	slowA.DiscoveryRTTAt = now
	slowB := verifiedRelayState(t, "https://slow-b.example")
	slowB.DiscoveryRTT = 700 * time.Millisecond
	slowB.DiscoveryRTTAt = now
	if congested, _ := molsCongestionMode([]relayState{slowA, slowB}); !congested {
		t.Fatal("molsCongestionMode() = false, want true for a genuinely slow active pool")
	}
}

func TestMOLSPressureSwapsTopRelayOnly(t *testing.T) {
	pool := []relayState{
		verifiedRelayState(t, "https://relay-a.example"),
		verifiedRelayState(t, "https://relay-b.example"),
	}

	base := rankRelayPool(pool, "client-a", nil)
	if len(base) != 2 {
		t.Fatalf("len(rankRelayPool()) = %d, want 2", len(base))
	}

	top := base[0]
	for i := range pool {
		if pool[i].Descriptor.APIHTTPSAddr == top {
			for j := 0; j < 8; j++ {
				pool[i].RTTTracker.add(100 * time.Millisecond)
			}
			for j := 0; j < 4; j++ {
				pool[i].RTTTracker.add(200 * time.Millisecond)
			}
		} else {
			for j := 0; j < 12; j++ {
				pool[i].RTTTracker.add(100 * time.Millisecond)
			}
		}
	}

	got := rankRelayPool(pool, "client-a", nil)
	if got[0] != base[1] || got[1] != base[0] {
		t.Fatalf("rankRelayPool() = %v, want adjacent swap of %v", got, base)
	}
}
