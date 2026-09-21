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

	selected := SelectPriority([]RelayState{
		bootstrapRelayState(explicitRelay),
		verifiedRelayState(t, relayA),
		verifiedRelayState(t, relayB),
	}, routeState{
		ExplicitRelayURLs: []string{explicitRelay},
		MaxActiveRelays:   1,
	})

	if len(selected) != 2 || selected[0] != explicitRelay {
		t.Fatalf("SelectPriority() = %v, want explicit relay followed by one automatic relay", selected)
	}
}

func TestSelectPriorityDeduplicatesExplicitRelays(t *testing.T) {
	relayURL := "https://relay-explicit.example"
	selected := SelectPriority([]RelayState{bootstrapRelayState(relayURL)}, routeState{
		ExplicitRelayURLs: []string{relayURL, relayURL},
	})
	if len(selected) != 1 || selected[0] != relayURL {
		t.Fatalf("SelectPriority() = %v, want one explicit relay %q", selected, relayURL)
	}
}

func TestSelectPriorityLimitsAutomaticRelays(t *testing.T) {
	relays := make([]RelayState, 10)
	for i := range relays {
		relays[i] = verifiedRelayState(t, fmt.Sprintf("https://relay-%d.example", i))
	}

	if selected := SelectPriority(relays, routeState{MaxActiveRelays: 3}); len(selected) != 3 {
		t.Fatalf("len(SelectPriority()) = %d, want 3", len(selected))
	}
	if selected := SelectPriority(relays, routeState{}); len(selected) != defaultMaxActiveRelays {
		t.Fatalf("len(SelectPriority()) = %d, want default limit %d", len(selected), defaultMaxActiveRelays)
	}
}

func TestSelectPriorityExcludesIneligibleAutomaticRelays(t *testing.T) {
	expired := verifiedRelayState(t, "https://relay-expired.example")
	expired.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	banned := verifiedRelayState(t, "https://relay-banned.example")
	banned.Banned = true

	if selected := SelectPriority([]RelayState{expired, banned}, routeState{}); len(selected) != 0 {
		t.Fatalf("SelectPriority() = %v, want no ineligible automatic relays", selected)
	}
}

func TestSelectPriorityKeepsExplicitRelayIndependentOfDiscoveryState(t *testing.T) {
	relayURL := "https://relay-explicit.example"
	expired := verifiedRelayState(t, relayURL)
	expired.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)

	selected := SelectPriority([]RelayState{expired}, routeState{ExplicitRelayURLs: []string{relayURL}})
	if len(selected) != 1 || selected[0] != relayURL {
		t.Fatalf("SelectPriority() = %v, want explicit relay %q", selected, relayURL)
	}

	seedURL := "https://relay-seed.example"
	selected = SelectPriority([]RelayState{bootstrapRelayState(seedURL)}, routeState{})
	if len(selected) != 1 || selected[0] != seedURL {
		t.Fatalf("SelectPriority() = %v, want unobserved seed %q", selected, seedURL)
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

	selected := SelectPriority([]RelayState{fallback, healthyA, healthyB}, routeState{
		ActiveRelayURLs: []string{fallback.Descriptor.APIHTTPSAddr},
		MaxActiveRelays: 2,
	})
	if len(selected) != 2 {
		t.Fatalf("len(SelectPriority()) = %d, want 2", len(selected))
	}
	if slices.Contains(selected, fallback.Descriptor.APIHTTPSAddr) {
		t.Fatalf("SelectPriority() restored ineligible active relays: %v", selected)
	}
}

func TestSelectPriorityStickinessRetainsEligibleActiveRelay(t *testing.T) {
	relayA := "https://relay-a.example"
	relayB := "https://relay-b.example"

	selected := SelectPriority([]RelayState{
		verifiedRelayState(t, relayA),
		verifiedRelayState(t, relayB),
	}, routeState{
		ActiveRelayURLs: []string{relayA},
		MaxActiveRelays: 1,
	})

	if len(selected) != 1 || selected[0] != relayA {
		t.Fatalf("SelectPriority() = %v, want the healthy active relay %q retained under the active cap", selected, relayA)
	}
}
