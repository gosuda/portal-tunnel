package discovery

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestSelectPriorityKeepsExplicitRelaysOutsideAutoLimit(t *testing.T) {
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

	if len(selected) != 2 || selected[0] != explicitRelay {
		t.Fatalf("SelectPriority() = %v, want explicit relay followed by one automatic relay", selected)
	}
}

func TestSelectPriorityDeduplicatesExplicitRelays(t *testing.T) {
	relayURL := "https://relay-explicit.example"
	selected := SelectPriority([]RelayState{bootstrapRelayState(relayURL)}, RouteState{
		ExplicitRelayURLs: []string{relayURL, relayURL},
	})
	if len(selected) != 1 || selected[0] != relayURL {
		t.Fatalf("SelectPriority() = %v, want one explicit relay %q", selected, relayURL)
	}
}

func TestSelectPriorityLimitsAutomaticRelays(t *testing.T) {
	relays := make([]RelayState, 10)
	for i := range relays {
		relays[i] = confirmedRelayState(t, fmt.Sprintf("https://relay-%d.example", i))
	}

	if selected := SelectPriority(relays, RouteState{MaxActiveRelays: 3}); len(selected) != 3 {
		t.Fatalf("len(SelectPriority()) = %d, want 3", len(selected))
	}
	if selected := SelectPriority(relays, RouteState{}); len(selected) != defaultMaxActiveRelays {
		t.Fatalf("len(SelectPriority()) = %d, want default limit %d", len(selected), defaultMaxActiveRelays)
	}
}

func TestSelectPriorityExcludesIneligibleAutomaticRelays(t *testing.T) {
	expired := confirmedRelayState(t, "https://relay-expired.example")
	expired.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	banned := confirmedRelayState(t, "https://relay-banned.example")
	banned.Banned = true

	if selected := SelectPriority([]RelayState{expired, banned}, RouteState{}); len(selected) != 0 {
		t.Fatalf("SelectPriority() = %v, want no ineligible automatic relays", selected)
	}
}

func TestSelectPriorityKeepsExplicitRelayIndependentOfDiscoveryState(t *testing.T) {
	relayURL := "https://relay-explicit.example"
	expired := confirmedRelayState(t, relayURL)
	expired.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Minute)

	selected := SelectPriority([]RelayState{expired}, RouteState{ExplicitRelayURLs: []string{relayURL}})
	if len(selected) != 1 || selected[0] != relayURL {
		t.Fatalf("SelectPriority() = %v, want explicit relay %q", selected, relayURL)
	}

	seedURL := "https://relay-seed.example"
	selected = SelectPriority([]RelayState{bootstrapRelayState(seedURL)}, RouteState{})
	if len(selected) != 1 || selected[0] != seedURL {
		t.Fatalf("SelectPriority() = %v, want unobserved seed %q", selected, seedURL)
	}
}

func TestSelectPriorityStickinessDoesNotRestoreIneligibleRelays(t *testing.T) {
	now := time.Now().UTC()
	saturated := confirmedRelayState(t, "https://saturated.example")
	saturated.IsSaturated = true
	saturated.LoadFactor = 0.95

	fallback := confirmedRelayState(t, "https://fallback.example")
	fallback.DiscoveryRTT = 3 * time.Second
	fallback.DiscoveryRTTAt = now

	healthyA := confirmedRelayState(t, "https://healthy-a.example")
	healthyA.DiscoveryRTT = 50 * time.Millisecond
	healthyA.DiscoveryRTTAt = now
	healthyB := confirmedRelayState(t, "https://healthy-b.example")
	healthyB.DiscoveryRTT = 60 * time.Millisecond
	healthyB.DiscoveryRTTAt = now

	selected := SelectPriority([]RelayState{saturated, fallback, healthyA, healthyB}, RouteState{
		ActiveRelayURLs: []string{saturated.Descriptor.APIHTTPSAddr, fallback.Descriptor.APIHTTPSAddr},
		MaxActiveRelays: 2,
	})
	if len(selected) != 2 {
		t.Fatalf("len(SelectPriority()) = %d, want 2", len(selected))
	}
	if slices.Contains(selected, saturated.Descriptor.APIHTTPSAddr) || slices.Contains(selected, fallback.Descriptor.APIHTTPSAddr) {
		t.Fatalf("SelectPriority() restored ineligible active relays: %v", selected)
	}
}

func BenchmarkSelectPriority(b *testing.B) {
	relays := make([]RelayState, 100)
	for i := range relays {
		relays[i] = RelayState{
			Descriptor:     types.RelayDescriptor{APIHTTPSAddr: fmt.Sprintf("https://relay-%d.example", i)},
			DiscoveryRTT:   100 * time.Millisecond,
			DiscoveryRTTAt: time.Now(),
			Confirmed:      true,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SelectPriority(relays, RouteState{LocalAddress: fmt.Sprintf("client-%d", i)})
	}
}
