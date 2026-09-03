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

// TestHRWMonotonicityZeroChurn verifies that when a relay is removed from the candidate pool,
// 100% of clients that were NOT using the removed relay maintain their existing primary choice (0% churn).
func TestHRWMonotonicityZeroChurn(t *testing.T) {
	const numRelays = 7
	const numClients = 700
	now := time.Now().UTC()

	relays := make([]RelayState, numRelays)
	for i := 0; i < numRelays; i++ {
		relays[i] = confirmedRelayState(t, fmt.Sprintf("https://relay-hrw-%d.example", i))
		relays[i].DiscoveryRTT = 20 * time.Millisecond
		relays[i].DiscoveryRTTAt = now
	}

	clients := make([]string, numClients)
	for i := 0; i < numClients; i++ {
		clients[i] = fmt.Sprintf("client-%04d", i)
	}

	initialPrimary := make(map[string]string)
	primaryCounts := make(map[string]int)
	for _, c := range clients {
		ranked := RankRelayPool(relays, c)
		initialPrimary[c] = ranked[0]
		primaryCounts[ranked[0]]++
	}

	// Identify busiest relay to drop
	busiest := ""
	maxCount := 0
	for r, cnt := range primaryCounts {
		if cnt > maxCount {
			maxCount = cnt
			busiest = r
		}
	}

	surviving := make([]RelayState, 0, numRelays-1)
	for _, r := range relays {
		if r.Descriptor.APIHTTPSAddr != busiest {
			surviving = append(surviving, r)
		}
	}

	unaffectedMoved := 0
	unaffectedTotal := 0
	displacedSecondaries := make(map[string]int)

	for _, c := range clients {
		orig := initialPrimary[c]
		rankedAfter := RankRelayPool(surviving, c)
		if orig != busiest {
			unaffectedTotal++
			if rankedAfter[0] != orig {
				unaffectedMoved++
			}
		} else {
			displacedSecondaries[rankedAfter[0]]++
		}
	}

	// Invariant 1: Minimal disruption property of HRW guarantees 0 unaffected clients churn.
	if unaffectedMoved != 0 {
		t.Fatalf("HRW monotonicity violation: %d / %d unaffected clients were reshuffled", unaffectedMoved, unaffectedTotal)
	}

	// Invariant 2: Displaced clients disperse across survivors without herd collapse onto a single replacement.
	if len(displacedSecondaries) < numRelays-2 {
		t.Fatalf("HRW herd dispersion violation: displaced clients only reached %d survivors: %v",
			len(displacedSecondaries), displacedSecondaries)
	}
}
