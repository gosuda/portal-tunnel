package discovery

import (
	"fmt"
	"slices"
	"sync"
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

func TestMOLSMultiHopBypassesSingleHopStickiness(t *testing.T) {
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
	// Multi-hop routing bypasses single-hop ActiveRelayURLs stickiness to preserve route-level path generation
	expectedRoutes, _ := set.PlanRoutes(nil, RouteState{
		MultiHopDepth:   2,
		MaxActiveRelays: 2,
		LocalAddress:    "client",
	})
	if routes[0].ListenerRelayURL() != expectedRoutes[0].ListenerRelayURL() {
		t.Fatalf("multi-hop route should follow pure buildMOLSPaths ordering")
	}
}

func TestMOLSFallbackSortURLTieBreaker(t *testing.T) {
	now := time.Now().UTC()
	// Create two fallback relays with identical effectiveRTT
	rB := confirmedRelayState(t, "https://relay-b.example")
	rB.DiscoveryRTT = 3 * time.Second
	rB.DiscoveryRTTAt = now

	rA := confirmedRelayState(t, "https://relay-a.example")
	rA.DiscoveryRTT = 3 * time.Second
	rA.DiscoveryRTTAt = now

	// Only 1 active state, so fallback promotion will promote one fallback node
	active := confirmedRelayState(t, "https://relay-active.example")
	active.DiscoveryRTT = 30 * time.Millisecond
	active.DiscoveryRTTAt = now

	// Pass in reverse order [rB, rA]
	relays := []RelayState{active, rB, rA}
	ranked := RankRelayPool(relays, "client-tie-breaker", 0)

	// Since active pool has 1 node, molsMinActiveNodes (2) causes 1 fallback node to be promoted into active tier.
	// Between rA and rB (both 3s RTT), rA MUST be promoted due to URL tie-breaker, leaving rB in fallback.
	if !slices.Contains(ranked[:2], "https://relay-a.example") || ranked[2] != "https://relay-b.example" {
		t.Fatalf("expected relay-a to be promoted into active tier and relay-b in fallback, got: %v", ranked)
	}
}

func TestMOLSP2CLocalChoiceTopTwo(t *testing.T) {
	now := time.Now().UTC()
	// Create 4 candidates
	// R0 has higher pressure than R1 (delta > 0.3)
	r0 := confirmedRelayState(t, "https://relay-0.example")
	r0.LoadFactor = 0.6
	r0.EWMALoad = 0.6
	r0.LoadDelta = 0.3
	r0.DiscoveryRTT = 30 * time.Millisecond
	r0.DiscoveryRTTAt = now

	r1 := confirmedRelayState(t, "https://relay-1.example")
	r1.LoadFactor = 0.1
	r1.EWMALoad = 0.1
	r1.DiscoveryRTT = 30 * time.Millisecond
	r1.DiscoveryRTTAt = now

	r2 := confirmedRelayState(t, "https://relay-2.example")
	r2.LoadFactor = 0.1
	r2.EWMALoad = 0.1
	r2.DiscoveryRTT = 30 * time.Millisecond
	r2.DiscoveryRTTAt = now

	relays := []RelayState{r0, r1, r2}
	ranked := RankRelayPool(relays, "test-client", 0)
	if len(ranked) != 3 {
		t.Fatalf("expected 3 ranked relays, got %d", len(ranked))
	}
	// Pressure difference between r0 and r1 triggers local P2C demotion of overloaded candidate 0
	if ranked[0] == "https://relay-0.example" && r0.Pressure()-r1.Pressure() > molsP2CPressureDelta {
		t.Fatalf("relay-0 should have yielded its top slot due to P2C local choice")
	}
}

func TestMOLSP2CActiveSetMembershipChangeDefaultQuota(t *testing.T) {
	now := time.Now().UTC()
	const numRelays = 4 // 3 active + 1 reserve under default MaxActiveRelays = 3
	relays := make([]RelayState, numRelays)
	for i := 0; i < numRelays; i++ {
		st := confirmedRelayState(t, fmt.Sprintf("https://relay-quota-%d.example", i))
		st.DiscoveryRTT = 25 * time.Millisecond
		st.DiscoveryRTTAt = now
		st.LoadFactor = 0.10
		st.EWMALoad = 0.10
		relays[i] = st
	}

	// Baseline: under balanced loads, MOLS determines initial order
	clientAddr := "client-quota-test"
	basePicks := SelectPriority(relays, RouteState{
		MaxActiveRelays: defaultMaxActiveRelays, // 3
		LocalAddress:    clientAddr,
	})
	if len(basePicks) != defaultMaxActiveRelays {
		t.Fatalf("expected %d base picks, got %d", defaultMaxActiveRelays, len(basePicks))
	}

	rankedBase := RankRelayPool(relays, clientAddr, 0)
	topCandidateURL := rankedBase[0]
	reserveCandidateURL := rankedBase[3] // 4th candidate (reserve slot)

	// Overload the top candidate with surging load and tail inflation
	loadedRelays := make([]RelayState, len(relays))
	for i, r := range relays {
		loadedRelays[i] = r
		if r.Descriptor.APIHTTPSAddr == topCandidateURL {
			loadedRelays[i].LoadFactor = 0.75
			loadedRelays[i].EWMALoad = 0.75
			loadedRelays[i].LoadDelta = 0.35
			for j := 0; j < 90; j++ {
				loadedRelays[i].RTTTracker.Add(10 * time.Millisecond)
			}
			for j := 0; j < 10; j++ {
				loadedRelays[i].RTTTracker.Add(150 * time.Millisecond)
			}
		}
	}

	// Under default MaxActiveRelays = 3 with ActiveRelayURLs POPULATED (production path),
	// overloaded top candidate MUST be evicted from active set despite active stickiness.
	newPicks := SelectPriority(loadedRelays, RouteState{
		ActiveRelayURLs: basePicks,              // Simulates active connections in Exposure.reconcileRelayListeners
		MaxActiveRelays: defaultMaxActiveRelays, // 3
		LocalAddress:    clientAddr,
	})
	if len(newPicks) != defaultMaxActiveRelays {
		t.Fatalf("expected %d new picks, got %d", defaultMaxActiveRelays, len(newPicks))
	}

	// Invariant 1: Overloaded relay is evicted outside the active listener quota
	if slices.Contains(newPicks, topCandidateURL) {
		t.Fatalf("overloaded relay %s was NOT evicted from active set: %v", topCandidateURL, newPicks)
	}

	// Invariant 2: Reserve candidate steps into the active listener set
	if !slices.Contains(newPicks, reserveCandidateURL) {
		t.Fatalf("reserve relay %s did not enter active set: %v", reserveCandidateURL, newPicks)
	}
}

func TestMOLSAntiCascadeDispersion(t *testing.T) {
	testDispersion := func(t *testing.T, numRelays int) {
		now := time.Now().UTC()
		relays := make([]RelayState, numRelays)
		for i := 0; i < numRelays; i++ {
			relays[i] = confirmedRelayState(t, fmt.Sprintf("https://relay-%d-%d.example", numRelays, i))
			relays[i].DiscoveryRTT = 20 * time.Millisecond
			relays[i].DiscoveryRTTAt = now
		}

		const numClients = 700
		clientsByPrimary := make(map[string][]string)
		for i := 0; i < numClients; i++ {
			clientAddr := fmt.Sprintf("client-%d-%d.example", numRelays, i)
			ranked := RankRelayPool(relays, clientAddr, 0)
			primary := ranked[0]
			clientsByPrimary[primary] = append(clientsByPrimary[primary], clientAddr)
		}

		// Find the primary relay serving the largest group of clients
		var targetPrimary string
		var targetClients []string
		for p, cs := range clientsByPrimary {
			if len(cs) > len(targetClients) {
				targetPrimary = p
				targetClients = cs
			}
		}

		// Simulate primary relay failure (drop from candidate pool)
		survivingRelays := make([]RelayState, 0, numRelays-1)
		for _, r := range relays {
			if r.Descriptor.APIHTTPSAddr != targetPrimary {
				survivingRelays = append(survivingRelays, r)
			}
		}

		// Measure replacement distribution for displaced clients
		replacementCounts := make(map[string]int)
		for _, clientAddr := range targetClients {
			ranked := RankRelayPool(survivingRelays, clientAddr, 0)
			replacement := ranked[0]
			replacementCounts[replacement]++
		}

		// Anti-cascade Invariant 1: Displaced clients MUST NOT collapse onto a single secondary
		if len(replacementCounts) <= 1 {
			t.Fatalf("N=%d: All displaced clients collapsed onto a single replacement: %v", numRelays, replacementCounts)
		}

		// Anti-cascade Invariant 2: No single surviving relay should absorb an overwhelming monopoly (>50%)
		for repl, count := range replacementCounts {
			fraction := float64(count) / float64(len(targetClients))
			if fraction > 0.50 {
				t.Fatalf("N=%d: Replacement relay %s absorbed %.1f%% (>50%%) of displaced traffic: %v", numRelays, repl, fraction*100, replacementCounts)
			}
		}
	}

	t.Run("PrimeOrder_N7", func(t *testing.T) {
		testDispersion(t, 7)
	})

	t.Run("EvenOrder_N8", func(t *testing.T) {
		testDispersion(t, 8)
	})

	t.Run("EvenOrder_N6", func(t *testing.T) {
		testDispersion(t, 6)
	})
}

// TestMOLSDualOrthogonalPairDispersion verifies that when MOLS has a valid orthogonal pair
// (e.g. N=7), the 2nd-choice ranking across clients sharing the same primary relay
// is genuinely dispersed across multiple distinct relays via the second Latin square (m2),
// rather than collapsing into a single cyclic successor (herd elimination).
func TestMOLSDualOrthogonalPairDispersion(t *testing.T) {
	const numRelays = 7
	now := time.Now().UTC()
	relays := make([]RelayState, numRelays)
	for i := 0; i < numRelays; i++ {
		relays[i] = confirmedRelayState(t, fmt.Sprintf("https://relay-pair-%d.example", i))
		relays[i].DiscoveryRTT = 20 * time.Millisecond
		relays[i].DiscoveryRTTAt = now
	}

	const numClients = 700
	secByPrim := make(map[string]map[string]int)
	for i := 0; i < numClients; i++ {
		clientAddr := fmt.Sprintf("client-pair-%d.example", i)
		ranked := RankRelayPool(relays, clientAddr, 0)
		p := ranked[0]
		s := ranked[1]
		if secByPrim[p] == nil {
			secByPrim[p] = make(map[string]int)
		}
		secByPrim[p][s]++
	}

	// Under true dual-orthogonal MOLS, every primary relay must see its secondary choices
	// dispersed across multiple distinct relays (at least 4 out of the 6 alternatives).
	for prim, secs := range secByPrim {
		if len(secs) < 4 {
			t.Fatalf("Primary %s has insufficient secondary dispersion (%d distinct 2nd choices, want >= 4): %v",
				prim, len(secs), secs)
		}
	}
}

func TestMOLSConcurrentRefreshAndFailureLifecycle(t *testing.T) {
	now := time.Now().UTC()
	set := NewRelaySet(nil)
	const numRelays = 6

	for i := 0; i < numRelays; i++ {
		u := fmt.Sprintf("https://relay-conc-%d.example", i)
		st := confirmedRelayState(t, u)
		st.Descriptor.SupportsOverlay = true
		st.Descriptor.WireGuardPublicKey = fmt.Sprintf("wg-key-%d", i)
		st.Descriptor.WireGuardPort = 51820
		st.Descriptor.ExpiresAt = now.Add(time.Hour)
		st.LastSeenAt = now
		set.relays[u] = st
	}

	failingRelay := "https://relay-conc-0.example"
	var wg sync.WaitGroup

	// Concurrently plan routes (multi-hop and single-hop)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				routes, err := set.PlanRoutes(nil, RouteState{
					MultiHopDepth:   2,
					MaxActiveRelays: 2,
					LocalAddress:    fmt.Sprintf("client-%d-%d", id, j),
				})
				if err == nil && len(routes) > 0 {
					_ = routes[0].ListenerRelayURL()
				}
			}
		}(i)
	}

	// Concurrently record failures on the failing relay
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			set.RecordActiveFailure(failingRelay, 0)
		}
	}()

	wg.Wait()

	// After 10 consecutive failures, failingRelay should have accumulated significant
	// virtual latency penalty and should be demoted, not appearing in top active routes.
	routes, err := set.PlanRoutes(nil, RouteState{
		MaxActiveRelays: 2,
		LocalAddress:    "client-verify",
	})
	if err != nil {
		t.Fatalf("PlanRoutes failed: %v", err)
	}
	for _, r := range routes {
		if r.ListenerRelayURL() == failingRelay {
			t.Fatalf("failing relay %s should not be active after repeated failures", failingRelay)
		}
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
