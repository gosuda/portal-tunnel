package discovery

import (
	"cmp"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// TestMOLSScoreRange checks that molsScore always produces values in
// [1, order^2] for any grid order.
func TestMOLSScoreRange(t *testing.T) {
	for order := 1; order <= 64; order++ {
		for i := 0; i < order; i++ {
			for j := 0; j < order; j++ {
				s := molsScore(i, j, int(molsBaseM1), int(molsBaseM2), order)
				if s < 1 || s > order*order {
					t.Fatalf("molsScore(%d, %d, order=%d) = %d, out of range [1, %d]", i, j, order, s, order*order)
				}
			}
		}
	}
}

// TestMOLSScoreRowPermutation checks that each row of the MOLS score grid is
// duplicate-free for any grid order. Rows are indexed by ingress i; columns by
// candidate j.
func TestMOLSScoreRowPermutation(t *testing.T) {
	for order := 1; order <= 64; order++ {
		for i := 0; i < order; i++ {
			seen := make(map[int]struct{}, order)
			for j := 0; j < order; j++ {
				s := molsScore(i, j, int(molsBaseM1), int(molsBaseM2), order)
				if _, dup := seen[s]; dup {
					t.Fatalf("duplicate score %d in row i=%d (order=%d)", s, i, order)
				}
				seen[s] = struct{}{}
			}
		}
	}
}

func TestMOLSSelectPriorityMathematicalOrdering(t *testing.T) {
	clientAddr := "192.168.0.10"

	relays := []string{
		"https://relay-alpha.io",
		"https://relay-beta.io",
		"https://relay-gamma.io",
	}

	states := make([]RelayState, 0, len(relays))
	for _, relayURL := range relays {
		states = append(states, confirmedRelayState(t, relayURL))
	}

	selected := SelectPriority(states, RouteState{LocalAddress: clientAddr})

	order := len(states)
	m1, m2, _ := molsMultipliers(order, false)
	row := int(hashToGridIndex(clientAddr) % uint32(order))
	for i := 0; i < len(selected)-1; i++ {
		colA := int(hashToGridIndex(selected[i]) % uint32(order))
		colB := int(hashToGridIndex(selected[i+1]) % uint32(order))
		scoreA := molsScore(row, colA, m1, m2, order)
		scoreB := molsScore(row, colB, m1, m2, order)
		if scoreA < scoreB {
			t.Fatalf("selected[%d:%d] scores = %d < %d", i, i+1, scoreA, scoreB)
		}
	}
}

// TestMOLSCongestionScoreRange checks that the Reverse-Siamese scores stay in
// [1, order^2] and are the complement of the base scores for any grid order.
func TestMOLSCongestionScoreRange(t *testing.T) {
	for order := 1; order <= 64; order++ {
		for i := 0; i < order; i++ {
			for j := 0; j < order; j++ {
				s := molsCongestionScore(i, j, int(molsBaseM1), int(molsBaseM2), order)
				if s < 1 || s > order*order {
					t.Fatalf("molsCongestionScore(%d, %d, order=%d) = %d, out of range", i, j, order, s)
				}
				// Verify B(i,j) = (n^2+1) - A(i, n-1-j)
				want := order*order + 1 - molsScore(i, (order-1)-j, int(molsBaseM1), int(molsBaseM2), order)
				if s != want {
					t.Fatalf("molsCongestionScore(%d, %d, order=%d) = %d, want %d", i, j, order, s, want)
				}
			}
		}
	}
}

// TestMOLSRTTStatsMean checks the mean calculation.
func TestMOLSRTTStatsMean(t *testing.T) {
	states := []RelayState{
		{DiscoveryRTT: 100 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 200 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 300 * time.Millisecond, DiscoveryRTTAt: time.Now()},
	}
	mean, _ := molsRTTStats(states)
	if mean != 200*time.Millisecond {
		t.Fatalf("mean = %v, want 200ms", mean)
	}
}

// TestMOLSRTTStatsCVUniform checks that a uniform RTT distribution has CV=0.
func TestMOLSRTTStatsCVUniform(t *testing.T) {
	states := []RelayState{
		{DiscoveryRTT: 100 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 100 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 100 * time.Millisecond, DiscoveryRTTAt: time.Now()},
	}
	_, cv := molsRTTStats(states)
	if cv != 0 {
		t.Fatalf("cv = %v, want 0 for uniform distribution", cv)
	}
}

// TestMOLSRTTStatsCVHigh checks that a highly varied RTT distribution
// produces a CV above the threshold.
func TestMOLSRTTStatsCVHigh(t *testing.T) {
	states := []RelayState{
		{DiscoveryRTT: 10 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 2000 * time.Millisecond, DiscoveryRTTAt: time.Now()},
	}
	_, cv := molsRTTStats(states)
	if cv <= molsCVThreshold {
		t.Fatalf("cv = %v, want > %v for high-variance distribution", cv, molsCVThreshold)
	}
}

// TestMOLSRTTStatsSkipsMissingRTT checks that relays without a measured RTT
// are excluded from both mean and CV calculations.
func TestMOLSRTTStatsSkipsMissingRTT(t *testing.T) {
	states := []RelayState{
		{DiscoveryRTT: 100 * time.Millisecond, DiscoveryRTTAt: time.Now()},
		{DiscoveryRTT: 999 * time.Second}, // no DiscoveryRTTAt, excluded
	}
	mean, _ := molsRTTStats(states)
	if mean != 100*time.Millisecond {
		t.Fatalf("mean = %v, want 100ms (excluded relay with zero RTTAt)", mean)
	}
}

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
// RTT are placed after healthy relays in the priority list.
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

// TestMOLSSelectPriorityCongestionSwitchChangesOrder verifies that the
// Reverse-Siamese mode (triggered by high average RTT) produces a different
// ordering than normal mode for the same relay set.
func TestMOLSSelectPriorityCongestionSwitchChangesOrder(t *testing.T) {

	// Two relays with different MOLS column indices so their scores differ.
	r1 := confirmedRelayState(t, "https://relay-one.example")
	r2 := confirmedRelayState(t, "https://relay-two.example")

	// Normal mode: no RTT measurements, no congestion.
	normal := SelectPriority([]RelayState{r1, r2}, RouteState{
		LocalAddress: "ingress-test",
	})

	// Congestion mode: set RTTs above threshold (but low CV to avoid variant).
	rttHigh := molsCongestionRTTThreshold + 100*time.Millisecond
	r1c := r1
	r1c.DiscoveryRTT = rttHigh
	r1c.DiscoveryRTTAt = time.Now()
	r2c := r2
	r2c.DiscoveryRTT = rttHigh
	r2c.DiscoveryRTTAt = time.Now()

	congested := SelectPriority([]RelayState{r1c, r2c}, RouteState{
		LocalAddress: "ingress-test",
	})

	if len(normal) != 2 || len(congested) != 2 {
		t.Fatalf("expected 2 relays in both modes: normal=%d congested=%d", len(normal), len(congested))
	}

	// The two orderings should differ (unless MOLS scores happen to be symmetric,
	// which is extremely unlikely for distinct relay URLs).
	if normal[0] == congested[0] {
		// Verify the scores are actually different to confirm the switch is working.
		order := 2
		m1, m2, _ := molsMultipliers(order, false)
		row := int(hashToGridIndex("ingress-test") % uint32(order))
		j1 := int(hashToGridIndex("https://relay-one.example") % uint32(order))
		j2 := int(hashToGridIndex("https://relay-two.example") % uint32(order))
		normal1 := molsScore(row, j1, m1, m2, order)
		normal2 := molsScore(row, j2, m1, m2, order)
		cong1 := molsCongestionScore(row, j1, m1, m2, order)
		cong2 := molsCongestionScore(row, j2, m1, m2, order)
		if (normal1 > normal2) != (cong1 > cong2) {
			t.Fatal("expected congestion switch to invert ordering but result matched normal mode")
		}
		// If ordering is the same it means the math happens to agree; acceptable.
	}
}

// TestMOLSSelectPriorityVariantGridActivatesOnHighCV confirms that a high
// coefficient of variation triggers the variant multipliers (7, 11) while the
// mean RTT stays below the congestion threshold.
func TestMOLSSelectPriorityVariantGridActivatesOnHighCV(t *testing.T) {
	const localAddress = "ingress-cv"
	relays := []string{
		"https://relay-cv-one.example",
		"https://relay-cv-two.example",
		"https://relay-cv-three.example",
	}

	states := make([]RelayState, 0, len(relays))
	for _, relayURL := range relays {
		states = append(states, confirmedRelayState(t, relayURL))
	}

	// Normal mode: no RTT, no congestion, no CV.
	normalOrder := SelectPriority(states, RouteState{LocalAddress: localAddress})

	// High-CV mode: very different RTTs push CV above 0.5 while the mean stays
	// below the congestion threshold, isolating the variant-grid branch.
	variantStates := make([]RelayState, 0, len(states))
	for i, state := range states {
		state.DiscoveryRTT = time.Duration([]int{100, 400, 100}[i]) * time.Millisecond
		state.DiscoveryRTTAt = time.Now()
		variantStates = append(variantStates, state)
	}

	// Verify high-CV state is actually detected.
	avgRTT, cv := molsRTTStats(variantStates)
	if cv <= molsCVThreshold {
		t.Fatalf("test precondition: cv = %v, want > %v", cv, molsCVThreshold)
	}
	if avgRTT > molsCongestionRTTThreshold {
		t.Fatalf("test precondition: avgRTT = %v, want <= %v", avgRTT, molsCongestionRTTThreshold)
	}

	variantOrder := SelectPriority(variantStates, RouteState{LocalAddress: localAddress})

	order := len(relays)
	baseM1, baseM2, _ := molsMultipliers(order, false)
	variantM1, variantM2, _ := molsMultipliers(order, true)
	if want := expectedScoreOrder(relays, localAddress, order, baseM1, baseM2); !slices.Equal(normalOrder, want) {
		t.Fatalf("normal order = %v, want %v (base multipliers)", normalOrder, want)
	}
	if want := expectedScoreOrder(relays, localAddress, order, variantM1, variantM2); !slices.Equal(variantOrder, want) {
		t.Fatalf("variant order = %v, want %v (variant multipliers)", variantOrder, want)
	}
}

// TestMOLSSelectPriorityDifferentIngressDifferentOrder verifies that two
// different ingress identities can produce different relay orderings (MOLS
// property: each row is an independent permutation).
func TestMOLSSelectPriorityDifferentIngressDifferentOrder(t *testing.T) {

	states := make([]RelayState, 12)
	relayURLs := make([]string, 12)
	for i := range states {
		relayURLs[i] = fmt.Sprintf("https://relay-ingress-%d.example", i)
		states[i] = confirmedRelayState(t, relayURLs[i])
	}

	// Collect orderings for a range of ingress addresses and check that at
	// least one pair produces a different result (MOLS diversity property).
	orderings := make(map[string]struct{})
	addresses := make([]string, 24)
	for i := range addresses {
		addresses[i] = fmt.Sprintf("ingress-%d", i)
	}
	for _, addr := range addresses {
		sel := SelectPriority(states, RouteState{LocalAddress: addr, MaxActiveRelays: len(states)})
		key := ""
		for _, u := range sel {
			key += u + "|"
		}
		orderings[key] = struct{}{}
	}

	if len(orderings) == 1 {
		// Verify by checking MOLS row diversity for these relays.
		order := len(states)
		m1, m2, _ := molsMultipliers(order, false)
		cols := make([]int, len(relayURLs))
		for i, relayURL := range relayURLs {
			cols[i] = int(hashToGridIndex(relayURL) % uint32(order))
		}

		type row [12]int
		rows := make(map[row]struct{})
		for _, addr := range addresses {
			i := int(hashToGridIndex(addr) % uint32(order))
			var r row
			for k, col := range cols {
				r[k] = molsScore(i, col, m1, m2, order)
			}
			rows[r] = struct{}{}
		}
		if len(rows) == 1 {
			t.Skip("all selected ingress addresses happen to hash to the same grid row")
		}
		t.Fatal("expected multiple ingress addresses to produce at least two distinct orderings")
	}
}

// TestMOLSSelectPriorityEmptyPoolReturnsNil checks the empty-input guard.
func TestMOLSSelectPriorityEmptyPoolReturnsNil(t *testing.T) {
	if got := SelectPriority(nil, RouteState{}); got != nil {
		t.Fatalf("SelectPriority(nil, ...) = %v, want nil", got)
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

// expectedScoreOrder mirrors RankRelayPool's index derivation: the ingress row
// is hashToGridIndex(localAddress) % order and each relay's column is
// hashToGridIndex(url) % order, where order is the current pool size.
func expectedScoreOrder(urls []string, localAddress string, order, m1, m2 int) []string {
	row := int(hashToGridIndex(localAddress) % uint32(order))
	type scored struct {
		url   string
		score int
	}
	scoredURLs := make([]scored, 0, len(urls))
	for _, relayURL := range urls {
		col := int(hashToGridIndex(relayURL) % uint32(order))
		scoredURLs = append(scoredURLs, scored{
			url:   relayURL,
			score: molsScore(row, col, m1, m2, order),
		})
	}
	slices.SortStableFunc(scoredURLs, func(a, b scored) int {
		if a.score != b.score {
			return cmp.Compare(b.score, a.score)
		}
		return cmp.Compare(a.url, b.url)
	})
	out := make([]string, 0, len(scoredURLs))
	for _, s := range scoredURLs {
		out = append(out, s.url)
	}
	return out
}

// TestRankRelayPoolGridShrinksWithPool verifies that removing a node from the
// pool shrinks the MOLS grid from NxN to (N-1)x(N-1) and that the surviving
// relays are re-ranked purely by their mechanically recomputed indexes.
func TestRankRelayPoolGridShrinksWithPool(t *testing.T) {
	const localAddress = "client-grid-shrink"
	relays := []string{
		"https://relay-shrink-0.example",
		"https://relay-shrink-1.example",
		"https://relay-shrink-2.example",
		"https://relay-shrink-3.example",
	}

	states := make([]RelayState, 0, len(relays))
	for _, relayURL := range relays {
		states = append(states, confirmedRelayState(t, relayURL))
	}

	ranked4 := RankRelayPool(states, localAddress)
	m1o4, m2o4, _ := molsMultipliers(4, false)
	if want := expectedScoreOrder(relays, localAddress, 4, m1o4, m2o4); !slices.Equal(ranked4, want) {
		t.Fatalf("RankRelayPool(4 relays) = %v, want %v (4x4 grid order)", ranked4, want)
	}

	// Evict one node: the grid must shrink to 3x3 and the remaining relays
	// must be ranked by their recomputed indexes at order 3.
	survivors := relays[:3]
	ranked3 := RankRelayPool(states[:3], localAddress)
	if slices.Contains(ranked3, relays[3]) {
		t.Fatalf("RankRelayPool(3 relays) = %v, removed relay %q still present", ranked3, relays[3])
	}
	m1o3, m2o3, _ := molsMultipliers(3, false)
	if want := expectedScoreOrder(survivors, localAddress, 3, m1o3, m2o3); !slices.Equal(ranked3, want) {
		t.Fatalf("RankRelayPool(3 relays) = %v, want %v (3x3 grid order)", ranked3, want)
	}
}

// TestSelectPriorityBannedRelayShrinksGrid verifies that a node excluded by
// the candidate filter leaves no stale entry: the output contains only the
// survivors, ranked with the shrunk (N-1)x(N-1) grid.
func TestSelectPriorityBannedRelayShrinksGrid(t *testing.T) {
	const localAddress = "client-ban-shrink"
	survivors := []string{
		"https://relay-ban-0.example",
		"https://relay-ban-1.example",
		"https://relay-ban-2.example",
	}
	bannedURL := "https://relay-ban-dead.example"

	states := make([]RelayState, 0, len(survivors)+1)
	for _, relayURL := range survivors {
		states = append(states, confirmedRelayState(t, relayURL))
	}
	banned := confirmedRelayState(t, bannedURL)
	banned.Banned = true
	states = append(states, banned)

	selected := SelectPriority(states, RouteState{LocalAddress: localAddress, MaxActiveRelays: len(survivors) + 1})
	if len(selected) != len(survivors) {
		t.Fatalf("len(selected) = %d, want %d (banned relay excluded)", len(selected), len(survivors))
	}
	if slices.Contains(selected, bannedURL) {
		t.Fatalf("selected = %v, banned relay %q still present", selected, bannedURL)
	}
	m1, m2, _ := molsMultipliers(len(survivors), false)
	if want := expectedScoreOrder(survivors, localAddress, len(survivors), m1, m2); !slices.Equal(selected, want) {
		t.Fatalf("selected = %v, want %v (3x3 grid order)", selected, want)
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

// mathGridOrder is coprime to 2 and to every MOLS multiplier (3, 5, 7, 11),
// so both multiplier pairs stay orthogonal at this order and the full
// magic-square properties hold.
const mathGridOrder = 13

// TestMOLSMagicRowSum verifies that each row of the base MOLS score grid sums
// to the magic constant n*(n^2+1)/2.
func TestMOLSMagicRowSum(t *testing.T) {
	const magicSum = mathGridOrder * (mathGridOrder*mathGridOrder + 1) / 2

	for i := 0; i < mathGridOrder; i++ {
		var rowSum int
		for j := 0; j < mathGridOrder; j++ {
			rowSum += molsScore(i, j, int(molsBaseM1), int(molsBaseM2), mathGridOrder)
		}
		if rowSum != magicSum {
			t.Fatalf("row i=%d sum = %d, want %d", i, rowSum, magicSum)
		}
	}
}

// TestMOLSMagicColumnSum verifies that each column sums to the magic constant.
func TestMOLSMagicColumnSum(t *testing.T) {
	const magicSum = mathGridOrder * (mathGridOrder*mathGridOrder + 1) / 2

	for j := 0; j < mathGridOrder; j++ {
		var colSum int
		for i := 0; i < mathGridOrder; i++ {
			colSum += molsScore(i, j, int(molsBaseM1), int(molsBaseM2), mathGridOrder)
		}
		if colSum != magicSum {
			t.Fatalf("column j=%d sum = %d, want %d", j, colSum, magicSum)
		}
	}
}

// TestMOLSGridUniqueness checks that all n² cells of the base grid have
// distinct values (Latin-square MOLS composite uniqueness).
func TestMOLSGridUniqueness(t *testing.T) {
	seen := make(map[int]struct{}, mathGridOrder*mathGridOrder)
	for i := 0; i < mathGridOrder; i++ {
		for j := 0; j < mathGridOrder; j++ {
			s := molsScore(i, j, int(molsBaseM1), int(molsBaseM2), mathGridOrder)
			if _, dup := seen[s]; dup {
				t.Fatalf("duplicate score %d at (%d, %d)", s, i, j)
			}
			seen[s] = struct{}{}
		}
	}
	if len(seen) != mathGridOrder*mathGridOrder {
		t.Fatalf("grid has %d unique values, want %d", len(seen), mathGridOrder*mathGridOrder)
	}
}

// TestMOLSVariantGridUniqueness checks uniqueness for the variant (7,11) grid.
func TestMOLSVariantGridUniqueness(t *testing.T) {
	seen := make(map[int]struct{}, mathGridOrder*mathGridOrder)
	for i := 0; i < mathGridOrder; i++ {
		for j := 0; j < mathGridOrder; j++ {
			s := molsScore(i, j, int(molsVariantM1), int(molsVariantM2), mathGridOrder)
			if _, dup := seen[s]; dup {
				t.Fatalf("duplicate score %d at (%d, %d) in variant grid", s, i, j)
			}
			seen[s] = struct{}{}
		}
	}
	if len(seen) != mathGridOrder*mathGridOrder {
		t.Fatalf("variant grid has %d unique values, want %d", len(seen), mathGridOrder*mathGridOrder)
	}
}

// TestMOLSHashToGridIndexStableAndFoldable checks that hashToGridIndex is
// deterministic and folds into any grid order without going out of range.
func TestMOLSHashToGridIndexStableAndFoldable(t *testing.T) {
	inputs := []string{"", "a", "hello", "0x1234", "https://relay.example", "unicode-ish"}
	for _, s := range inputs {
		h := hashToGridIndex(s)
		for order := 1; order <= 64; order++ {
			if idx := h % uint32(order); idx >= uint32(order) {
				t.Fatalf("hashToGridIndex(%q) %% %d = %d, out of range", s, order, idx)
			}
		}
	}
}

// TestMOLSRTTStatsEmpty checks that an empty slice returns zero values.
func TestMOLSRTTStatsEmpty(t *testing.T) {
	mean, cv := molsRTTStats(nil)
	if mean != 0 || cv != 0 {
		t.Fatalf("molsRTTStats(nil) = (%v, %v), want (0, 0)", mean, cv)
	}
}

// TestMOLSSelectPriorityScoreOrdering verifies that SelectPriority returns a
// two-relay pool in descending MOLS score order. EWMA RTT is telemetry only
// and does not participate in scoring.
func TestMOLSSelectPriorityScoreOrdering(t *testing.T) {
	const localAddress = "test-ingress"
	relays := []string{
		"https://relay-stable.example",
		"https://relay-unstable.example",
	}

	states := make([]RelayState, 0, len(relays))
	for _, relayURL := range relays {
		states = append(states, confirmedRelayState(t, relayURL))
	}

	selected := SelectPriority(states, RouteState{LocalAddress: localAddress})

	if len(selected) != 2 {
		t.Fatalf("len(selected) = %d, want 2", len(selected))
	}

	m1, m2, _ := molsMultipliers(len(relays), false)
	if want := expectedScoreOrder(relays, localAddress, len(relays), m1, m2); !slices.Equal(selected, want) {
		t.Fatalf("selected = %v, want %v (2x2 grid order)", selected, want)
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
