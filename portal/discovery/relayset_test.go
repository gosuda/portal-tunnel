package discovery

import (
	"slices"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func relayStates(set *RelaySet) []RelayState {
	set.mu.RLock()
	defer set.mu.RUnlock()
	states := make([]RelayState, 0, len(set.relays))
	for _, state := range set.relays {
		if !state.Banned {
			states = append(states, state)
		}
	}
	return states
}

func mustRelayDescriptor(t *testing.T, relayURL string) types.RelayDescriptor {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	return mustSignedDescriptor(t, mustSigningIdentity(t), relayURL, now)
}

func confirmedRelayState(t *testing.T, relayURL string) RelayState {
	t.Helper()
	return RelayState{
		Descriptor: mustRelayDescriptor(t, relayURL),
		Confirmed:  true,
		LastSeenAt: time.Now().UTC(),
	}
}

func bootstrapRelayState(relayURL string) RelayState {
	state := newRelayState(relayURL)
	state.Bootstrap = true
	return state
}

func TestApplyRelayDiscoveryResponsePreservesBootstrapFlag(t *testing.T) {
	set := NewRelaySet([]string{"https://relay-a.example"})

	desc := mustRelayDescriptor(t, "https://relay-a.example")
	if _, err := set.ApplyRelayDiscoveryResponse(desc.APIHTTPSAddr, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

	states := relayStates(set)
	if len(states) != 1 {
		t.Fatalf("len(relayStates()) = %d, want 1", len(states))
	}
	if !states[0].Bootstrap {
		t.Fatal("bootstrap relay lost bootstrap flag after discovery update")
	}
}

func TestDescriptorsDropsExpiredSignedRelayDescriptor(t *testing.T) {
	set := NewRelaySet(nil)

	now := time.Now().UTC()
	relayURL := "https://relay-stale.example"
	state := confirmedRelayState(t, relayURL)
	state.Descriptor.ExpiresAt = now.Add(-time.Minute)
	state.LastSeenAt = now.Add(-6 * time.Hour)
	state.Descriptor.SupportsUDP = true
	state.Descriptor.SupportsTCP = true

	set.mu.Lock()
	set.relays[relayURL] = state
	set.mu.Unlock()

	descriptors := set.Descriptors(types.RelayDescriptor{})
	if len(descriptors) != 0 {
		t.Fatalf("len(Descriptors(empty)) = %d, want 0", len(descriptors))
	}
}

func TestDescriptorsDropsDeadRelayDescriptor(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-dead.example"
	state := confirmedRelayState(t, relayURL)
	state.Dead = true

	set.mu.Lock()
	set.relays[relayURL] = state
	set.mu.Unlock()

	descriptors := set.Descriptors(types.RelayDescriptor{})
	if len(descriptors) != 0 {
		t.Fatalf("len(Descriptors(dead)) = %d, want 0", len(descriptors))
	}
}

func TestDescriptorsKeepsRelayDuringTransientDiscoveryFailure(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-unstable.example"
	state := confirmedRelayState(t, relayURL)
	state.discoveryFailures = 1

	set.mu.Lock()
	set.relays[relayURL] = state
	set.mu.Unlock()

	descriptors := set.Descriptors(types.RelayDescriptor{})
	if len(descriptors) != 1 {
		t.Fatalf("len(Descriptors(transient failure)) = %d, want 1", len(descriptors))
	}
	if descriptors[0].APIHTTPSAddr != relayURL {
		t.Fatalf("Descriptors(transient failure)[0] = %q, want %q", descriptors[0].APIHTTPSAddr, relayURL)
	}
}

func TestDescriptorsDropsBannedRelayDescriptor(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-banned.example"
	state := confirmedRelayState(t, relayURL)
	state.Banned = true

	set.mu.Lock()
	set.relays[relayURL] = state
	set.mu.Unlock()

	descriptors := set.Descriptors(types.RelayDescriptor{})
	if len(descriptors) != 0 {
		t.Fatalf("len(Descriptors(banned)) = %d, want 0", len(descriptors))
	}
}

func TestApplyRelayDiscoveryResponseCollectsRelaysDespiteProtocolMismatch(t *testing.T) {
	set := NewRelaySet(nil)

	desc := mustRelayDescriptor(t, "https://relay-mismatch.example")
	changed, err := set.ApplyRelayDiscoveryResponse("", types.DiscoveryResponse{
		ProtocolVersion: "5",
		Relays:          []types.RelayDescriptor{desc},
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}
	if !changed {
		t.Fatal("expected protocol-mismatched discovery response to change relay set")
	}

	states := relayStates(set)
	if len(states) != 1 {
		t.Fatalf("len(relayStates()) = %d, want 1", len(states))
	}
	if got := states[0].Descriptor.APIHTTPSAddr; got != desc.APIHTTPSAddr {
		t.Fatalf("states[0] = %q, want %q", got, desc.APIHTTPSAddr)
	}
	if states[0].Confirmed {
		t.Fatal("hinted relay should not become locally confirmed from aggregation")
	}
}

func TestApplyRelayDiscoveryResponseCollectsHintsWhenTargetDescriptorIsMissing(t *testing.T) {
	set := NewRelaySet(nil)

	hinted := mustRelayDescriptor(t, "https://relay-hinted.example")
	changed, err := set.ApplyRelayDiscoveryResponse("https://relay-source.example", types.DiscoveryResponse{
		ProtocolVersion: "5",
		Relays:          []types.RelayDescriptor{hinted},
	}, time.Now().UTC())
	if err == nil {
		t.Fatal("expected missing target descriptor error")
	}
	if !changed {
		t.Fatal("expected hinted relay to still be collected")
	}

	states := relayStates(set)
	if len(states) != 1 {
		t.Fatalf("len(relayStates()) = %d, want 1", len(states))
	}
	if got := states[0].Descriptor.APIHTTPSAddr; got != hinted.APIHTTPSAddr {
		t.Fatalf("states[0] = %q, want %q", got, hinted.APIHTTPSAddr)
	}
	if states[0].Confirmed {
		t.Fatal("hinted relay should not become locally confirmed when target descriptor is missing")
	}
}

func TestApplyRelayDiscoveryResponseClearsDiscoveryRetryOnAuthoritativeSuccess(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-source.example"
	desc := mustRelayDescriptor(t, relayURL)
	set.mu.Lock()
	state := RelayState{
		Descriptor:             desc,
		LastSeenAt:             time.Now().UTC(),
		discoveryFailures:      defaultRecoveryFailures,
		nextDiscoveryRefreshAt: time.Now().UTC().Add(time.Minute),
		activeFailures:         1,
		suppressActiveUntil:    time.Now().UTC().Add(time.Minute),
	}
	set.relays[relayURL] = state
	set.mu.Unlock()

	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

	set.mu.RLock()
	refreshed := set.relays[relayURL]
	set.mu.RUnlock()
	if refreshed.discoveryFailures != 0 {
		t.Fatalf("discoveryFailures = %d, want 0", refreshed.discoveryFailures)
	}
	if !refreshed.nextDiscoveryRefreshAt.IsZero() {
		t.Fatalf("nextDiscoveryRefreshAt = %v, want zero time", refreshed.nextDiscoveryRefreshAt)
	}
	if refreshed.activeFailures != 1 {
		t.Fatalf("activeFailures = %d, want 1", refreshed.activeFailures)
	}
	if refreshed.suppressActiveUntil.IsZero() {
		t.Fatal("suppressActiveUntil was cleared by discovery success")
	}
}

func TestApplyRelayDiscoveryResponsePreservesDiscoveryRetryOnHint(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-hinted.example"
	desc := mustRelayDescriptor(t, relayURL)
	nextDiscoveryRefreshAt := time.Now().UTC().Add(time.Minute)
	set.mu.Lock()
	state := RelayState{
		Descriptor:             desc,
		LastSeenAt:             time.Now().UTC(),
		nextDiscoveryRefreshAt: nextDiscoveryRefreshAt,
	}
	set.relays[relayURL] = state
	set.mu.Unlock()

	if _, err := set.ApplyRelayDiscoveryResponse("", types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

	set.mu.RLock()
	refreshed := set.relays[relayURL]
	set.mu.RUnlock()
	if !refreshed.nextDiscoveryRefreshAt.Equal(nextDiscoveryRefreshAt) {
		t.Fatalf("nextDiscoveryRefreshAt = %v, want %v", refreshed.nextDiscoveryRefreshAt, nextDiscoveryRefreshAt)
	}
}

func TestConfirmRelayURLMarksRelayConfirmedWithoutChangingAggregateDescriptor(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-confirmed.example"
	state := RelayState{
		Descriptor: mustRelayDescriptor(t, relayURL),
		LastSeenAt: time.Now().UTC(),
	}

	set.mu.Lock()
	set.relays[relayURL] = state
	set.mu.Unlock()

	set.ConfirmRelayURL(relayURL)

	set.mu.RLock()
	confirmed := set.relays[relayURL]
	set.mu.RUnlock()
	if !confirmed.Confirmed {
		t.Fatal("relay should become locally confirmed after listener success")
	}
	if confirmed.Descriptor.APIHTTPSAddr != relayURL {
		t.Fatalf("descriptor api_https_addr = %q, want %q", confirmed.Descriptor.APIHTTPSAddr, relayURL)
	}
}

func TestConfirmRelayURLResetsActiveFailures(t *testing.T) {
	relayURL := "https://error.io"
	set := NewRelaySet(nil)
	state := RelayState{
		Descriptor: types.RelayDescriptor{
			APIHTTPSAddr: relayURL,
		},
		activeFailures:      5,
		suppressActiveUntil: time.Now().UTC().Add(time.Minute),
	}
	set.mu.Lock()
	set.relays[relayURL] = state
	set.mu.Unlock()

	set.ConfirmRelayURL(relayURL)

	set.mu.RLock()
	state = set.relays[relayURL]
	set.mu.RUnlock()
	if !state.Confirmed {
		t.Fatal("relay should be confirmed")
	}
	if state.activeFailures != 0 {
		t.Fatalf("activeFailures = %d, want 0", state.activeFailures)
	}
	if !state.suppressActiveUntil.IsZero() {
		t.Fatalf("suppressActiveUntil = %v, want zero", state.suppressActiveUntil)
	}
}

func TestUnconfirmRelayURLClearsLocalConfirmationOnly(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-confirmed.example"
	state := confirmedRelayState(t, relayURL)

	set.mu.Lock()
	set.relays[relayURL] = state
	set.mu.Unlock()

	set.UnconfirmRelayURL(relayURL)

	set.mu.RLock()
	unconfirmed := set.relays[relayURL]
	set.mu.RUnlock()
	if unconfirmed.Confirmed {
		t.Fatal("relay should lose local confirmation after listener failure")
	}
}

func TestRecordDiscoveryFailureBackoff(t *testing.T) {
	relayURL := "https://discovery-error.example"
	set := NewRelaySet(nil)
	set.mu.Lock()
	set.relays[relayURL] = confirmedRelayState(t, relayURL)
	set.mu.Unlock()
	budget := 3

	start := time.Now()
	for i := 0; i < budget; i++ {
		backedOff, _, _ := set.RecordDiscoveryFailure(relayURL, budget)
		if i < budget-1 && backedOff {
			t.Fatal("discovery failure backed off before budget")
		}
	}

	set.mu.RLock()
	state := set.relays[relayURL]
	set.mu.RUnlock()
	if !state.nextDiscoveryRefreshAt.After(start) {
		t.Fatal("discovery retry timer was not scheduled")
	}
	if !state.suppressActiveUntil.IsZero() {
		t.Fatalf("suppressActiveUntil = %v, want zero", state.suppressActiveUntil)
	}
}

func TestRecordDiscoveryFailureMarksDeadAndRevivesOnAuthoritativeSuccess(t *testing.T) {
	set := NewRelaySet(nil)

	deadURL := "https://relay-dead.example"
	aliveURL := "https://relay-alive.example"
	deadDesc := mustRelayDescriptor(t, deadURL)

	set.mu.Lock()
	set.relays[deadURL] = RelayState{
		Descriptor: deadDesc,
		Confirmed:  true,
		LastSeenAt: time.Now().UTC(),
	}
	set.relays[aliveURL] = confirmedRelayState(t, aliveURL)
	set.mu.Unlock()

	budget := 3
	for i := 0; i < budget; i++ {
		set.RecordDiscoveryFailure(deadURL, budget)
	}

	set.mu.RLock()
	dead := set.relays[deadURL]
	set.mu.RUnlock()
	if !dead.Dead {
		t.Fatal("relay was not marked dead after exhausting discovery failure budget")
	}

	routes, err := set.PlanRoutes(nil, RouteState{LocalAddress: "client", ExplicitRelayURLs: []string{deadURL}})
	if err != nil {
		t.Fatalf("PlanRoutes() error = %v", err)
	}
	if len(routes) == 0 {
		t.Fatal("alive relay was excluded from route planning")
	}
	for _, route := range routes {
		if route.ListenerRelayURL() == deadURL {
			t.Fatal("dead relay was included in route planning")
		}
	}

	if _, err := set.ApplyRelayDiscoveryResponse(deadURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{deadDesc},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

	set.mu.RLock()
	revived := set.relays[deadURL]
	set.mu.RUnlock()
	if revived.Dead {
		t.Fatal("dead mark was not cleared after authoritative discovery success")
	}

	routes, err = set.PlanRoutes(nil, RouteState{LocalAddress: "client"})
	if err != nil {
		t.Fatalf("PlanRoutes() error = %v", err)
	}
	found := false
	for _, route := range routes {
		if route.ListenerRelayURL() == deadURL {
			found = true
		}
	}
	if !found {
		t.Fatal("revived relay was not re-included in route planning")
	}
}

func TestRecordActiveFailureBackoff(t *testing.T) {
	relayURL := "https://active-error.example"
	set := NewRelaySet(nil)
	set.mu.Lock()
	set.relays[relayURL] = confirmedRelayState(t, relayURL)
	set.mu.Unlock()
	start := time.Now()

	backedOff, _, _ := set.RecordActiveFailure(relayURL, 1)
	if !backedOff {
		t.Fatal("active failure should back off at budget")
	}
	set.mu.RLock()
	state := set.relays[relayURL]
	set.mu.RUnlock()
	if !state.suppressActiveUntil.After(start) {
		t.Fatal("active suppression timer was not scheduled")
	}
	if !state.nextDiscoveryRefreshAt.IsZero() {
		t.Fatalf("nextDiscoveryRefreshAt = %v, want zero", state.nextDiscoveryRefreshAt)
	}
}

func TestRecordDiscoveryFailurePoolBansLongUnhealthyRelay(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-unhealthy.example"
	state := confirmedRelayState(t, relayURL)
	state.unhealthySince = time.Now().UTC().Add(-AnnounceMaxValidity - time.Minute)

	set.mu.Lock()
	set.relays[relayURL] = state
	set.mu.Unlock()

	backedOff, reason, failures := set.RecordDiscoveryFailure(relayURL, 1)
	if !backedOff || reason != "unhealthy" {
		t.Fatalf("RecordDiscoveryFailure() = (%v, %q), want unhealthy pool ban", backedOff, reason)
	}
	if failures != 1 {
		t.Fatalf("failure count = %d, want 1", failures)
	}

	set.mu.RLock()
	quarantined := set.relays[relayURL]
	set.mu.RUnlock()
	if !quarantined.Banned {
		t.Fatal("unhealthy relay was not pool-banned")
	}
	if quarantined.hasObservedDescriptor() {
		t.Fatal("unhealthy relay descriptor should be removed from active relay pool")
	}
	if !quarantined.suppressActiveUntil.After(time.Now().UTC().Add(relayPoolBanTTL - time.Minute)) {
		t.Fatalf("pool ban until = %v, want about %v from now", quarantined.suppressActiveUntil, relayPoolBanTTL)
	}
}

func TestRecordActiveFailureDoesNotPoolBanLongUnhealthyRelay(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-active-unhealthy.example"
	state := confirmedRelayState(t, relayURL)
	state.unhealthySince = time.Now().UTC().Add(-AnnounceMaxValidity - time.Minute)

	set.mu.Lock()
	set.relays[relayURL] = state
	set.mu.Unlock()

	backedOff, reason, failures := set.RecordActiveFailure(relayURL, 1)
	if !backedOff || reason != "active" {
		t.Fatalf("RecordActiveFailure() = (%v, %q), want active backoff", backedOff, reason)
	}
	if failures != 1 {
		t.Fatalf("failure count = %d, want 1", failures)
	}

	set.mu.RLock()
	activeBackoff := set.relays[relayURL]
	set.mu.RUnlock()
	if activeBackoff.Banned {
		t.Fatal("active failure should not pool-ban relay")
	}
	if !activeBackoff.hasObservedDescriptor() {
		t.Fatal("active failure should not remove relay descriptor")
	}
	if activeBackoff.suppressActiveUntil.IsZero() {
		t.Fatal("active failure should schedule active suppression")
	}
}

func TestPoolBanRejectsDiscoveryUntilExpiry(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-quarantined.example"
	desc := mustRelayDescriptor(t, relayURL)

	set.mu.Lock()
	state := newRelayState(relayURL)
	state.Banned = true
	state.suppressActiveUntil = time.Now().UTC().Add(time.Hour)
	set.relays[relayURL] = state
	set.mu.Unlock()

	changed, err := set.ApplyRelayDiscoveryResponse("", types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}
	if changed {
		t.Fatal("pool-banned relay should not change relay set")
	}
	if got := relayStates(set); len(got) != 0 {
		t.Fatalf("len(relayStates()) = %d, want 0", len(got))
	}

	set.mu.Lock()
	state = set.relays[relayURL]
	state.suppressActiveUntil = time.Now().UTC().Add(-time.Second)
	set.relays[relayURL] = state
	set.mu.Unlock()

	changed, err = set.ApplyRelayDiscoveryResponse("", types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() after expiry error = %v", err)
	}
	if !changed {
		t.Fatal("expired pool ban should allow relay set update")
	}
	if got := relayStates(set); len(got) != 1 || got[0].Descriptor.APIHTTPSAddr != relayURL {
		t.Fatalf("relayStates() = %v, want relay %q", got, relayURL)
	}
}

func TestPlanRoutesExplicitPathReturnsSingleRouteToEntry(t *testing.T) {
	const (
		entry = "https://entry.example"
		mid   = "https://middle.example"
		exit  = "https://exit.example"
	)

	routes, err := NewRelaySet(nil).PlanRoutes([]string{entry, mid, exit}, RouteState{})
	if err != nil {
		t.Fatalf("PlanRoutes() error = %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("len(routes) = %d, want 1", len(routes))
	}
	route := routes[0]
	if !route.Explicit() {
		t.Fatal("route.Explicit() = false, want true")
	}
	if got := route.ListenerRelayURL(); got != entry {
		t.Fatalf("ListenerRelayURL() = %q, want %q", got, entry)
	}
	path := route.MultiHop()
	if len(path) != 3 || path[0] != entry || path[1] != mid || path[2] != exit {
		t.Fatalf("MultiHop() = %v, want [%q %q %q]", path, entry, mid, exit)
	}
}

func TestPlanRoutesBuildsMultiHopPathsForEveryRequestedEntryRelay(t *testing.T) {
	set := NewRelaySet(nil)
	now := time.Now().UTC()
	for _, relayURL := range []string{
		"https://relay-a.example", "https://relay-b.example",
		"https://relay-c.example", "https://relay-d.example",
	} {
		state := confirmedRelayState(t, relayURL)
		state.LastSeenAt = now
		state.Descriptor.SupportsOverlay = true
		state.Descriptor.WireGuardPublicKey = "wg-key"
		state.Descriptor.WireGuardPort = 51820
		set.relays[relayURL] = state
	}

	routes, err := set.PlanRoutes(nil, RouteState{MultiHopDepth: 3, MaxActiveRelays: 4, LocalAddress: "client"})
	if err != nil {
		t.Fatalf("PlanRoutes() error = %v", err)
	}
	if len(routes) != 4 {
		t.Fatalf("len(routes) = %d, want 4; every relay should be an entry point", len(routes))
	}
	entries := make(map[string]bool, len(routes))
	for _, route := range routes {
		if path := route.MultiHop(); len(path) != 3 || route.ListenerRelayURL() != path[0] {
			t.Fatalf("route = %v, want three-hop path from its entry relay", path)
		}
		entries[route.ListenerRelayURL()] = true
	}
	if len(entries) != 4 {
		t.Fatalf("entry relays = %v, want all four relays", entries)
	}
}

func TestPlanRoutesCapsMultiHopListenerEntries(t *testing.T) {
	set := NewRelaySet(nil)
	now := time.Now().UTC()
	for _, relayURL := range []string{
		"https://relay-a.example", "https://relay-b.example", "https://relay-c.example", "https://relay-d.example",
	} {
		state := confirmedRelayState(t, relayURL)
		state.LastSeenAt = now
		state.Descriptor.SupportsOverlay = true
		state.Descriptor.WireGuardPublicKey = "wg-key"
		state.Descriptor.WireGuardPort = 51820
		set.relays[relayURL] = state
	}

	routes, err := set.PlanRoutes(nil, RouteState{MultiHopDepth: 3, MaxActiveRelays: 2, LocalAddress: "client"})
	if err != nil {
		t.Fatalf("PlanRoutes() error = %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("len(routes) = %d, want 2 capped listener entries", len(routes))
	}
	for _, route := range routes {
		if len(route.MultiHop()) != 3 {
			t.Fatalf("route %v does not retain a complete three-hop path", route.MultiHop())
		}
	}
}

func TestPlanRoutesKeepsBootstrapRelayAsMultiHopEntry(t *testing.T) {
	set := NewRelaySet(nil)
	now := time.Now().UTC()
	const bootstrap = "https://relay-bootstrap.example"
	for _, relayURL := range []string{
		bootstrap, "https://relay-b.example", "https://relay-c.example",
	} {
		state := confirmedRelayState(t, relayURL)
		state.LastSeenAt = now
		state.Descriptor.SupportsOverlay = true
		state.Descriptor.WireGuardPublicKey = "wg-key"
		state.Descriptor.WireGuardPort = 51820
		set.relays[relayURL] = state
	}

	routes, err := set.PlanRoutes(nil, RouteState{
		ExplicitRelayURLs: []string{bootstrap},
		MultiHopDepth:     3,
		LocalAddress:      "client",
	})
	if err != nil {
		t.Fatalf("PlanRoutes() error = %v", err)
	}
	for _, route := range routes {
		if route.ListenerRelayURL() == bootstrap {
			return
		}
	}
	t.Fatalf("routes = %v, want bootstrap relay %q as an entry", routes, bootstrap)
}

func TestPlanRoutesSkipsUnavailableMultiHopRelays(t *testing.T) {
	set := NewRelaySet(nil)
	now := time.Now().UTC()
	for _, relayURL := range []string{
		"https://relay-a.example", "https://relay-b.example", "https://relay-c.example",
	} {
		state := confirmedRelayState(t, relayURL)
		state.LastSeenAt = now
		state.Descriptor.SupportsOverlay = true
		state.Descriptor.WireGuardPublicKey = "wg-key"
		state.Descriptor.WireGuardPort = 51820
		set.relays[relayURL] = state
	}

	incompatible := confirmedRelayState(t, "https://relay-incompatible.example")
	incompatible.LastSeenAt = now
	set.relays[incompatible.Descriptor.APIHTTPSAddr] = incompatible

	suppressed := confirmedRelayState(t, "https://relay-suppressed.example")
	suppressed.LastSeenAt = now
	suppressed.Descriptor.SupportsOverlay = true
	suppressed.Descriptor.WireGuardPublicKey = "wg-key"
	suppressed.Descriptor.WireGuardPort = 51820
	suppressed.suppressActiveUntil = now.Add(time.Minute)
	set.relays[suppressed.Descriptor.APIHTTPSAddr] = suppressed

	recovering := confirmedRelayState(t, "https://relay-recovering.example")
	recovering.LastSeenAt = now
	recovering.Descriptor.SupportsOverlay = true
	recovering.Descriptor.WireGuardPublicKey = "wg-key"
	recovering.Descriptor.WireGuardPort = 51820
	recovering.nextDiscoveryRefreshAt = now.Add(time.Minute)
	set.relays[recovering.Descriptor.APIHTTPSAddr] = recovering

	routes, err := set.PlanRoutes(nil, RouteState{MultiHopDepth: 3, LocalAddress: "client"})
	if err != nil {
		t.Fatalf("PlanRoutes() error = %v", err)
	}
	if len(routes) != 3 {
		t.Fatalf("len(routes) = %d, want 3", len(routes))
	}
	for _, route := range routes {
		for _, relayURL := range route.MultiHop() {
			if relayURL == incompatible.Descriptor.APIHTTPSAddr || relayURL == suppressed.Descriptor.APIHTTPSAddr || relayURL == recovering.Descriptor.APIHTTPSAddr {
				t.Fatalf("route %v includes unavailable relay %q", route.MultiHop(), relayURL)
			}
		}
	}
}

func TestPlanRoutesSkipsMultiHopRelayWithoutRequiredTransport(t *testing.T) {
	set := NewRelaySet(nil)
	now := time.Now().UTC()
	for _, relayURL := range []string{
		"https://relay-a.example", "https://relay-b.example", "https://relay-c.example", "https://relay-d.example",
	} {
		state := confirmedRelayState(t, relayURL)
		state.LastSeenAt = now
		state.Descriptor.SupportsOverlay = true
		state.Descriptor.SupportsTCP = relayURL != "https://relay-d.example"
		state.Descriptor.WireGuardPublicKey = "wg-key"
		state.Descriptor.WireGuardPort = 51820
		set.relays[relayURL] = state
	}

	routes, err := set.PlanRoutes(nil, RouteState{
		MultiHopDepth:   3,
		RequireTCP:      true,
		MaxActiveRelays: 3,
		LocalAddress:    "client",
	})
	if err != nil {
		t.Fatalf("PlanRoutes() error = %v", err)
	}
	for _, route := range routes {
		for _, relayURL := range route.MultiHop() {
			if relayURL == "https://relay-d.example" {
				t.Fatalf("TCP-incompatible relay appears in multi-hop route %v", route.MultiHop())
			}
		}
	}
}

func TestBuildMOLSPathsWrapsAtEndOfRankedRelays(t *testing.T) {
	routes, err := buildMOLSPaths([]string{"a", "b", "c", "d"}, 3, 4)
	if err != nil {
		t.Fatalf("buildMOLSPaths() error = %v", err)
	}
	if len(routes) != 4 {
		t.Fatalf("len(routes) = %d, want 4", len(routes))
	}
	if got, want := routes[3].MultiHop(), []string{"d", "a", "b"}; !slices.Equal(got, want) {
		t.Fatalf("last path = %v, want %v", got, want)
	}
}

func TestPlanRoutesSkipsExplicitRelayWithoutRequiredTransport(t *testing.T) {
	const relayURL = "https://relay-udp-disabled.example"
	set := NewRelaySet(nil)
	state := confirmedRelayState(t, relayURL)
	state.Descriptor.SupportsUDP = false
	set.relays[relayURL] = state

	routes, err := set.PlanRoutes(nil, RouteState{
		ExplicitRelayURLs: []string{relayURL},
		RequireUDP:        true,
	})
	if err != nil {
		t.Fatalf("PlanRoutes() error = %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("PlanRoutes() = %v, want no UDP-incompatible explicit route", routes)
	}
}

func TestPlanRoutesIncludesExplicitRelayMissingFromSet(t *testing.T) {
	const relayURL = "https://relay-explicit.example"

	routes, err := NewRelaySet(nil).PlanRoutes(nil, RouteState{
		ExplicitRelayURLs: []string{relayURL},
	})
	if err != nil {
		t.Fatalf("PlanRoutes() error = %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("len(routes) = %d, want 1", len(routes))
	}
	route := routes[0]
	if !route.Explicit() {
		t.Fatal("route.Explicit() = false, want true")
	}
	if got := route.ListenerRelayURL(); got != relayURL {
		t.Fatalf("ListenerRelayURL() = %q, want %q", got, relayURL)
	}
}
