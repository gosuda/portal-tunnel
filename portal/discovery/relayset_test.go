package discovery

import (
	"slices"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// relayStates returns the non-banned relay states as seen through the public
// AllRelays view.
func relayStates(set *RelaySet) []RelayState {
	states := set.AllRelays()
	out := make([]RelayState, 0, len(states))
	for _, state := range states {
		if !state.Banned {
			out = append(out, state)
		}
	}
	return out
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
		Trust:      RelayVerified,
		Confirmed:  true,
		LastSeenAt: time.Now().UTC(),
	}
}

func bootstrapRelayState(relayURL string) RelayState {
	state := newRelayState(relayURL)
	state.Bootstrap = true
	return state
}

// mustApplyAuthoritative ingests the descriptor as a successful authoritative
// discovery response from the relay itself, promoting it to RelayVerified.
func mustApplyAuthoritative(t *testing.T, set *RelaySet, desc types.RelayDescriptor) {
	t.Helper()
	if _, err := set.ApplyRelayDiscoveryResponse(desc.APIHTTPSAddr, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse(%q) error = %v", desc.APIHTTPSAddr, err)
	}
}

// servesDescriptor reports whether the set currently gossips relayURL onward.
func servesDescriptor(set *RelaySet, relayURL string) bool {
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == relayURL {
			return true
		}
	}
	return false
}

// routesTo reports whether automatic single-hop route planning selects relayURL.
func routesTo(t *testing.T, set *RelaySet, relayURL string) bool {
	t.Helper()
	routes, err := set.PlanRoutes(nil, RouteState{LocalAddress: "client"})
	if err != nil {
		t.Fatalf("PlanRoutes() error = %v", err)
	}
	for _, route := range routes {
		if route.ListenerRelayURL() == relayURL {
			return true
		}
	}
	return false
}

func TestApplyRelayDiscoveryResponsePreservesBootstrapFlag(t *testing.T) {
	relayURL := "https://relay-a.example"
	set := NewRelaySet([]string{relayURL})

	mustApplyAuthoritative(t, set, mustRelayDescriptor(t, relayURL))

	if got := set.BootstrapRelayURLs(); len(got) != 1 || got[0] != relayURL {
		t.Fatalf("BootstrapRelayURLs() = %v, want bootstrap relay to survive discovery update", got)
	}
}

func TestDescriptorsDropsExpiredSignedRelayDescriptor(t *testing.T) {
	set := NewRelaySet(nil)

	now := time.Now().UTC()
	relayURL := "https://relay-stale.example"
	state := confirmedRelayState(t, relayURL)
	state.Descriptor.ExpiresAt = now.Add(-time.Minute)
	state.LastSeenAt = now.Add(-6 * time.Hour)
	set.relays[relayURL] = state

	if descriptors := set.Descriptors(types.RelayDescriptor{}); len(descriptors) != 0 {
		t.Fatalf("Descriptors(expired) = %v, want empty", descriptors)
	}
}

// A banned relay stops being served to peers, stops being selected for new
// routes, and cannot re-enter through a later gossip announce.
func TestBannedRelayStopsServingAndRouting(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-banned.example"
	desc := mustRelayDescriptor(t, relayURL)
	mustApplyAuthoritative(t, set, desc)
	if !servesDescriptor(set, relayURL) || !routesTo(t, set, relayURL) {
		t.Fatal("verified relay should serve and route before the ban")
	}

	set.BanRelayURL(relayURL)

	if servesDescriptor(set, relayURL) {
		t.Fatal("banned relay is still gossiped to peers")
	}
	if routesTo(t, set, relayURL) {
		t.Fatal("banned relay is still selected for new routes")
	}

	changed, err := set.ApplyRelayDiscoveryResponse("", types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}
	if changed || servesDescriptor(set, relayURL) {
		t.Fatal("gossip announce re-admitted a banned relay")
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

// Discovery-failure lifecycle: a transient failure does not remove an
// otherwise usable relay, exhausting the failure budget does, a gossip hint
// does not revive it, and a direct authoritative success does.
func TestDiscoveryFailureLifecycle(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
		budget = 3
	)
	set := NewRelaySet(nil)
	descA := mustRelayDescriptor(t, relayA)
	mustApplyAuthoritative(t, set, descA)
	mustApplyAuthoritative(t, set, mustRelayDescriptor(t, relayB))

	set.RecordDiscoveryFailure(relayA, budget)
	if !servesDescriptor(set, relayA) || !routesTo(t, set, relayA) {
		t.Fatal("a transient discovery failure removed an otherwise usable relay")
	}

	for range budget - 1 {
		set.RecordDiscoveryFailure(relayA, budget)
	}
	if servesDescriptor(set, relayA) || routesTo(t, set, relayA) {
		t.Fatal("relay with exhausted discovery budget is still served or routed")
	}
	if !servesDescriptor(set, relayB) || !routesTo(t, set, relayB) {
		t.Fatal("healthy relay was affected by another relay's discovery failures")
	}

	if _, err := set.ApplyRelayDiscoveryResponse("", types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{descA},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse(hint) error = %v", err)
	}
	if servesDescriptor(set, relayA) || routesTo(t, set, relayA) {
		t.Fatal("a gossip hint revived a dead relay; only authoritative contact may")
	}

	mustApplyAuthoritative(t, set, descA)
	if !servesDescriptor(set, relayA) || !routesTo(t, set, relayA) {
		t.Fatal("authoritative discovery success did not revive the relay")
	}
}

// Active-failure lifecycle: a listener failure suppresses the relay from new
// routes without banning it or hiding its descriptor, a later discovery
// success does not forgive the failure, and a successful listener
// confirmation does.
func TestActiveFailureLifecycle(t *testing.T) {
	const relayA = "https://relay-a.example"
	set := NewRelaySet(nil)
	desc := mustRelayDescriptor(t, relayA)
	mustApplyAuthoritative(t, set, desc)

	backedOff, _, _ := set.RecordActiveFailure(relayA, 1)
	if !backedOff {
		t.Fatal("active failure at budget should back off")
	}
	if routesTo(t, set, relayA) {
		t.Fatal("suppressed relay is still selected for new routes")
	}
	if !servesDescriptor(set, relayA) {
		t.Fatal("active failure hid the relay descriptor from peers")
	}
	if states := set.AllRelays(); len(states) != 1 || states[0].Banned {
		t.Fatalf("AllRelays() = %+v, want relay retained without a ban", states)
	}

	mustApplyAuthoritative(t, set, desc)
	if routesTo(t, set, relayA) {
		t.Fatal("discovery success forgave active listener failures")
	}

	set.ConfirmRelayURL(relayA)
	if !routesTo(t, set, relayA) {
		t.Fatal("listener confirmation did not restore the relay to route planning")
	}
}

// Listener confirmation is local state layered on top of discovery: discovery
// alone never confirms a relay, ConfirmRelayURL does, and UnconfirmRelayURL
// clears only the confirmation while keeping the relay as a candidate.
func TestConfirmAndUnconfirmRelayURL(t *testing.T) {
	const relayA = "https://relay-a.example"
	set := NewRelaySet(nil)
	mustApplyAuthoritative(t, set, mustRelayDescriptor(t, relayA))

	if confirmed := set.ConfirmedRelays(); len(confirmed) != 0 {
		t.Fatalf("ConfirmedRelays() = %v, want empty before listener success", confirmed)
	}

	set.ConfirmRelayURL(relayA)
	confirmed := set.ConfirmedRelays()
	if len(confirmed) != 1 || confirmed[0].Descriptor.APIHTTPSAddr != relayA {
		t.Fatalf("ConfirmedRelays() = %v, want [%q]", confirmed, relayA)
	}

	set.UnconfirmRelayURL(relayA)
	if confirmed := set.ConfirmedRelays(); len(confirmed) != 0 {
		t.Fatalf("ConfirmedRelays() = %v, want empty after listener failure", confirmed)
	}
	if states := relayStates(set); len(states) != 1 || states[0].Descriptor.APIHTTPSAddr != relayA {
		t.Fatalf("relayStates() = %v, want relay retained as candidate", states)
	}
}

// A relay that keeps failing discovery for longer than a full announce
// validity window is quarantined out of the pool entirely.
func TestRecordDiscoveryFailurePoolBansLongUnhealthyRelay(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-unhealthy.example"
	state := confirmedRelayState(t, relayURL)
	state.unhealthySince = time.Now().UTC().Add(-AnnounceMaxValidity - time.Minute)
	set.relays[relayURL] = state

	backedOff, _, _ := set.RecordDiscoveryFailure(relayURL, 1)
	if !backedOff {
		t.Fatal("long-unhealthy relay discovery failure should back off")
	}
	states := set.AllRelays()
	if len(states) != 1 || !states[0].Banned {
		t.Fatalf("AllRelays() = %+v, want pool-banned relay", states)
	}
	if servesDescriptor(set, relayURL) || routesTo(t, set, relayURL) {
		t.Fatal("pool-banned relay is still served or routed")
	}
}

// Active listener failures never escalate to a pool ban: the relay keeps its
// descriptor and only leaves active route selection.
func TestRecordActiveFailureDoesNotPoolBanLongUnhealthyRelay(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-active-unhealthy.example"
	state := confirmedRelayState(t, relayURL)
	state.unhealthySince = time.Now().UTC().Add(-AnnounceMaxValidity - time.Minute)
	set.relays[relayURL] = state

	backedOff, _, _ := set.RecordActiveFailure(relayURL, 1)
	if !backedOff {
		t.Fatal("active failure at budget should back off")
	}
	states := set.AllRelays()
	if len(states) != 1 || states[0].Banned {
		t.Fatalf("AllRelays() = %+v, want relay without a pool ban", states)
	}
	if !servesDescriptor(set, relayURL) {
		t.Fatal("active failure removed the relay descriptor")
	}
	if routesTo(t, set, relayURL) {
		t.Fatal("active failure did not suppress the relay from route planning")
	}
}

func TestPoolBanRejectsDiscoveryUntilExpiry(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-quarantined.example"
	desc := mustRelayDescriptor(t, relayURL)

	state := newRelayState(relayURL)
	state.Banned = true
	state.suppressActiveUntil = time.Now().UTC().Add(time.Hour)
	set.relays[relayURL] = state

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

	state = set.relays[relayURL]
	state.suppressActiveUntil = time.Now().UTC().Add(-time.Second)
	set.relays[relayURL] = state

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
		if slices.Contains(route.MultiHop(), "https://relay-d.example") {
			t.Fatalf("TCP-incompatible relay appears in multi-hop route %v", route.MultiHop())
		}
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
