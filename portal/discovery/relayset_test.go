package discovery

import (
	"errors"
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
	routes := set.SelectRelays(routeState{LocalAddress: "client"})
	for _, route := range routes {
		if route.RelayURL == relayURL {
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

	// Ingest a descriptor that was valid when it arrived but has since
	// expired: sign and apply it in the past, then read in the present.
	relayURL := "https://relay-stale.example"
	issuedAt := time.Now().UTC().Truncate(time.Microsecond).Add(-DiscoveryDescriptorTTL - time.Minute)
	desc := mustSignedDescriptor(t, mustSigningIdentity(t), relayURL, issuedAt)
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
	}, issuedAt.Add(time.Second)); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

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
		ProtocolVersion: types.DiscoveryVersion + "-other",
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

	// The protocol version matches, so the only error the response can
	// produce is the missing-target one.
	hinted := mustRelayDescriptor(t, "https://relay-hinted.example")
	changed, err := set.ApplyRelayDiscoveryResponse("https://relay-source.example", types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
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

// EnsureRelayURL must persist a clean candidate for an unknown URL without
// clobbering existing state: suppression recorded before the call survives,
// so explicit relays keep durable failure state across intent refreshes.
func TestRelaySetEnsureRelayURLPreservesExistingState(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)
	set := NewRelaySet(nil)
	mustApplyAuthoritative(t, set, mustRelayDescriptor(t, relayA))

	if _, _, failures := set.RecordActiveFailure(relayA, 1); failures != 1 {
		t.Fatalf("RecordActiveFailure() failures = %d, want 1", failures)
	}

	set.EnsureRelayURL(relayA)
	set.EnsureRelayURL(relayB)

	if !set.IsSuppressed(relayA, time.Now().UTC()) {
		t.Fatal("EnsureRelayURL() cleared relay A suppression")
	}
	if set.IsSuppressed(relayB, time.Now().UTC()) {
		t.Fatal("EnsureRelayURL() must not suppress an unknown relay")
	}
}

func TestSelectRelaysSkipsExplicitRelayWithoutRequiredTransport(t *testing.T) {
	const relayURL = "https://relay-udp-disabled.example"
	set := NewRelaySet(nil)
	state := confirmedRelayState(t, relayURL)
	state.Descriptor.SupportsUDP = false
	set.relays[relayURL] = state

	routes := set.SelectRelays(routeState{
		ExplicitRelayURLs: []string{relayURL},
		RequireUDP:        true,
	})
	if len(routes) != 0 {
		t.Fatalf("SelectRelays() = %v, want no UDP-incompatible explicit route", routes)
	}
}

func TestSelectRelaysIncludesExplicitRelayMissingFromSet(t *testing.T) {
	const relayURL = "https://relay-explicit.example"

	routes := NewRelaySet(nil).SelectRelays(routeState{
		ExplicitRelayURLs: []string{relayURL},
	})
	if len(routes) != 1 {
		t.Fatalf("len(routes) = %d, want 1", len(routes))
	}
	route := routes[0]
	if !route.Explicit {
		t.Fatal("route.Explicit = false, want true")
	}
	if got := route.RelayURL; got != relayURL {
		t.Fatalf("route.RelayURL = %q, want %q", got, relayURL)
	}
}

func TestProtocolMismatchKeepsOlderRelayVisibleWithoutRouting(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-old.example"
	desc := mustRelayDescriptor(t, relayURL)
	_, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion + "-older",
		Relays:          []types.RelayDescriptor{desc},
	}, time.Now().UTC())
	if err == nil {
		t.Fatal("ApplyRelayDiscoveryResponse() should keep reporting the protocol mismatch")
	}
	if !errors.Is(err, ErrProtocolMismatch) {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v, want ErrProtocolMismatch", err)
	}

	known := set.KnownIncompatibleRelays()
	if len(known) != 1 || known[0].URL != relayURL || known[0].ProtocolVersion != types.DiscoveryVersion+"-older" {
		t.Fatalf("KnownIncompatibleRelays() = %+v, want one entry for %q", known, relayURL)
	}
	if known[0].LastSeenAt.IsZero() {
		t.Fatal("KnownIncompatibleRelays() entry should carry LastSeenAt")
	}

	if servesDescriptor(set, relayURL) {
		t.Fatal("incompatible relay must not be served as a routable descriptor")
	}
	if routesTo(t, set, relayURL) {
		t.Fatal("incompatible relay must not be selected for routes")
	}
	for _, state := range relayStates(set) {
		if state.Descriptor.APIHTTPSAddr == relayURL && state.Trust == RelayVerified {
			t.Fatal("incompatible relay must not become a verified descriptor")
		}
	}
}

func TestKnownIncompatibleRelaysExpireAfterRetention(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-old.example"
	desc := mustRelayDescriptor(t, relayURL)
	observedAt := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion + "-older",
		Relays:          []types.RelayDescriptor{desc},
	}, observedAt); err == nil {
		t.Fatal("expected protocol mismatch error")
	}
	if known := set.knownIncompatibleRelaysAt(observedAt); len(known) != 1 {
		t.Fatalf("knownIncompatibleRelaysAt(fresh) = %+v, want one entry", known)
	}
	if known := set.knownIncompatibleRelaysAt(observedAt.Add(AnnounceMaxValidity + time.Minute)); len(known) != 0 {
		t.Fatalf("knownIncompatibleRelaysAt(stale) = %+v, want empty", known)
	}
}

func TestCompatibleAuthoritativeDiscoveryClearsIncompatibleRelay(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-upgraded.example"
	desc := mustRelayDescriptor(t, relayURL)
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion + "-older",
		Relays:          []types.RelayDescriptor{desc},
	}, time.Now().UTC()); err == nil {
		t.Fatal("expected protocol mismatch error")
	}
	if known := set.KnownIncompatibleRelays(); len(known) != 1 {
		t.Fatalf("KnownIncompatibleRelays() = %+v, want one entry before upgrade", known)
	}

	mustApplyAuthoritative(t, set, desc)
	if known := set.KnownIncompatibleRelays(); len(known) != 0 {
		t.Fatalf("KnownIncompatibleRelays() = %+v, want empty after compatible discovery", known)
	}
}

func TestKnownIncompatibleRelaysSuppressBannedRelay(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-old.example"
	desc := mustRelayDescriptor(t, relayURL)
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion + "-older",
		Relays:          []types.RelayDescriptor{desc},
	}, time.Now().UTC()); err == nil {
		t.Fatal("expected protocol mismatch error")
	}
	if known := set.KnownIncompatibleRelays(); len(known) != 1 {
		t.Fatalf("KnownIncompatibleRelays() = %+v, want one entry before ban", known)
	}

	set.BanRelayURL(relayURL)
	if known := set.KnownIncompatibleRelays(); len(known) != 0 {
		t.Fatalf("KnownIncompatibleRelays() = %+v, want empty after local ban", known)
	}
}

func TestProtocolMismatchOutranksMissingTarget(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-old.example"
	_, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion + "-older",
		Relays:          nil,
	}, time.Now().UTC())
	if !errors.Is(err, ErrProtocolMismatch) {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v, want ErrProtocolMismatch even without a target descriptor", err)
	}
	if known := set.KnownIncompatibleRelays(); len(known) != 1 || known[0].URL != relayURL {
		t.Fatalf("KnownIncompatibleRelays() = %+v, want one entry for %q", known, relayURL)
	}
}

func TestApplyRelayDiscoveryResponseRecordsTargetReleaseVersion(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-release.example"
	desc := mustRelayDescriptor(t, relayURL)
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
		ReleaseVersion:  "v2.6.0",
	}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

	var state *RelayState
	for _, candidate := range relayStates(set) {
		if candidate.Descriptor.APIHTTPSAddr == relayURL {
			state = &candidate
			break
		}
	}
	if state == nil {
		t.Fatalf("relayStates() has no entry for %q", relayURL)
	}
	if state.Trust != RelayVerified {
		t.Fatalf("RelayState.Trust = %d, want RelayVerified after the authoritative poll", state.Trust)
	}

	versions := set.KnownRelayReleaseVersions()
	if len(versions) != 1 || versions[relayURL] != "v2.6.0" {
		t.Fatalf("KnownRelayReleaseVersions() = %+v, want {%q: %q}", versions, relayURL, "v2.6.0")
	}
}

func TestApplyRelayDiscoveryResponseIgnoresReleaseVersionFromGossip(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-gossip.example"
	desc := mustRelayDescriptor(t, relayURL)
	if _, err := set.ApplyRelayDiscoveryResponse("", types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
		ReleaseVersion:  "v2.6.0",
	}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

	if versions := set.KnownRelayReleaseVersions(); len(versions) != 0 {
		t.Fatalf("KnownRelayReleaseVersions() = %+v, want no entries from a gossip batch", versions)
	}
}

func TestApplyRelayDiscoveryResponseRetainsReleaseAcrossProtocolMismatch(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-mismatch-release.example"
	_, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion + "-older",
		ReleaseVersion:  "v2.6.0",
	}, time.Now().UTC())
	if !errors.Is(err, ErrProtocolMismatch) {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v, want ErrProtocolMismatch", err)
	}

	// #512: the protocol label is only a fallback for when no release is
	// known. A directly observed release must survive the mismatch.
	if versions := set.KnownRelayReleaseVersions(); len(versions) != 1 || versions[relayURL] != "v2.6.0" {
		t.Fatalf("KnownRelayReleaseVersions() = %+v, want {%q: %q} despite ErrProtocolMismatch", versions, relayURL, "v2.6.0")
	}
}

func TestKnownRelayReleaseVersionsExpireWithoutFreshDirectPoll(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-expire.example"
	signing := mustSigningIdentity(t)
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	desc := mustSignedDescriptor(t, signing, relayURL, t0)
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
		ReleaseVersion:  "v2.6.0",
	}, t0); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

	// A gossip batch re-lists the same relay and refreshes its RelayState
	// freshness, but it is not a direct contact and carries no release of
	// its own: it must not extend the release observation's clock.
	gossipAt := t0.Add(2 * time.Hour)
	gossipDesc := mustSignedDescriptor(t, signing, relayURL, gossipAt)
	if _, err := set.ApplyRelayDiscoveryResponse("", types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{gossipDesc},
	}, gossipAt); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() gossip error = %v", err)
	}

	if versions := set.knownRelayReleaseVersionsAt(t0.Add(AnnounceMaxValidity)); versions[relayURL] != "v2.6.0" {
		t.Fatalf("knownRelayReleaseVersionsAt(validity boundary) = %+v, want %q still fresh on its direct-observation clock", versions, "v2.6.0")
	}
	if versions := set.knownRelayReleaseVersionsAt(t0.Add(AnnounceMaxValidity).Add(time.Second)); len(versions) != 0 {
		t.Fatalf("knownRelayReleaseVersionsAt(validity+1s) = %+v, want empty: gossip must not extend the direct clock", versions)
	}
}

func TestApplyRelayDiscoveryResponseDropsReleaseWhenPeerStopsReporting(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-stopped.example"
	signing := mustSigningIdentity(t)
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	desc := mustSignedDescriptor(t, signing, relayURL, t0)
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
		ReleaseVersion:  "v2.6.0",
	}, t0); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}
	if versions := set.KnownRelayReleaseVersions(); versions[relayURL] != "v2.6.0" {
		t.Fatalf("KnownRelayReleaseVersions() = %+v, want {%q: %q}", versions, relayURL, "v2.6.0")
	}

	// The peer later answers without a release (an older build that stopped
	// reporting): the latest direct observation wins.
	t1 := t0.Add(time.Minute)
	freshDesc := mustSignedDescriptor(t, signing, relayURL, t1)
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{freshDesc},
	}, t1); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}
	if versions := set.KnownRelayReleaseVersions(); len(versions) != 0 {
		t.Fatalf("KnownRelayReleaseVersions() = %+v, want empty after the peer stopped reporting its release", versions)
	}
}

// A local ban drops the release observation outright rather than hiding it:
// the projection goes empty on ban, stays empty after AllowRelayURL, and
// returns only after a fresh direct poll.
func TestBanRelayURLDropsReleaseObservation(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-banned-release.example"
	desc := mustRelayDescriptor(t, relayURL)
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
		ReleaseVersion:  "v2.6.0",
	}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}
	if versions := set.KnownRelayReleaseVersions(); len(versions) != 1 {
		t.Fatalf("KnownRelayReleaseVersions() = %+v, want one entry before ban", versions)
	}

	set.BanRelayURL(relayURL)
	if versions := set.KnownRelayReleaseVersions(); len(versions) != 0 {
		t.Fatalf("KnownRelayReleaseVersions() = %+v, want empty after local ban", versions)
	}

	// The observation was dropped, not hidden: unbanning must not resurface
	// the stale release; it returns only after a fresh direct poll.
	set.AllowRelayURL(relayURL)
	if versions := set.KnownRelayReleaseVersions(); len(versions) != 0 {
		t.Fatalf("KnownRelayReleaseVersions() = %+v, want still empty after unban: a local ban drops the observation", versions)
	}
}

// Storage bound: expired release observations are deleted from the map as
// fresh direct polls arrive (not merely hidden from the projection), so the
// map cannot grow without bound as polled relay URLs churn.
func TestRecordReleaseObservationPrunesExpiredEntries(t *testing.T) {
	set := NewRelaySet(nil)

	signing := mustSigningIdentity(t)
	relayA := "https://relay-a-release.example"
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	descA := mustSignedDescriptor(t, signing, relayA, t0)
	if _, err := set.ApplyRelayDiscoveryResponse(relayA, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{descA},
		ReleaseVersion:  "v2.6.0",
	}, t0); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

	relayB := "https://relay-b-release.example"
	t1 := t0.Add(AnnounceMaxValidity).Add(time.Hour)
	descB := mustSignedDescriptor(t, signing, relayB, t1)
	if _, err := set.ApplyRelayDiscoveryResponse(relayB, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{descB},
		ReleaseVersion:  "v2.6.1",
	}, t1); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

	if len(set.releaseVersions) != 1 {
		t.Fatalf("len(set.releaseVersions) = %d, want 1 after the expired observation is pruned", len(set.releaseVersions))
	}
	if observation, ok := set.releaseVersions[relayB]; !ok || observation.releaseVersion != "v2.6.1" {
		t.Fatalf("set.releaseVersions[%q] = (%+v, %v), want only the fresh observation", relayB, observation, ok)
	}
}
