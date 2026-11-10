package discovery

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func relayStates(set *RelaySet) []relayState {
	states := set.currentRelayStates(time.Now().UTC())
	out := make([]relayState, 0, len(states))
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

func verifiedRelayState(t *testing.T, relayURL string) relayState {
	t.Helper()
	return relayState{
		Descriptor: mustRelayDescriptor(t, relayURL),
		Trust:      relayVerified,
		LastSeenAt: time.Now().UTC(),
	}
}

func bootstrapRelayState(relayURL string) relayState {
	state := newRelayState(relayURL)
	state.Bootstrap = true
	return state
}

func mustApplyAuthoritative(t *testing.T, set *RelaySet, desc types.RelayDescriptor) {
	t.Helper()
	if _, err := set.ApplyRelayDiscoveryResponse(desc.APIHTTPSAddr, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse(%q) error = %v", desc.APIHTTPSAddr, err)
	}
}

func servesDescriptor(set *RelaySet, relayURL string) bool {
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == relayURL {
			return true
		}
	}
	return false
}

func routesTo(t *testing.T, set *RelaySet, relayURL string) bool {
	t.Helper()
	routes := set.selectRelays(routeState{LocalAddress: "client"})
	for _, route := range routes {
		if route == relayURL {
			return true
		}
	}
	return false
}

func TestDescriptorsDropsExpiredSignedRelayDescriptor(t *testing.T) {
	set := NewRelaySet(nil)

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
	if states[0].Trust != relayCandidate {
		t.Fatal("a gossip hint must remain an unverified candidate")
	}
}

func TestApplyRelayDiscoveryResponseCollectsHintsWhenTargetDescriptorIsMissing(t *testing.T) {
	set := NewRelaySet(nil)

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
	if states[0].Trust != relayCandidate {
		t.Fatal("a missing target must not verify a hinted relay")
	}
}

func seedDiscoveryFailureSet(t *testing.T, relayA string, relayB string) (*RelaySet, types.RelayDescriptor) {
	t.Helper()
	set := NewRelaySet(nil)
	descA := mustRelayDescriptor(t, relayA)
	mustApplyAuthoritative(t, set, descA)
	mustApplyAuthoritative(t, set, mustRelayDescriptor(t, relayB))
	return set, descA
}

func checkTransientDiscoveryFailure(t *testing.T, set *RelaySet, relayA string, budget int) {
	t.Helper()
	set.RecordDiscoveryFailure(relayA, budget)
	if !servesDescriptor(set, relayA) || !routesTo(t, set, relayA) {
		t.Fatal("a transient discovery failure removed an otherwise usable relay")
	}
}

func checkExhaustedDiscoveryFailure(t *testing.T, set *RelaySet, relayA string, relayB string, budget int) {
	t.Helper()
	for range budget - 1 {
		set.RecordDiscoveryFailure(relayA, budget)
	}
	if servesDescriptor(set, relayA) || routesTo(t, set, relayA) {
		t.Fatal("relay with exhausted discovery budget is still served or routed")
	}
	if !servesDescriptor(set, relayB) || !routesTo(t, set, relayB) {
		t.Fatal("healthy relay was affected by another relay's discovery failures")
	}
}

func checkHintRevivesNothing(t *testing.T, set *RelaySet, descA types.RelayDescriptor, relayA string) {
	t.Helper()
	if _, err := set.ApplyRelayDiscoveryResponse("", types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{descA},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse(hint) error = %v", err)
	}
	if servesDescriptor(set, relayA) || routesTo(t, set, relayA) {
		t.Fatal("a gossip hint revived a dead relay; only authoritative contact may")
	}
}

func checkAuthoritativeRevivesRelay(t *testing.T, set *RelaySet, descA types.RelayDescriptor, relayA string) {
	t.Helper()
	mustApplyAuthoritative(t, set, descA)
	if !servesDescriptor(set, relayA) || !routesTo(t, set, relayA) {
		t.Fatal("authoritative discovery success did not revive the relay")
	}
}

func TestDiscoveryFailureLifecycle(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
		budget = 3
	)
	set, descA := seedDiscoveryFailureSet(t, relayA, relayB)
	checkTransientDiscoveryFailure(t, set, relayA, budget)
	checkExhaustedDiscoveryFailure(t, set, relayA, relayB, budget)
	checkHintRevivesNothing(t, set, descA, relayA)
	checkAuthoritativeRevivesRelay(t, set, descA, relayA)
}

func checkActiveFailureBackoff(t *testing.T, set *RelaySet, relayA string) {
	t.Helper()
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
	if states := set.currentRelayStates(time.Now().UTC()); len(states) != 1 || states[0].Banned {
		t.Fatalf("relay states = %+v, want relay retained without a ban", states)
	}
}

func checkActiveFailureUnforgiven(t *testing.T, set *RelaySet, desc types.RelayDescriptor, relayA string) {
	t.Helper()
	mustApplyAuthoritative(t, set, desc)
	if routesTo(t, set, relayA) {
		t.Fatal("discovery success forgave active listener failures")
	}
}

func checkOperatorRestoresRelay(t *testing.T, set *RelaySet, relayA string) {
	t.Helper()
	set.AllowRelayURL(relayA)
	if !routesTo(t, set, relayA) {
		t.Fatal("operator re-add did not restore the relay to route planning")
	}
}

func TestActiveFailureLifecycle(t *testing.T) {
	const relayA = "https://relay-a.example"
	set := NewRelaySet(nil)
	desc := mustRelayDescriptor(t, relayA)
	mustApplyAuthoritative(t, set, desc)
	checkActiveFailureBackoff(t, set, relayA)
	checkActiveFailureUnforgiven(t, set, desc, relayA)
	checkOperatorRestoresRelay(t, set, relayA)
}

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
	state := verifiedRelayState(t, relayURL)
	state.Descriptor.SupportsUDP = false
	set.relays[relayURL] = state

	routes := set.selectRelays(routeState{
		ExplicitRelayURLs: []string{relayURL},
		RequireUDP:        true,
	})
	if len(routes) != 0 {
		t.Fatalf("selectRelays() = %v, want no UDP-incompatible explicit route", routes)
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
		if state.Descriptor.APIHTTPSAddr == relayURL && state.Trust == relayVerified {
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

func applyTargetReleaseResponse(t *testing.T, set *RelaySet, relayURL string, desc types.RelayDescriptor) {
	t.Helper()
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
		ReleaseVersion:  "v2.6.0",
	}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}
}

func checkTargetReleaseRecorded(t *testing.T, set *RelaySet, relayURL string) {
	t.Helper()
	var state *relayState
	for _, candidate := range relayStates(set) {
		if candidate.Descriptor.APIHTTPSAddr == relayURL {
			state = &candidate
			break
		}
	}
	if state == nil {
		t.Fatalf("relayStates() has no entry for %q", relayURL)
	}
	if state.Trust != relayVerified {
		t.Fatalf("relayState.Trust = %d, want relayVerified after the authoritative poll", state.Trust)
	}
	if versions := set.KnownRelayReleaseVersions(); len(versions) != 1 || versions[relayURL] != "v2.6.0" {
		t.Fatalf("KnownRelayReleaseVersions() = %+v, want {%q: %q}", versions, relayURL, "v2.6.0")
	}
}

func TestApplyRelayDiscoveryResponseRecordsTargetReleaseVersion(t *testing.T) {
	set := NewRelaySet(nil)
	relayURL := "https://relay-release.example"
	desc := mustRelayDescriptor(t, relayURL)
	applyTargetReleaseResponse(t, set, relayURL, desc)
	checkTargetReleaseRecorded(t, set, relayURL)
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

func seedDirectReleasePoll(t *testing.T, set *RelaySet, signing types.Identity, relayURL string, t0 time.Time) {
	t.Helper()
	desc := mustSignedDescriptor(t, signing, relayURL, t0)
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
		ReleaseVersion:  "v2.6.0",
	}, t0); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}
}

func applyGossipReleaseRefresh(t *testing.T, set *RelaySet, signing types.Identity, relayURL string, t0 time.Time) {
	t.Helper()
	gossipAt := t0.Add(2 * time.Hour)
	gossipDesc := mustSignedDescriptor(t, signing, relayURL, gossipAt)
	if _, err := set.ApplyRelayDiscoveryResponse("", types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{gossipDesc},
	}, gossipAt); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() gossip error = %v", err)
	}
}

func checkReleaseVersionExpiry(t *testing.T, set *RelaySet, relayURL string, t0 time.Time) {
	t.Helper()
	if versions := set.knownRelayReleaseVersionsAt(t0.Add(AnnounceMaxValidity)); versions[relayURL] != "v2.6.0" {
		t.Fatalf("knownRelayReleaseVersionsAt(validity boundary) = %+v, want %q still fresh on its direct-observation clock", versions, "v2.6.0")
	}
	if versions := set.knownRelayReleaseVersionsAt(t0.Add(AnnounceMaxValidity).Add(time.Second)); len(versions) != 0 {
		t.Fatalf("knownRelayReleaseVersionsAt(validity+1s) = %+v, want empty: gossip must not extend the direct clock", versions)
	}
}

func TestKnownRelayReleaseVersionsExpireWithoutFreshDirectPoll(t *testing.T) {
	set := NewRelaySet(nil)
	relayURL := "https://relay-expire.example"
	signing := mustSigningIdentity(t)
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	seedDirectReleasePoll(t, set, signing, relayURL, t0)
	applyGossipReleaseRefresh(t, set, signing, relayURL, t0)
	checkReleaseVersionExpiry(t, set, relayURL, t0)
}

func TestApplyRelayDiscoveryResponseCollectionLimit(t *testing.T) {
	t.Parallel()
	for _, count := range []int{MaxAnnouncedRelays + 1, MaxAnnouncedRelays + 2} {
		set := NewRelaySet(nil)
		changed, err := set.ApplyRelayDiscoveryResponse("", types.DiscoveryResponse{
			Relays: make([]types.RelayDescriptor, count),
		}, time.Now())
		if (err != nil) != (count > MaxAnnouncedRelays+1) || changed {
			t.Fatalf("collection size %d: changed=%v, error=%v", count, changed, err)
		}
	}
}

func TestDiscoveryObservationMapsStayBounded(t *testing.T) {
	t.Parallel()

	set := NewRelaySet(nil)
	now := time.Now().UTC()
	set.mu.Lock()
	for i := range MaxAnnouncedRelays + 1 {
		relayURL := fmt.Sprintf("https://observed-%d.example", i)
		observedAt := now.Add(time.Duration(i) * time.Millisecond)
		set.recordReleaseObservationLocked(relayURL, "v2.6.0", observedAt)
		set.recordIncompatibleRelayLocked(relayURL, "older", observedAt)
	}
	set.mu.Unlock()

	if len(set.releaseVersions) != MaxAnnouncedRelays || len(set.incompatible) != MaxAnnouncedRelays {
		t.Fatalf("retained observations = (releases %d, incompatible %d), want %d each",
			len(set.releaseVersions), len(set.incompatible), MaxAnnouncedRelays)
	}
	if _, ok := set.releaseVersions["https://observed-0.example"]; ok {
		t.Fatal("oldest release observation was not evicted")
	}
	if _, ok := set.incompatible["https://observed-0.example"]; ok {
		t.Fatal("oldest incompatible observation was not evicted")
	}
}

func TestDiscoveryObservationLabelsStayBounded(t *testing.T) {
	t.Parallel()

	set := NewRelaySet(nil)
	relayURL := "https://peer.example"
	large := strings.Repeat("v", types.MaxDiscoveryVersionBytes+1)
	set.mu.Lock()
	set.recordReleaseObservationLocked(relayURL, large, time.Now().UTC())
	set.recordIncompatibleRelayLocked(relayURL, large, time.Now().UTC())
	set.mu.Unlock()

	if len(set.releaseVersions) != 0 {
		t.Fatalf("retained %d oversized release labels", len(set.releaseVersions))
	}
	if entry, ok := set.incompatible[relayURL]; !ok || entry.ProtocolVersion != "" {
		t.Fatalf("oversized protocol label stored: %+v (exists: %t)", entry, ok)
	}
}
