package discovery

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func seedHiddenCandidate(t *testing.T, set *RelaySet, descriptor types.RelayDescriptor, relayURL string, now time.Time) {
	t.Helper()
	if err := set.InsertCandidate(descriptor, now); err != nil {
		t.Fatalf("InsertCandidate() error = %v", err)
	}
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == relayURL {
			t.Fatal("candidate relay must stay out of Descriptors() until directly probed")
		}
	}
}

func checkHiddenCandidateVisible(t *testing.T, set *RelaySet, descriptor types.RelayDescriptor, relayURL string, now time.Time) {
	t.Helper()
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		GeneratedAt:     now,
		Relays:          []types.RelayDescriptor{descriptor},
	}, now); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == relayURL {
			return
		}
	}
	t.Fatal("directly probed relay must appear in Descriptors()")
}

func TestInsertCandidateHiddenUntilDirectProbe(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	relayURL := "https://hop-forward.example"
	descriptor := mustSignedDescriptor(t, signing, relayURL, now)
	seedHiddenCandidate(t, set, descriptor, relayURL, now)
	checkHiddenCandidateVisible(t, set, descriptor, relayURL, now)
}

func TestFilterCandidatePoolExcludesCandidatesUntilVerified(t *testing.T) {
	signing := mustSigningIdentity(t)
	other := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	candidate := relayState{
		Descriptor: mustSignedDescriptor(t, signing, "https://candidate.example", now),
		LastSeenAt: now,
	}
	verified := relayState{
		Descriptor: mustSignedDescriptor(t, other, "https://verified-candidate.example", now),
		Trust:      relayVerified,
		LastSeenAt: now,
	}

	pool := filterCandidatePool([]relayState{candidate, verified}, routeState{}, now)
	if len(pool) != 1 || pool[0].Descriptor.APIHTTPSAddr != "https://verified-candidate.example" {
		t.Fatalf("filterCandidatePool() = %v, want only the verified entry", pool)
	}
}

func TestApplyRelayDiscoveryResponseAppliesIdentityCap(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	relays := make([]types.RelayDescriptor, 0, MaxAnnouncedRelaysPerIdentity*2)
	for i := range MaxAnnouncedRelaysPerIdentity * 2 {
		url := fmt.Sprintf("https://gossip-%02d.example", i)
		relays = append(relays, mustSignedDescriptor(t, signing, url, now.Add(time.Duration(i)*time.Second)))
	}
	if _, err := set.ApplyRelayDiscoveryResponse("", types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		GeneratedAt:     now,
		Relays:          relays,
	}, now); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

	ingested := 0
	for _, state := range relayStates(set) {
		if strings.EqualFold(state.Descriptor.Address, signing.Address) {
			ingested++
		}
	}
	if ingested > MaxAnnouncedRelaysPerIdentity {
		t.Fatalf("gossip ingested %d entries for one identity, want <= %d", ingested, MaxAnnouncedRelaysPerIdentity)
	}
}

func buildPromoteTargetRelays(t *testing.T, source types.Identity, gossiped []types.Identity, sourceURL string, now time.Time) []types.RelayDescriptor {
	t.Helper()
	relays := []types.RelayDescriptor{mustSignedDescriptor(t, source, sourceURL, now)}
	for i, identity := range gossiped {
		url := fmt.Sprintf("https://laundered-%d.example", i)
		relays = append(relays, mustSignedDescriptor(t, identity, url, now.Add(time.Duration(i)*time.Second)))
	}
	return relays
}

func checkPromoteTargetInitial(t *testing.T, set *RelaySet, relays []types.RelayDescriptor, sourceURL string, now time.Time) {
	t.Helper()
	if _, err := set.ApplyRelayDiscoveryResponse(sourceURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		GeneratedAt:     now,
		Relays:          relays,
	}, now); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}
	visible := set.Descriptors(types.RelayDescriptor{})
	if len(visible) != 1 || visible[0].APIHTTPSAddr != sourceURL {
		t.Fatalf("Descriptors() = %v, want only the directly probed source", visible)
	}
}

func checkPromoteTargetLaundered(t *testing.T, set *RelaySet, laundered types.RelayDescriptor, launderedURL string, now time.Time) {
	t.Helper()
	if _, err := set.ApplyRelayDiscoveryResponse(launderedURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		GeneratedAt:     now,
		Relays:          []types.RelayDescriptor{laundered},
	}, now); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse(laundered) error = %v", err)
	}
	visible := set.Descriptors(types.RelayDescriptor{})
	if len(visible) != 2 {
		t.Fatalf("len(Descriptors()) = %d, want 2 after the second direct probe", len(visible))
	}
}

func TestApplyRelayDiscoveryResponsePromotesOnlyTarget(t *testing.T) {
	set := NewRelaySet(nil)
	source := mustSigningIdentity(t)
	gossiped := make([]types.Identity, 3)
	for i := range gossiped {
		gossiped[i] = mustSigningIdentity(t)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	sourceURL := "https://probed-source.example"
	relays := buildPromoteTargetRelays(t, source, gossiped, sourceURL, now)
	checkPromoteTargetInitial(t, set, relays, sourceURL, now)
	checkPromoteTargetLaundered(t, set, relays[1], "https://laundered-0.example", now)
}

func applyTargetForRefresh(t *testing.T, set *RelaySet, signing types.Identity, relayURL string, now time.Time) {
	t.Helper()
	descriptor := mustSignedDescriptor(t, signing, relayURL, now)
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		GeneratedAt:     now,
		Relays:          []types.RelayDescriptor{descriptor},
	}, now); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse(target) error = %v", err)
	}
}

func applyVerifiedGossipRefresh(t *testing.T, set *RelaySet, signing types.Identity, relayURL string, now time.Time) {
	t.Helper()
	refreshed := mustSignedDescriptor(t, signing, relayURL, now.Add(time.Second))
	if _, err := set.ApplyRelayDiscoveryResponse("", types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		GeneratedAt:     now.Add(time.Second),
		Relays:          []types.RelayDescriptor{refreshed},
	}, now.Add(time.Second)); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse(gossip) error = %v", err)
	}
}

func checkRefreshKeepsVerified(t *testing.T, set *RelaySet, relayURL string) {
	t.Helper()
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == relayURL {
			return
		}
	}
	t.Fatal("gossip refresh must not demote a verified entry")
}

func TestGossipRefreshKeepsVerifiedTrust(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	relayURL := "https://monotone.example"
	applyTargetForRefresh(t, set, signing, relayURL, now)
	applyVerifiedGossipRefresh(t, set, signing, relayURL, now)
	checkRefreshKeepsVerified(t, set, relayURL)
}

func applyVerifiedForCap(t *testing.T, set *RelaySet, verified types.Identity, now time.Time) {
	t.Helper()
	verifiedDescriptor := mustSignedDescriptor(t, verified, "https://verified.example", now)
	if _, err := set.ApplyRelayDiscoveryResponse("https://verified.example", types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		GeneratedAt:     now,
		Relays:          []types.RelayDescriptor{verifiedDescriptor},
	}, now); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse(verified) error = %v", err)
	}
}

func floodCandidatesForCap(t *testing.T, set *RelaySet, now time.Time) {
	t.Helper()
	identitiesNeeded := MaxAnnouncedRelays / MaxAnnouncedRelaysPerIdentity
	inserted := 0
	for i := 0; i < identitiesNeeded+1 && inserted <= MaxAnnouncedRelays; i++ {
		identity := mustSigningIdentity(t)
		for j := 0; j < MaxAnnouncedRelaysPerIdentity && inserted <= MaxAnnouncedRelays; j++ {
			at := now.Add(time.Duration(inserted) * time.Millisecond)
			url := fmt.Sprintf("https://flood-%05d.example", inserted)
			if err := set.InsertCandidate(mustSignedDescriptor(t, identity, url, at), at); err != nil {
				t.Fatalf("InsertCandidate(%d) error = %v", inserted, err)
			}
			inserted++
		}
	}
}

func checkVerifiedSurvivesCap(t *testing.T, set *RelaySet) {
	t.Helper()
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == "https://verified.example" {
			if got := len(relayStates(set)); got > MaxAnnouncedRelays {
				t.Fatalf("pool size = %d, want <= %d", got, MaxAnnouncedRelays)
			}
			return
		}
	}
	t.Fatal("verified relay must survive a candidate flood filling the global cap")
}

func TestGlobalCapEvictsCandidatesBeforeVerified(t *testing.T) {
	set := NewRelaySet(nil)
	verified := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	applyVerifiedForCap(t, set, verified, now)
	floodCandidatesForCap(t, set, now)
	checkVerifiedSurvivesCap(t, set)
}

func applyTakeoverAnnounceFirst(t *testing.T, set *RelaySet, first types.Identity, relayURL string, now time.Time) {
	t.Helper()
	firstDescriptor := mustSignedDescriptor(t, first, relayURL, now)
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		GeneratedAt:     now,
		Relays:          []types.RelayDescriptor{firstDescriptor},
	}, now); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}
}

func applyTakeoverAnnounceAttacker(t *testing.T, set *RelaySet, attacker types.Identity, relayURL string, now time.Time) {
	t.Helper()
	later := now.Add(DiscoveryDescriptorTTL + time.Minute)
	if err := set.InsertCandidate(mustSignedDescriptor(t, attacker, relayURL, later), later); err != nil {
		t.Fatalf("InsertCandidate() error = %v", err)
	}
}

func checkTakeoverAnnounceUntrusted(t *testing.T, set *RelaySet, relayURL string) {
	t.Helper()
	state, ok := set.relays[relayURL]
	if !ok {
		t.Fatal("replacement descriptor must be stored")
	}
	if state.Trust != relayCandidate {
		t.Fatalf("trust = %v, want relayCandidate after a cross-identity takeover", state.Trust)
	}
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == relayURL {
			t.Fatal("replacement identity must not inherit visibility from the previous identity")
		}
	}
}

func TestTrustDoesNotTransferAcrossIdentityTakeover(t *testing.T) {
	set := NewRelaySet(nil)
	first := mustSigningIdentity(t)
	attacker := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	relayURL := "https://takeover.example"
	applyTakeoverAnnounceFirst(t, set, first, relayURL, now)
	applyTakeoverAnnounceAttacker(t, set, attacker, relayURL, now)
	checkTakeoverAnnounceUntrusted(t, set, relayURL)
}

func TestBootstrapCandidateDescriptorStaysHidden(t *testing.T) {
	bootstrapURL := "https://bootstrap.example"
	set := NewRelaySet([]string{bootstrapURL})
	attacker := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	if err := set.InsertCandidate(mustSignedDescriptor(t, attacker, bootstrapURL, now), now); err != nil {
		t.Fatalf("InsertCandidate() error = %v", err)
	}
	state, ok := set.relays[bootstrapURL]
	if !ok || !state.Bootstrap {
		t.Fatal("bootstrap pin must survive a candidate insert at the same URL")
	}
	if state.Trust != relayCandidate {
		t.Fatalf("trust = %v, want relayCandidate for a squatted bootstrap descriptor", state.Trust)
	}
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == bootstrapURL {
			t.Fatal("candidate descriptor squatted on a bootstrap URL must stay out of Descriptors()")
		}
	}
	if pool := filterCandidatePool([]relayState{state}, routeState{}, now); len(pool) != 0 {
		t.Fatalf("filterCandidatePool() = %v, want the squatted bootstrap excluded", pool)
	}

	urlOnly := newRelayState("https://bootstrap-fallback.example")
	urlOnly.Bootstrap = true
	if pool := filterCandidatePool([]relayState{urlOnly}, routeState{}, now); len(pool) != 1 {
		t.Fatal("URL-only bootstrap entry must remain a single-hop fallback candidate")
	}
}
