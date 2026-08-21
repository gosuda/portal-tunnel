package discovery

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func mustSigningIdentity(t *testing.T) types.Identity {
	t.Helper()
	signingIdentity, err := identity.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("identity.ResolveSecp256k1Identity() error = %v", err)
	}
	return signingIdentity
}

func mustUnsignedDescriptor(t *testing.T, signing types.Identity, relayURL string) types.RelayDescriptor {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	return types.RelayDescriptor{
		Address:      signing.Address,
		Version:      types.DiscoveryVersion,
		IssuedAt:     now,
		ExpiresAt:    now.Add(time.Hour),
		APIHTTPSAddr: relayURL,
	}
}

func mustSignedDescriptor(t *testing.T, signing types.Identity, relayURL string, issuedAt time.Time) types.RelayDescriptor {
	t.Helper()
	authority, err := identity.NewLocalAuthority(signing)
	if err != nil {
		t.Fatalf("identity.NewLocalAuthority() error = %v", err)
	}
	signed, err := auth.SignRelayDescriptor(types.RelayDescriptor{
		Address:      signing.Address,
		Version:      types.DiscoveryVersion,
		IssuedAt:     issuedAt,
		ExpiresAt:    issuedAt.Add(DiscoveryDescriptorTTL),
		APIHTTPSAddr: relayURL,
	}, authority)
	if err != nil {
		t.Fatalf("SignRelayDescriptor() error = %v", err)
	}
	return signed
}

func TestInsertCandidateAcceptsValidDescriptor(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	desc := mustSignedDescriptor(t, signing, "https://relay-ann.example", now)
	if err := set.InsertCandidate(desc, now); err != nil {
		t.Fatalf("InsertCandidate() error = %v", err)
	}
	if got := relayStates(set); len(got) != 1 {
		t.Fatalf("len(relayStates()) = %d, want 1", len(got))
	}
}

func TestInsertCandidateRejectsUnsigned(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	desc := mustUnsignedDescriptor(t, signing, "https://relay-unsigned.example")
	err := set.InsertCandidate(desc, now)
	if err == nil || err.Error() != "relay descriptor is not signed" {
		t.Fatalf("InsertCandidate() error = %v, want unsigned descriptor error", err)
	}
}

func TestInsertCandidateRejectsExpired(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	desc := mustSignedDescriptor(t, signing, "https://relay-expired.example", now.Add(-DiscoveryDescriptorTTL-time.Second))
	err := set.InsertCandidate(desc, now)
	if err == nil || err.Error() != "relay descriptor already expired" {
		t.Fatalf("InsertCandidate() error = %v, want expired descriptor error", err)
	}
}

func TestInsertCandidateIgnoresSupersededRollback(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	relayURL := "https://relay-roll.example"
	newer := mustSignedDescriptor(t, signing, relayURL, now)
	if err := set.InsertCandidate(newer, now); err != nil {
		t.Fatalf("seed insert error = %v", err)
	}
	older := mustSignedDescriptor(t, signing, relayURL, now.Add(-time.Minute))
	if err := set.InsertCandidate(older, now); err != nil {
		t.Fatalf("superseded insert error = %v", err)
	}

	states := relayStates(set)
	if len(states) != 1 {
		t.Fatalf("len(relayStates()) = %d, want 1", len(states))
	}
	if got := states[0].Descriptor.IssuedAt; !got.Equal(newer.IssuedAt) {
		t.Fatalf("stored issued_at = %v, want %v", got, newer.IssuedAt)
	}
}

func TestInsertCandidateRejectsRollbackAcrossRelayURL(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	newer := mustSignedDescriptor(t, signing, "https://relay-roll-new.example", now)
	if err := set.InsertCandidate(newer, now); err != nil {
		t.Fatalf("seed insert error = %v", err)
	}
	older := mustSignedDescriptor(t, signing, "https://relay-roll-old.example", now.Add(-time.Minute))
	if err := set.InsertCandidate(older, now); err == nil {
		t.Fatal("expected rollback reject")
	}
}

func TestInsertCandidateBlocksCrossIdentityTakeover(t *testing.T) {
	set := NewRelaySet(nil)
	owner := mustSigningIdentity(t)
	attacker := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	relayURL := "https://relay-takeover.example"

	ownerDesc := mustSignedDescriptor(t, owner, relayURL, now)
	if err := set.InsertCandidate(ownerDesc, now); err != nil {
		t.Fatalf("owner insert error = %v", err)
	}

	attackerDesc := mustSignedDescriptor(t, attacker, relayURL, now.Add(time.Second))
	if err := set.InsertCandidate(attackerDesc, now); err == nil {
		t.Fatal("expected takeover reject")
	}

	states := relayStates(set)
	if len(states) != 1 {
		t.Fatalf("len(relayStates()) = %d, want 1", len(states))
	}
	if got := states[0].Descriptor.Address; got != owner.Address {
		t.Fatalf("retained address = %q, want %q", got, owner.Address)
	}
}

func TestAnnounceLimiterAllowsBurstThenThrottles(t *testing.T) {
	limiter := NewAnnounceLimiter(60, 5) // 1/sec sustained, burst 5
	for i := range 5 {
		if !limiter.Allow("10.0.0.1") {
			t.Fatalf("burst[%d] should be allowed", i)
		}
	}
	if limiter.Allow("10.0.0.1") {
		t.Fatal("burst budget should be exhausted")
	}
	if !limiter.Allow("10.0.0.2") {
		t.Fatal("different IP should have its own bucket")
	}
}

func TestInsertCandidateCapsFloodPerSigningIdentity(t *testing.T) {
	set := NewRelaySet(nil)
	legit := mustSigningIdentity(t)
	attacker := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	if err := set.InsertCandidate(mustSignedDescriptor(t, legit, "https://legit.example", now), now); err != nil {
		t.Fatalf("legit insert error = %v", err)
	}
	// Flood the pool the way the reported abuse does: one signing identity
	// announcing MaxAnnouncedRelays distinct URLs with fresh IssuedAt.
	for i := range MaxAnnouncedRelays {
		at := now.Add(time.Duration(i) * time.Second)
		url := fmt.Sprintf("https://attacker-%04d.example", i)
		if err := set.InsertCandidate(mustSignedDescriptor(t, attacker, url, at), at); err != nil {
			t.Fatalf("flood insert %d error = %v", i, err)
		}
	}

	var legitEntries, attackerEntries int
	for _, state := range relayStates(set) {
		switch strings.ToLower(state.Descriptor.Address) {
		case strings.ToLower(legit.Address):
			legitEntries++
		case strings.ToLower(attacker.Address):
			attackerEntries++
		}
	}
	if legitEntries != 1 {
		t.Fatalf("legit entries = %d, want 1 (identity flood must not displace other relays)", legitEntries)
	}
	if attackerEntries != MaxAnnouncedRelaysPerIdentity {
		t.Fatalf("attacker entries = %d, want %d", attackerEntries, MaxAnnouncedRelaysPerIdentity)
	}
}

func TestInsertCandidatePerIdentityCapKeepsConfirmedEntries(t *testing.T) {
	set := NewRelaySet(nil)
	owner := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	confirmedURL := "https://confirmed.example"
	set.relays[confirmedURL] = RelayState{
		Descriptor: mustSignedDescriptor(t, owner, confirmedURL, now),
		Confirmed:  true,
		LastSeenAt: now,
	}
	for i := range MaxAnnouncedRelaysPerIdentity * 2 {
		at := now.Add(time.Duration(i) * time.Second)
		url := fmt.Sprintf("https://owner-%02d.example", i)
		if err := set.InsertCandidate(mustSignedDescriptor(t, owner, url, at), at); err != nil {
			t.Fatalf("insert %d error = %v", i, err)
		}
	}

	confirmed, ok := set.relays[confirmedURL]
	if !ok || !confirmed.Confirmed {
		t.Fatal("listener-confirmed entry must survive the identity cap")
	}
}

func mustSignedOverlayDescriptor(t *testing.T, signing types.Identity, relayURL string, issuedAt time.Time) types.RelayDescriptor {
	t.Helper()
	authority, err := identity.NewLocalAuthority(signing)
	if err != nil {
		t.Fatalf("identity.NewLocalAuthority() error = %v", err)
	}
	signed, err := auth.SignRelayDescriptor(types.RelayDescriptor{
		Address:            signing.Address,
		Version:            types.DiscoveryVersion,
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(DiscoveryDescriptorTTL),
		APIHTTPSAddr:       relayURL,
		WireGuardPublicKey: "3dpOqFgLYqlt/5hKsy653evfDxl7PjHUtTXLzcwkqxo=",
		WireGuardPort:      51820,
		SupportsOverlay:    true,
	}, authority)
	if err != nil {
		t.Fatalf("SignRelayDescriptor() error = %v", err)
	}
	return signed
}

func TestInsertCandidateHiddenUntilDirectProbe(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	relayURL := "https://hop-forward.example"
	descriptor := mustSignedOverlayDescriptor(t, signing, relayURL, now)

	if err := set.InsertCandidate(descriptor, now); err != nil {
		t.Fatalf("InsertCandidate() error = %v", err)
	}
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == relayURL {
			t.Fatal("candidate relay must stay out of Descriptors() until directly probed")
		}
	}
	overlayPeer := false
	for _, desc := range set.OverlayPeerDescriptor() {
		if desc.APIHTTPSAddr == relayURL {
			overlayPeer = true
		}
	}
	if !overlayPeer {
		t.Fatal("candidate relay must remain an overlay peer for its hop route")
	}

	// The real promotion path: the refresher polls the relay itself and
	// ApplyRelayDiscoveryResponse verifies the target's own descriptor.
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		GeneratedAt:     now,
		Relays:          []types.RelayDescriptor{descriptor},
	}, now); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}
	discovered := false
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == relayURL {
			discovered = true
		}
	}
	if !discovered {
		t.Fatal("directly probed relay must appear in Descriptors()")
	}
}

func TestFilterCandidatePoolExcludesCandidatesUntilVerified(t *testing.T) {
	signing := mustSigningIdentity(t)
	other := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	candidate := RelayState{
		Descriptor: mustSignedOverlayDescriptor(t, signing, "https://candidate.example", now),
		LastSeenAt: now,
	}
	verified := RelayState{
		Descriptor: mustSignedDescriptor(t, other, "https://verified-candidate.example", now),
		Trust:      RelayVerified,
		LastSeenAt: now,
	}

	pool := filterCandidatePool([]RelayState{candidate, verified}, RouteState{}, now, false)
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

func TestApplyRelayDiscoveryResponsePromotesOnlyTarget(t *testing.T) {
	set := NewRelaySet(nil)
	source := mustSigningIdentity(t)
	gossiped := make([]types.Identity, 3)
	for i := range gossiped {
		gossiped[i] = mustSigningIdentity(t)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	sourceURL := "https://probed-source.example"

	sourceDescriptor := mustSignedDescriptor(t, source, sourceURL, now)
	relays := []types.RelayDescriptor{sourceDescriptor}
	for i, identity := range gossiped {
		url := fmt.Sprintf("https://laundered-%d.example", i)
		relays = append(relays, mustSignedDescriptor(t, identity, url, now.Add(time.Duration(i)*time.Second)))
	}
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

	// A relay mentioned by the probed source only becomes visible through
	// its own direct probe.
	launderedURL := "https://laundered-0.example"
	launderedDescriptor := relays[1]
	if _, err := set.ApplyRelayDiscoveryResponse(launderedURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		GeneratedAt:     now,
		Relays:          []types.RelayDescriptor{launderedDescriptor},
	}, now); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse(laundered) error = %v", err)
	}
	visible = set.Descriptors(types.RelayDescriptor{})
	if len(visible) != 2 {
		t.Fatalf("len(Descriptors()) = %d, want 2 after the second direct probe", len(visible))
	}
}

func TestGossipRefreshKeepsVerifiedTrust(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	relayURL := "https://monotone.example"
	descriptor := mustSignedDescriptor(t, signing, relayURL, now)

	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		GeneratedAt:     now,
		Relays:          []types.RelayDescriptor{descriptor},
	}, now); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse(target) error = %v", err)
	}
	refreshed := mustSignedDescriptor(t, signing, relayURL, now.Add(time.Second))
	if _, err := set.ApplyRelayDiscoveryResponse("", types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		GeneratedAt:     now.Add(time.Second),
		Relays:          []types.RelayDescriptor{refreshed},
	}, now.Add(time.Second)); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse(gossip) error = %v", err)
	}

	visible := false
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == relayURL {
			visible = true
		}
	}
	if !visible {
		t.Fatal("gossip refresh must not demote a verified entry")
	}
}

func TestGlobalCapEvictsCandidatesBeforeVerified(t *testing.T) {
	set := NewRelaySet(nil)
	verified := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	verifiedDescriptor := mustSignedDescriptor(t, verified, "https://verified.example", now)
	if _, err := set.ApplyRelayDiscoveryResponse("https://verified.example", types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		GeneratedAt:     now,
		Relays:          []types.RelayDescriptor{verifiedDescriptor},
	}, now); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse(verified) error = %v", err)
	}

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

	visible := false
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == "https://verified.example" {
			visible = true
		}
	}
	if !visible {
		t.Fatal("verified relay must survive a candidate flood filling the global cap")
	}
	if got := len(relayStates(set)); got > MaxAnnouncedRelays {
		t.Fatalf("pool size = %d, want <= %d", got, MaxAnnouncedRelays)
	}
}

func TestTrustDoesNotTransferAcrossIdentityTakeover(t *testing.T) {
	set := NewRelaySet(nil)
	first := mustSigningIdentity(t)
	attacker := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	relayURL := "https://takeover.example"

	firstDescriptor := mustSignedDescriptor(t, first, relayURL, now)
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		GeneratedAt:     now,
		Relays:          []types.RelayDescriptor{firstDescriptor},
	}, now); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

	// The verified descriptor expires, which opens the URL slot to a
	// cross-identity takeover.
	later := now.Add(DiscoveryDescriptorTTL + time.Minute)
	if err := set.InsertCandidate(mustSignedDescriptor(t, attacker, relayURL, later), later); err != nil {
		t.Fatalf("InsertCandidate() error = %v", err)
	}

	state, ok := set.relays[relayURL]
	if !ok {
		t.Fatal("replacement descriptor must be stored")
	}
	if state.Trust != RelayCandidate {
		t.Fatalf("trust = %v, want RelayCandidate after a cross-identity takeover", state.Trust)
	}
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == relayURL {
			t.Fatal("replacement identity must not inherit visibility from the previous identity")
		}
	}
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
	if state.Trust != RelayCandidate {
		t.Fatalf("trust = %v, want RelayCandidate for a squatted bootstrap descriptor", state.Trust)
	}
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == bootstrapURL {
			t.Fatal("candidate descriptor squatted on a bootstrap URL must stay out of Descriptors()")
		}
	}
	if pool := filterCandidatePool([]RelayState{state}, RouteState{}, now, false); len(pool) != 0 {
		t.Fatalf("filterCandidatePool() = %v, want the squatted bootstrap excluded", pool)
	}

	// URL-only bootstrap entries keep their single-hop fallback role, but
	// never join multi-hop paths.
	urlOnly := newRelayState("https://bootstrap-fallback.example")
	urlOnly.Bootstrap = true
	if pool := filterCandidatePool([]RelayState{urlOnly}, RouteState{}, now, false); len(pool) != 1 {
		t.Fatal("URL-only bootstrap entry must remain a single-hop fallback candidate")
	}
	if pool := filterCandidatePool([]RelayState{urlOnly}, RouteState{}, now, true); len(pool) != 0 {
		t.Fatal("URL-only bootstrap entry must not join multi-hop paths")
	}
}
