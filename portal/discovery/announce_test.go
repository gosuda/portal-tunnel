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

func TestInsertAnnouncedAcceptsValidDescriptor(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	desc := mustSignedDescriptor(t, signing, "https://relay-ann.example", now)
	if err := set.InsertAnnounced(desc, now); err != nil {
		t.Fatalf("InsertAnnounced() error = %v", err)
	}
	if got := relayStates(set); len(got) != 1 {
		t.Fatalf("len(relayStates()) = %d, want 1", len(got))
	}
}

func TestInsertAnnouncedRejectsUnsigned(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	desc := mustUnsignedDescriptor(t, signing, "https://relay-unsigned.example")
	err := set.InsertAnnounced(desc, now)
	if err == nil || err.Error() != "relay descriptor is not signed" {
		t.Fatalf("InsertAnnounced() error = %v, want unsigned descriptor error", err)
	}
}

func TestInsertAnnouncedRejectsExpired(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	desc := mustSignedDescriptor(t, signing, "https://relay-expired.example", now.Add(-DiscoveryDescriptorTTL-time.Second))
	err := set.InsertAnnounced(desc, now)
	if err == nil || err.Error() != "relay descriptor already expired" {
		t.Fatalf("InsertAnnounced() error = %v, want expired descriptor error", err)
	}
}

func TestInsertAnnouncedIgnoresSupersededRollback(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	relayURL := "https://relay-roll.example"
	newer := mustSignedDescriptor(t, signing, relayURL, now)
	if err := set.InsertAnnounced(newer, now); err != nil {
		t.Fatalf("seed insert error = %v", err)
	}
	older := mustSignedDescriptor(t, signing, relayURL, now.Add(-time.Minute))
	if err := set.InsertAnnounced(older, now); err != nil {
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

func TestInsertAnnouncedRejectsRollbackAcrossRelayURL(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	newer := mustSignedDescriptor(t, signing, "https://relay-roll-new.example", now)
	if err := set.InsertAnnounced(newer, now); err != nil {
		t.Fatalf("seed insert error = %v", err)
	}
	older := mustSignedDescriptor(t, signing, "https://relay-roll-old.example", now.Add(-time.Minute))
	if err := set.InsertAnnounced(older, now); err == nil {
		t.Fatal("expected rollback reject")
	}
}

func TestInsertAnnouncedBlocksCrossIdentityTakeover(t *testing.T) {
	set := NewRelaySet(nil)
	owner := mustSigningIdentity(t)
	attacker := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	relayURL := "https://relay-takeover.example"

	ownerDesc := mustSignedDescriptor(t, owner, relayURL, now)
	if err := set.InsertAnnounced(ownerDesc, now); err != nil {
		t.Fatalf("owner insert error = %v", err)
	}

	attackerDesc := mustSignedDescriptor(t, attacker, relayURL, now.Add(time.Second))
	if err := set.InsertAnnounced(attackerDesc, now); err == nil {
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

func TestInsertAnnouncedCapsFloodPerSigningIdentity(t *testing.T) {
	set := NewRelaySet(nil)
	legit := mustSigningIdentity(t)
	attacker := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	if err := set.InsertAnnounced(mustSignedDescriptor(t, legit, "https://legit.example", now), now); err != nil {
		t.Fatalf("legit insert error = %v", err)
	}
	// Flood the pool the way the reported abuse does: one signing identity
	// announcing MaxAnnouncedRelays distinct URLs with fresh IssuedAt.
	for i := range MaxAnnouncedRelays {
		at := now.Add(time.Duration(i) * time.Second)
		url := fmt.Sprintf("https://attacker-%04d.example", i)
		if err := set.InsertAnnounced(mustSignedDescriptor(t, attacker, url, at), at); err != nil {
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

func TestInsertAnnouncedPerIdentityCapKeepsConfirmedEntries(t *testing.T) {
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
		if err := set.InsertAnnounced(mustSignedDescriptor(t, owner, url, at), at); err != nil {
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

func TestInsertHopRelayStagesUntilConfirmed(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	relayURL := "https://hop-forward.example"

	if err := set.InsertHopRelay(mustSignedOverlayDescriptor(t, signing, relayURL, now), now); err != nil {
		t.Fatalf("InsertHopRelay() error = %v", err)
	}
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == relayURL {
			t.Fatal("staged hop relay must stay out of Descriptors() until confirmed")
		}
	}
	overlayPeer := false
	for _, desc := range set.OverlayPeerDescriptor() {
		if desc.APIHTTPSAddr == relayURL {
			overlayPeer = true
		}
	}
	if !overlayPeer {
		t.Fatal("staged hop relay must remain an overlay peer for its hop route")
	}

	set.ConfirmRelayURL(relayURL)
	discovered := false
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == relayURL {
			discovered = true
		}
	}
	if !discovered {
		t.Fatal("confirmed hop relay must appear in Descriptors()")
	}
}

func TestFilterCandidatePoolExcludesStagedUntilConfirmed(t *testing.T) {
	signing := mustSigningIdentity(t)
	other := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	staged := RelayState{
		Descriptor: mustSignedOverlayDescriptor(t, signing, "https://staged.example", now),
		Staged:     true,
		LastSeenAt: now,
	}
	confirmed := RelayState{
		Descriptor: mustSignedDescriptor(t, other, "https://confirmed-candidate.example", now),
		Confirmed:  true,
		LastSeenAt: now,
	}

	pool := filterCandidatePool([]RelayState{staged, confirmed}, RouteState{}, now, false)
	if len(pool) != 1 || pool[0].Descriptor.APIHTTPSAddr != "https://confirmed-candidate.example" {
		t.Fatalf("filterCandidatePool() = %v, want only the confirmed entry", pool)
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
