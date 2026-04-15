package discovery

import (
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func mustSigningIdentity(t *testing.T) types.Identity {
	t.Helper()
	identity, err := utils.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("ResolveSecp256k1Identity() error = %v", err)
	}
	return identity
}

func mustUnsignedDescriptor(t *testing.T, signing types.Identity, relayName, relayURL string) types.RelayDescriptor {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	return types.RelayDescriptor{
		Identity: types.Identity{
			Name:    relayName,
			Address: signing.Address,
		},
		RelayID:      relayURL,
		Version:      1,
		IssuedAt:     now,
		ExpiresAt:    now.Add(time.Hour),
		APIHTTPSAddr: relayURL,
		Discovery:    true,
	}
}

func mustSignedDescriptor(t *testing.T, signing types.Identity, relayName, relayURL string, issuedAt time.Time) types.RelayDescriptor {
	t.Helper()
	signed, err := auth.SignRelayDescriptor(types.RelayDescriptor{
		Identity: types.Identity{
			Name:    relayName,
			Address: signing.Address,
		},
		RelayID:      relayURL,
		Version:      1,
		IssuedAt:     issuedAt,
		ExpiresAt:    issuedAt.Add(DiscoveryDescriptorTTL),
		APIHTTPSAddr: relayURL,
		Discovery:    true,
	}, signing.PrivateKey)
	if err != nil {
		t.Fatalf("SignRelayDescriptor() error = %v", err)
	}
	return signed
}

func TestInsertAnnouncedAcceptsValidDescriptor(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	desc := mustSignedDescriptor(t, signing, "relay-ann", "https://relay-ann.example", now)
	if err := set.InsertAnnounced(desc, now); err != nil {
		t.Fatalf("InsertAnnounced() error = %v", err)
	}
	if got := set.AggregateRelays(); len(got) != 1 {
		t.Fatalf("len(AggregateRelays()) = %d, want 1", len(got))
	}
}

func TestInsertAnnouncedRejectsUnsigned(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	desc := mustUnsignedDescriptor(t, signing, "relay-unsigned", "https://relay-unsigned.example")
	if err := set.InsertAnnounced(desc, now); err == nil {
		t.Fatal("expected unsigned reject")
	}
}

func TestInsertAnnouncedIgnoresSupersededRollback(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	relayURL := "https://relay-roll.example"
	newer := mustSignedDescriptor(t, signing, "relay-roll", relayURL, now)
	if err := set.InsertAnnounced(newer, now); err != nil {
		t.Fatalf("seed insert error = %v", err)
	}
	older := mustSignedDescriptor(t, signing, "relay-roll", relayURL, now.Add(-time.Minute))
	if err := set.InsertAnnounced(older, now); err != nil {
		t.Fatalf("superseded insert error = %v", err)
	}

	states := set.AggregateRelays()
	if len(states) != 1 {
		t.Fatalf("len(AggregateRelays()) = %d, want 1", len(states))
	}
	if got := states[0].Descriptor.IssuedAt; !got.Equal(newer.IssuedAt) {
		t.Fatalf("stored issued_at = %v, want %v", got, newer.IssuedAt)
	}
}

func TestInsertAnnouncedRejectsRollbackAcrossRelayURL(t *testing.T) {
	set := NewRelaySet(nil)
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	newer := mustSignedDescriptor(t, signing, "relay-roll", "https://relay-roll-new.example", now)
	if err := set.InsertAnnounced(newer, now); err != nil {
		t.Fatalf("seed insert error = %v", err)
	}
	older := mustSignedDescriptor(t, signing, "relay-roll", "https://relay-roll-old.example", now.Add(-time.Minute))
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

	ownerDesc := mustSignedDescriptor(t, owner, "relay-takeover", relayURL, now)
	if err := set.InsertAnnounced(ownerDesc, now); err != nil {
		t.Fatalf("owner insert error = %v", err)
	}

	attackerDesc := mustSignedDescriptor(t, attacker, "relay-takeover", relayURL, now.Add(time.Second))
	if err := set.InsertAnnounced(attackerDesc, now); err == nil {
		t.Fatal("expected takeover reject")
	}

	states := set.AggregateRelays()
	if len(states) != 1 {
		t.Fatalf("len(AggregateRelays()) = %d, want 1", len(states))
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
