package discovery

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

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

func seedColludingGossipSet(t *testing.T) (*RelaySet, time.Time, types.RelayDescriptor, types.RelayDescriptor, types.RelayDescriptor) {
	t.Helper()
	set := NewRelaySet(nil)
	now := time.Now().UTC().Truncate(time.Microsecond)
	const healthy, reporter = "https://healthy.example", "https://reporter.example"
	healthyDescriptor := mustSignedDescriptor(t, mustSigningIdentity(t), healthy, now)
	mustApplyAuthoritative(t, set, healthyDescriptor)
	reporterDescriptor := mustSignedDescriptor(t, mustSigningIdentity(t), reporter, now)
	forged := healthyDescriptor
	forged.SupportsTCP = !forged.SupportsTCP
	return set, now, healthyDescriptor, reporterDescriptor, forged
}

func applyColludingGossipReports(t *testing.T, set *RelaySet, reporterDescriptor types.RelayDescriptor, forged types.RelayDescriptor, now time.Time) {
	t.Helper()
	const healthy, reporter = "https://healthy.example", "https://reporter.example"
	for i := range 4 {
		colluder := mustSignedDescriptor(t, mustSigningIdentity(t), fmt.Sprintf("https://colluder-%d.example", i), now)
		if _, err := set.ApplyRelayDiscoveryResponse(reporter, types.DiscoveryResponse{
			ProtocolVersion: types.DiscoveryVersion,
			Relays:          []types.RelayDescriptor{reporterDescriptor, colluder, forged},
			IncompatibleRelays: []types.IncompatibleRelayEntry{{
				URL: healthy, ProtocolVersion: "claimed-incompatible", LastSeenAt: now,
			}},
			RelayReleaseVersions: map[string]string{healthy: "claimed-release"},
		}, now); err != nil {
			t.Fatal(err)
		}
	}
}

func checkColludingGossipEvidence(t *testing.T, set *RelaySet, healthyDescriptor types.RelayDescriptor) {
	t.Helper()
	const healthy, reporter = "https://healthy.example", "https://reporter.example"
	selected := set.selectRelays(routeState{})
	if len(selected) != 2 || !slices.Contains(selected, healthy) || !slices.Contains(selected, reporter) {
		t.Fatalf("gossip manufactured selectable relays or excluded the healthy peer: %v", selected)
	}
	if len(set.KnownIncompatibleRelays()) != 0 || set.KnownRelayReleaseVersions()[healthy] != "" {
		t.Fatal("reporter's peer metadata replaced a direct observation")
	}
	for _, desc := range set.Descriptors(types.RelayDescriptor{}) {
		if desc.APIHTTPSAddr == healthy && desc.Signature != healthyDescriptor.Signature {
			t.Fatal("forged capabilities replaced the healthy peer's signed descriptor")
		}
	}
}

func TestColludingGossipCannotReplaceLocalRelayEvidence(t *testing.T) {
	set, now, healthyDescriptor, reporterDescriptor, forged := seedColludingGossipSet(t)
	applyColludingGossipReports(t, set, reporterDescriptor, forged, now)
	checkColludingGossipEvidence(t, set, healthyDescriptor)
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
	authority := identity.NewLocalAuthority(signing)
	signed, err := SignRelayDescriptor(types.RelayDescriptor{
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

func recordConflictMismatch(t *testing.T, set *RelaySet, original types.RelayDescriptor, relayURL string, now time.Time) {
	t.Helper()
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: "incompatible",
		Relays:          []types.RelayDescriptor{original},
	}, now); !errors.Is(err, ErrProtocolMismatch) {
		t.Fatalf("protocol mismatch error = %v", err)
	}
}

func buildConflictUpdate(t *testing.T, signer types.Identity, original types.RelayDescriptor) types.RelayDescriptor {
	t.Helper()
	conflict := original
	conflict.SupportsTCP = !original.SupportsTCP
	conflict, err := SignRelayDescriptor(conflict, identity.NewLocalAuthority(signer))
	if err != nil {
		t.Fatal(err)
	}
	return conflict
}

func applyConflictIngress(t *testing.T, set *RelaySet, conflict types.RelayDescriptor, ingress string, now time.Time) error {
	t.Helper()
	const relayURL = "https://conflicting.example"
	switch ingress {
	case "announce":
		return set.InsertCandidate(conflict, now)
	case "gossip":
		reporter := mustSignedDescriptor(t, mustSigningIdentity(t), "https://reporter.example", now)
		_, err := set.ApplyRelayDiscoveryResponse(reporter.APIHTTPSAddr, types.DiscoveryResponse{
			ProtocolVersion: types.DiscoveryVersion,
			Relays:          []types.RelayDescriptor{reporter, conflict},
		}, now)
		return err
	case "direct":
		_, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
			ProtocolVersion: types.DiscoveryVersion,
			Relays:          []types.RelayDescriptor{conflict},
		}, now)
		return err
	}
	t.Fatalf("unknown ingress %q", ingress)
	return nil
}

func checkConflictPreserved(t *testing.T, set *RelaySet, before relayState, ingress string) {
	t.Helper()
	const relayURL = "https://conflicting.example"
	if after := set.relays[relayURL]; !reflect.DeepEqual(after, before) {
		t.Fatalf("conflicting update changed retained observation or recovery state: before=%+v after=%+v", before, after)
	}
	if ingress == "direct" && len(set.KnownIncompatibleRelays()) != 1 {
		t.Fatal("conflicting direct response cleared prior incompatibility")
	}
}

func seedDescriptorConflictCase(t *testing.T, set *RelaySet, ingress string) (types.Identity, types.RelayDescriptor, time.Time) {
	t.Helper()
	const relayURL = "https://conflicting.example"
	now := time.Now().UTC().Truncate(time.Microsecond)
	signer := mustSigningIdentity(t)
	original := mustSignedDescriptor(t, signer, relayURL, now)
	mustApplyAuthoritative(t, set, original)
	if ingress == "direct" {
		recordConflictMismatch(t, set, original, relayURL, now)
	}
	return signer, original, now
}

func admitDescriptorConflictCase(t *testing.T, set *RelaySet, conflict types.RelayDescriptor, ingress string, now time.Time) {
	t.Helper()
	before := set.relays["https://conflicting.example"]
	err := applyConflictIngress(t, set, conflict, ingress, now)
	if (err != nil) != (ingress != "gossip") {
		t.Fatalf("admission error = %v for %s", err, ingress)
	}
	checkConflictPreserved(t, set, before, ingress)
}

func runSteadyConflictCase(t *testing.T, ingress string) {
	t.Helper()
	const relayURL = "https://conflicting.example"
	set := NewRelaySet(nil)
	signer, original, now := seedDescriptorConflictCase(t, set, ingress)
	conflict := buildConflictUpdate(t, signer, original)
	admitDescriptorConflictCase(t, set, conflict, ingress, now)
	if got := routesTo(t, set, relayURL); !got {
		t.Fatalf("relay eligible = %t, want %t", got, true)
	}
}

func runRecoveringConflictCase(t *testing.T, ingress string) {
	t.Helper()
	const relayURL = "https://conflicting.example"
	set := NewRelaySet(nil)
	signer, original, now := seedDescriptorConflictCase(t, set, ingress)
	set.RecordDiscoveryFailure(relayURL, 1)
	conflict := buildConflictUpdate(t, signer, original)
	admitDescriptorConflictCase(t, set, conflict, ingress, now)
	if got := routesTo(t, set, relayURL); got {
		t.Fatalf("relay eligible = %t, want %t", got, false)
	}
}

func TestSignedDescriptorConflictPreservesLocalObservation(t *testing.T) {
	for _, ingress := range []string{"announce", "gossip", "direct"} {
		t.Run(ingress+"/recovering=false", func(t *testing.T) {
			runSteadyConflictCase(t, ingress)
		})
		t.Run(ingress+"/recovering=true", func(t *testing.T) {
			runRecoveringConflictCase(t, ingress)
		})
	}
}

func TestDescriptorConflictGuardAllowsRetransmissionAndFreshUpdates(t *testing.T) {
	set := NewRelaySet(nil)
	now := time.Now().UTC().Truncate(time.Microsecond)
	signer := mustSigningIdentity(t)
	const relayURL = "https://recovering.example"
	original := mustSignedDescriptor(t, signer, relayURL, now)
	mustApplyAuthoritative(t, set, original)
	set.RecordDiscoveryFailure(relayURL, 1)
	mustApplyAuthoritative(t, set, original)
	if !routesTo(t, set, relayURL) {
		t.Fatal("identical retransmission did not recover eligibility")
	}
	other := mustSignedDescriptor(t, signer, "https://other.example", now)
	if err := set.InsertCandidate(other, now); err != nil {
		t.Fatalf("same-time descriptor for another URL: %v", err)
	}
	updated := original
	updated.IssuedAt = now.Add(time.Second)
	updated.ExpiresAt = updated.IssuedAt.Add(DiscoveryDescriptorTTL)
	updated.SupportsTCP = !original.SupportsTCP
	updated, err := SignRelayDescriptor(updated, identity.NewLocalAuthority(signer))
	if err != nil {
		t.Fatal(err)
	}
	mustApplyAuthoritative(t, set, updated)
	if set.relays[relayURL].Descriptor.Signature != updated.Signature || !routesTo(t, set, relayURL) {
		t.Fatal("newly issued capability update did not replace the previous observation")
	}
}

func TestNormalizeRelayDescriptorFieldLimits(t *testing.T) {
	const prefix = "https://relay.example/"
	for _, tc := range []struct {
		name, url, destination, signature string
		valid                             bool
	}{
		{"maximum URL", prefix + strings.Repeat("a", types.MaxRelayDescriptorURLBytes-len(prefix)), "", "", true},
		{"oversized URL", prefix + strings.Repeat("a", types.MaxRelayDescriptorURLBytes-len(prefix)+1), "", "", false},
		{"maximum destination", prefix, strings.Repeat("a", 52) + ".b32.i2p", "", true},
		{"oversized destination", prefix, strings.Repeat("a", types.MaxRelayDescriptorDestinationBytes+1), "", false},
		{"maximum signature", prefix, "", strings.Repeat("a", types.MaxRelayDescriptorSignatureBytes), true},
		{"oversized signature", prefix, "", strings.Repeat("a", types.MaxRelayDescriptorSignatureBytes+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			desc := types.RelayDescriptor{
				Address:         "0x" + strings.Repeat("1", 40),
				APIHTTPSAddr:    tc.url,
				IVNPDestination: tc.destination,
				Signature:       tc.signature,
				ExpiresAt:       time.Unix(1, 0),
			}
			if _, err := NormalizeRelayDescriptor(desc); (err == nil) != tc.valid {
				t.Fatalf("NormalizeRelayDescriptor() error = %v, want valid=%v", err, tc.valid)
			}
		})
	}
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

func TestInsertCandidateCapsFloodPerSigningIdentity(t *testing.T) {
	set := NewRelaySet(nil)
	legit := mustSigningIdentity(t)
	attacker := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	if err := set.InsertCandidate(mustSignedDescriptor(t, legit, "https://legit.example", now), now); err != nil {
		t.Fatalf("legit insert error = %v", err)
	}
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

func TestInsertCandidatePerIdentityCapKeepsVerifiedEntries(t *testing.T) {
	set := NewRelaySet(nil)
	owner := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	verifiedURL := "https://verified.example"
	set.relays[verifiedURL] = relayState{
		Descriptor: mustSignedDescriptor(t, owner, verifiedURL, now),
		Trust:      relayVerified,
		LastSeenAt: now,
	}
	for i := range MaxAnnouncedRelaysPerIdentity * 2 {
		at := now.Add(time.Duration(i) * time.Second)
		url := fmt.Sprintf("https://owner-%02d.example", i)
		if err := set.InsertCandidate(mustSignedDescriptor(t, owner, url, at), at); err != nil {
			t.Fatalf("insert %d error = %v", i, err)
		}
	}

	verified, ok := set.relays[verifiedURL]
	if !ok || verified.Trust != relayVerified {
		t.Fatal("directly verified entry must survive the identity cap")
	}
}
