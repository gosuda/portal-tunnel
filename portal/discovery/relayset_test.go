package discovery

import (
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestApplyRelayDiscoveryResponsePreservesBootstrapFlag(t *testing.T) {
	set := newTestRelaySet([]string{"https://relay-a.example"})

	desc := mustPolicyRelayDescriptor(t, "https://relay-a.example")
	if _, err := set.ApplyRelayDiscoveryResponse(desc.APIHTTPSAddr, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

	states := set.AggregateRelays()
	if len(states) != 1 {
		t.Fatalf("len(AggregateRelays()) = %d, want 1", len(states))
	}
	if !states[0].Bootstrap {
		t.Fatal("bootstrap relay lost bootstrap flag after discovery update")
	}
}

func TestDescriptorsDropsExpiredSignedRelayDescriptor(t *testing.T) {
	set := newTestRelaySet(nil)

	now := time.Now().UTC()
	relayURL := "https://relay-stale.example"
	state := confirmedPolicyRelayState(t, relayURL)
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

func TestApplyRelayDiscoveryResponseCollectsRelaysDespiteProtocolMismatch(t *testing.T) {
	set := newTestRelaySet(nil)

	desc := mustPolicyRelayDescriptor(t, "https://relay-mismatch.example")
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

	states := set.AggregateRelays()
	if len(states) != 1 {
		t.Fatalf("len(AggregateRelays()) = %d, want 1", len(states))
	}
	if got := states[0].Descriptor.APIHTTPSAddr; got != desc.APIHTTPSAddr {
		t.Fatalf("states[0] = %q, want %q", got, desc.APIHTTPSAddr)
	}
	if states[0].Confirmed {
		t.Fatal("hinted relay should not become locally confirmed from aggregation")
	}
}

func TestApplyRelayDiscoveryResponseCollectsHintsWhenTargetDescriptorIsMissing(t *testing.T) {
	set := newTestRelaySet(nil)

	hinted := mustPolicyRelayDescriptor(t, "https://relay-hinted.example")
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

	states := set.AggregateRelays()
	if len(states) != 1 {
		t.Fatalf("len(AggregateRelays()) = %d, want 1", len(states))
	}
	if got := states[0].Descriptor.APIHTTPSAddr; got != hinted.APIHTTPSAddr {
		t.Fatalf("states[0] = %q, want %q", got, hinted.APIHTTPSAddr)
	}
	if states[0].Confirmed {
		t.Fatal("hinted relay should not become locally confirmed when target descriptor is missing")
	}
}

func TestApplyRelayDiscoveryResponseClearsDiscoveryRetryOnAuthoritativeSuccess(t *testing.T) {
	set := newTestRelaySet(nil)

	relayURL := "https://relay-source.example"
	desc := mustPolicyRelayDescriptor(t, relayURL)
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
	set := newTestRelaySet(nil)

	relayURL := "https://relay-hinted.example"
	desc := mustPolicyRelayDescriptor(t, relayURL)
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
	set := newTestRelaySet(nil)

	relayURL := "https://relay-confirmed.example"
	state := RelayState{
		Descriptor: mustPolicyRelayDescriptor(t, relayURL),
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

func TestUnconfirmRelayURLClearsLocalConfirmationOnly(t *testing.T) {
	set := newTestRelaySet(nil)

	relayURL := "https://relay-confirmed.example"
	state := confirmedPolicyRelayState(t, relayURL)

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
