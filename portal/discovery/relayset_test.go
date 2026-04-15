package discovery

import (
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestApplyRelayDiscoveryResponsePreservesBootstrapFlag(t *testing.T) {
	set := NewRelaySet([]string{"https://relay-a.example"})

	desc := mustPolicyRelayDescriptor(t, "relay-a", "https://relay-a.example")
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
	set := NewRelaySet(nil)

	now := time.Now().UTC()
	relayURL := "https://relay-stale.example"
	state := confirmedPolicyRelayState(t, "relay-stale", relayURL)
	state.Descriptor.ExpiresAt = now.Add(-time.Minute)
	state.LastSeenAt = now.Add(-6 * time.Hour)
	state.Descriptor.SupportsUDP = true
	state.Descriptor.SupportsTCP = true
	state.Descriptor.SupportsOverlayPeer = true
	state.Descriptor.IngressTLSAddr = "relay-stale.example:443"
	state.Descriptor.WireGuardPublicKey = "pub"
	state.Descriptor.WireGuardEndpoint = "relay-stale.example:51820"
	state.Descriptor.OverlayIPv4 = "10.0.0.1"
	state.Descriptor.OverlayCIDRs = []string{"10.0.0.0/24"}
	state.Descriptor.Load = 1
	state.Descriptor.LoadScore = 2

	set.mu.Lock()
	set.relays[relayURL] = state
	set.mu.Unlock()

	descriptors := set.Descriptors(types.RelayDescriptor{})
	if len(descriptors) != 0 {
		t.Fatalf("len(Descriptors(empty)) = %d, want 0", len(descriptors))
	}
}

func TestApplyRelayDiscoveryResponseCollectsRelaysDespiteProtocolMismatch(t *testing.T) {
	set := NewRelaySet(nil)

	desc := mustPolicyRelayDescriptor(t, "relay-mismatch", "https://relay-mismatch.example")
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
	set := NewRelaySet(nil)

	hinted := mustPolicyRelayDescriptor(t, "relay-hinted", "https://relay-hinted.example")
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

func TestApplyRelayDiscoveryResponseClearsDirectRetryOnAuthoritativeSuccess(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-source.example"
	desc := mustPolicyRelayDescriptor(t, "relay-source", relayURL)
	set.mu.Lock()
	state := RelayState{
		Descriptor:          desc,
		LastSeenAt:          time.Now().UTC(),
		consecutiveFailures: defaultRecoveryFailures,
		nextDirectRefreshAt: time.Now().UTC().Add(time.Minute),
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
	if refreshed.consecutiveFailures != 0 {
		t.Fatalf("consecutiveFailures = %d, want 0", refreshed.consecutiveFailures)
	}
	if !refreshed.nextDirectRefreshAt.IsZero() {
		t.Fatalf("nextDirectRefreshAt = %v, want zero time", refreshed.nextDirectRefreshAt)
	}
}

func TestApplyRelayDiscoveryResponsePreservesDirectRetryOnHint(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-hinted.example"
	desc := mustPolicyRelayDescriptor(t, "relay-hinted", relayURL)
	nextDirectRefreshAt := time.Now().UTC().Add(time.Minute)
	set.mu.Lock()
	state := RelayState{
		Descriptor:          desc,
		LastSeenAt:          time.Now().UTC(),
		nextDirectRefreshAt: nextDirectRefreshAt,
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
	if !refreshed.nextDirectRefreshAt.Equal(nextDirectRefreshAt) {
		t.Fatalf("nextDirectRefreshAt = %v, want %v", refreshed.nextDirectRefreshAt, nextDirectRefreshAt)
	}
}

func TestConfirmRelayURLMarksRelayConfirmedWithoutChangingAggregateDescriptor(t *testing.T) {
	set := NewRelaySet(nil)

	relayURL := "https://relay-confirmed.example"
	state := RelayState{
		Descriptor: mustPolicyRelayDescriptor(t, "relay-confirmed", relayURL),
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
	set := NewRelaySet(nil)

	relayURL := "https://relay-confirmed.example"
	state := confirmedPolicyRelayState(t, "relay-confirmed", relayURL)

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
