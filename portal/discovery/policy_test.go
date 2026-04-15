package discovery

import (
	"errors"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func mustPolicyRelayDescriptor(t *testing.T, relayName, relayURL string) types.RelayDescriptor {
	t.Helper()

	signing, err := utils.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("ResolveSecp256k1Identity() error = %v", err)
	}
	now := time.Now().UTC()
	signed, err := auth.SignRelayDescriptor(types.RelayDescriptor{
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
	}, signing.PrivateKey)
	if err != nil {
		t.Fatalf("SignRelayDescriptor() error = %v", err)
	}
	return signed
}

func bootstrapPolicyRelayState(relayURL string) RelayState {
	return RelayState{
		Descriptor: types.RelayDescriptor{
			Identity: types.Identity{
				Name: utils.PortalRootHost(relayURL),
			},
			RelayID:      relayURL,
			APIHTTPSAddr: relayURL,
		},
		Bootstrap: true,
	}
}

func confirmedPolicyRelayState(t *testing.T, relayName, relayURL string) RelayState {
	t.Helper()

	return RelayState{
		Descriptor: mustPolicyRelayDescriptor(t, relayName, relayURL),
		Confirmed:  true,
		LastSeenAt: time.Now().UTC(),
	}
}

func confirmedPolicyRelayStateWithRTT(t *testing.T, relayName, relayURL string, rtt time.Duration) RelayState {
	t.Helper()

	state := confirmedPolicyRelayState(t, relayName, relayURL)
	state.DiscoveryRTT = rtt
	state.DiscoveryRTTAt = time.Now().UTC()
	return state
}

func TestSelectPriorityKeepsExplicitRelaysOutsideAutoLimit(t *testing.T) {
	policy := DefaultRelayPolicy{}
	explicitRelay := "https://relay-explicit.example"
	relayA := "https://relay-a.example"
	relayB := "https://relay-b.example"

	selected := policy.SelectPriority([]RelayState{
		bootstrapPolicyRelayState(explicitRelay),
		confirmedPolicyRelayState(t, "relay-a", relayA),
		confirmedPolicyRelayState(t, "relay-b", relayB),
	}, ClientState{
		ExplicitRelayURLs: []string{explicitRelay},
		MaxActiveRelays:   1,
	})

	if len(selected) != 2 {
		t.Fatalf("len(selected) = %d, want 2", len(selected))
	}
	if got := selected[0]; got != explicitRelay {
		t.Fatalf("selected[0] = %q, want explicit relay %q", got, explicitRelay)
	}
}

func TestSelectAggregateKeepsBootstrapRelayWhenDescriptorExpired(t *testing.T) {
	policy := DefaultRelayPolicy{}
	relayURL := "https://relay-bootstrap.example"

	state := bootstrapPolicyRelayState(relayURL)
	state.LastSeenAt = time.Now().UTC().Add(-time.Minute)
	state.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Second)

	selected := policy.SelectAggregate([]RelayState{state})

	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d, want 1", len(selected))
	}
	if got := selected[0].Descriptor.APIHTTPSAddr; got != relayURL {
		t.Fatalf("selected[0] = %q, want bootstrap relay %q", got, relayURL)
	}
}

func TestSelectAggregateKeepsCollectedRelayEvenWhenNotAdvertisable(t *testing.T) {
	policy := DefaultRelayPolicy{}
	state := RelayState{
		Descriptor: mustPolicyRelayDescriptor(t, "relay-a", "https://relay-a.example"),
		LastSeenAt: time.Now().UTC().Add(-31 * 24 * time.Hour),
	}
	state.Descriptor.Discovery = false
	state.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Second)

	selected := policy.SelectAggregate([]RelayState{state})

	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d, want 1", len(selected))
	}
}

func TestSelectAggregateIncludesHintedRelayWithoutConfirmation(t *testing.T) {
	policy := DefaultRelayPolicy{}
	state := RelayState{
		Descriptor: mustPolicyRelayDescriptor(t, "relay-hinted", "https://relay-hinted.example"),
		LastSeenAt: time.Now().UTC(),
	}

	selected := policy.SelectAggregate([]RelayState{state})

	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d, want 1", len(selected))
	}
	if got := selected[0].Descriptor.APIHTTPSAddr; got != state.Descriptor.APIHTTPSAddr {
		t.Fatalf("selected[0] = %q, want %q", got, state.Descriptor.APIHTTPSAddr)
	}
}

func TestSelectAggregateSkipsBannedBootstrapRelay(t *testing.T) {
	policy := DefaultRelayPolicy{}
	state := bootstrapPolicyRelayState("https://relay-banned.example")
	state.Banned = true

	selected := policy.SelectAggregate([]RelayState{state})

	if len(selected) != 0 {
		t.Fatalf("len(selected) = %d, want 0", len(selected))
	}
}

func TestSelectPriorityColdStartSelectsEligibleRelay(t *testing.T) {
	policy := DefaultRelayPolicy{}
	relayA := "https://relay-a.example"
	relayB := "https://relay-b.example"

	selected := policy.SelectPriority([]RelayState{
		confirmedPolicyRelayState(t, "relay-a", relayA),
		confirmedPolicyRelayState(t, "relay-b", relayB),
	}, ClientState{
		MaxActiveRelays: 1,
	})

	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d, want 1", len(selected))
	}
	if got := selected[0]; got != relayA && got != relayB {
		t.Fatalf("selected[0] = %q, want one of %q or %q", got, relayA, relayB)
	}
}

func TestSelectPriorityPrefersConfirmedRelayOverHintedRelay(t *testing.T) {
	policy := DefaultRelayPolicy{}
	confirmedRelay := confirmedPolicyRelayState(t, "relay-confirmed", "https://relay-confirmed.example")
	hintedRelay := RelayState{
		Descriptor: mustPolicyRelayDescriptor(t, "relay-hinted", "https://relay-hinted.example"),
		LastSeenAt: time.Now().UTC(),
	}

	selected := policy.SelectPriority([]RelayState{
		hintedRelay,
		confirmedRelay,
	}, ClientState{
		MaxActiveRelays: 1,
	})

	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d, want 1", len(selected))
	}
	if got := selected[0]; got != confirmedRelay.Descriptor.APIHTTPSAddr {
		t.Fatalf("selected[0] = %q, want confirmed relay %q", got, confirmedRelay.Descriptor.APIHTTPSAddr)
	}
}

func TestSelectPriorityKeepsCurrentRelayOverNewConfirmedRelay(t *testing.T) {
	policy := DefaultRelayPolicy{}
	currentRelay := "https://relay-current.example"
	newRelay := "https://relay-new.example"

	selected := policy.SelectPriority([]RelayState{
		bootstrapPolicyRelayState(currentRelay),
		confirmedPolicyRelayState(t, "relay-new", newRelay),
	}, ClientState{
		ActiveRelayURLs: []string{currentRelay},
		MaxActiveRelays: 1,
	})

	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d, want 1", len(selected))
	}
	if got := selected[0]; got != currentRelay {
		t.Fatalf("selected[0] = %q, want current relay %q kept", got, currentRelay)
	}
}

func TestSelectPriorityPushesHighRTTRelayBehindNormalRelay(t *testing.T) {
	policy := DefaultRelayPolicy{}
	normalRelay := confirmedPolicyRelayStateWithRTT(t, "relay-normal", "https://relay-normal.example", 200*time.Millisecond)
	highRTTRelay := confirmedPolicyRelayStateWithRTT(t, "relay-high-rtt", "https://relay-high-rtt.example", 1500*time.Millisecond)

	selected := policy.SelectPriority([]RelayState{
		highRTTRelay,
		normalRelay,
	}, ClientState{
		MaxActiveRelays: 1,
	})

	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d, want 1", len(selected))
	}
	if got := selected[0]; got != normalRelay.Descriptor.APIHTTPSAddr {
		t.Fatalf("selected[0] = %q, want normal RTT relay %q", got, normalRelay.Descriptor.APIHTTPSAddr)
	}
}

func TestOnConfirmedMarksRelayConfirmed(t *testing.T) {
	policy := DefaultRelayPolicy{}
	nextDirectRefreshAt := time.Now().UTC().Add(time.Minute)
	state := RelayState{
		Descriptor:          mustPolicyRelayDescriptor(t, "relay-a", "https://relay-a.example"),
		LastSeenAt:          time.Now().UTC(),
		consecutiveFailures: defaultRecoveryFailures,
		nextDirectRefreshAt: nextDirectRefreshAt,
	}

	state = policy.OnConfirmed(state)

	if !state.Confirmed {
		t.Fatal("relay should become confirmed")
	}
	if state.consecutiveFailures != defaultRecoveryFailures {
		t.Fatalf("consecutiveFailures = %d, want %d", state.consecutiveFailures, defaultRecoveryFailures)
	}
	if !state.nextDirectRefreshAt.Equal(nextDirectRefreshAt) {
		t.Fatalf("nextDirectRefreshAt = %v, want %v", state.nextDirectRefreshAt, nextDirectRefreshAt)
	}
}

func TestOnUnconfirmedClearsRelayConfirmation(t *testing.T) {
	policy := DefaultRelayPolicy{}
	state := confirmedPolicyRelayState(t, "relay-a", "https://relay-a.example")

	state = policy.OnUnconfirmed(state)

	if state.Confirmed {
		t.Fatal("relay should become unconfirmed")
	}
}

func TestOnFailureSchedulesDirectRecoveryRetry(t *testing.T) {
	policy := DefaultRelayPolicy{}
	state := confirmedPolicyRelayState(t, "relay-a", "https://relay-a.example")
	startedAt := time.Now().UTC()

	var backedOff bool
	var reason string
	for range defaultRecoveryFailures {
		state, backedOff, reason = policy.OnFailure(state, errors.New("boom"), defaultRecoveryFailures)
	}

	if !backedOff {
		t.Fatal("expected relay to back off after recovery failure budget")
	}
	if reason != "recovery" {
		t.Fatalf("backoff reason = %q, want recovery", reason)
	}
	if !state.nextDirectRefreshAt.After(startedAt) {
		t.Fatalf("nextDirectRefreshAt = %v, want a future retry time", state.nextDirectRefreshAt)
	}
}

func TestOnFailureSchedulesRetryForHintedRelay(t *testing.T) {
	policy := DefaultRelayPolicy{}
	state := RelayState{
		Descriptor: mustPolicyRelayDescriptor(t, "relay-hinted", "https://relay-hinted.example"),
		LastSeenAt: time.Now().UTC(),
	}
	startedAt := time.Now().UTC()

	for range defaultRecoveryFailures {
		state, _, _ = policy.OnFailure(state, errors.New("boom"), defaultRecoveryFailures)
	}

	if !state.nextDirectRefreshAt.After(startedAt) {
		t.Fatalf("nextDirectRefreshAt = %v, want a future retry time", state.nextDirectRefreshAt)
	}
}
