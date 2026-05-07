package discovery

import (
	"errors"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func mustPolicyRelayDescriptor(t *testing.T, relayURL string) types.RelayDescriptor {
	t.Helper()

	signing, err := utils.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("ResolveSecp256k1Identity() error = %v", err)
	}
	now := time.Now().UTC()
	signed, err := auth.SignRelayDescriptor(types.RelayDescriptor{
		Address:      signing.Address,
		Version:      types.DiscoveryVersion,
		IssuedAt:     now,
		ExpiresAt:    now.Add(time.Hour),
		APIHTTPSAddr: relayURL,
	}, signing.PrivateKey)
	if err != nil {
		t.Fatalf("SignRelayDescriptor() error = %v", err)
	}
	return signed
}

func bootstrapPolicyRelayState(relayURL string) RelayState {
	return RelayState{
		Descriptor: types.RelayDescriptor{
			APIHTTPSAddr: relayURL,
		},
		Bootstrap: true,
	}
}

func confirmedPolicyRelayState(t *testing.T, relayURL string) RelayState {
	t.Helper()

	return RelayState{
		Descriptor: mustPolicyRelayDescriptor(t, relayURL),
		Confirmed:  true,
		LastSeenAt: time.Now().UTC(),
	}
}

func confirmedPolicyRelayStateWithRTT(t *testing.T, relayURL string, rtt time.Duration) RelayState {
	t.Helper()

	state := confirmedPolicyRelayState(t, relayURL)
	state.DiscoveryRTT = rtt
	state.DiscoveryRTTAt = time.Now().UTC()
	return state
}

func TestSelectPriorityMathematicalOrdering(t *testing.T) {
	policy := MOLSRelayPolicy{}
	clientAddr := "192.168.0.10"
	ingressIdx := hashToGF64(clientAddr)

	relays := []string{
		"https://relay-alpha.io",
		"https://relay-beta.io",
		"https://relay-gamma.io",
	}

	var states []RelayState
	for _, url := range relays {
		states = append(states, confirmedPolicyRelayState(t, url))
	}

	selected := policy.SelectPriority(states, ClientState{LocalAddress: clientAddr})

	for i := 0; i < len(selected)-1; i++ {
		scoreA := molsScore(int(ingressIdx), int(hashToGF64(selected[i])), int(molsBaseM1), int(molsBaseM2), 64)
		scoreB := molsScore(int(ingressIdx), int(hashToGF64(selected[i+1])), int(molsBaseM1), int(molsBaseM2), 64)
		if scoreA < scoreB {
			t.Errorf("Priority mismatch at index %d: %d < %d", i, scoreA, scoreB)
		}
	}
}

func TestSelectPriorityKeepsExplicitRelaysOutsideAutoLimit(t *testing.T) {
	policy := MOLSRelayPolicy{}
	explicitRelay := "https://relay-explicit.example"
	relayA := "https://relay-a.example"
	relayB := "https://relay-b.example"

	selected := policy.SelectPriority([]RelayState{
		bootstrapPolicyRelayState(explicitRelay),
		confirmedPolicyRelayState(t, relayA),
		confirmedPolicyRelayState(t, relayB),
	}, ClientState{
		LocalAddress:      "127.0.0.1",
		ExplicitRelayURLs: []string{explicitRelay},
		MaxActiveRelays:   1,
	})

	if len(selected) < 2 {
		t.Fatalf("len(selected) = %d, want at least 2", len(selected))
	}
	if selected[0] != explicitRelay {
		t.Fatalf("selected[0] = %q, want %q", selected[0], explicitRelay)
	}
}

func TestSelectPriorityCongestionInversion(t *testing.T) {
	policy := MOLSRelayPolicy{}
	clientAddr := "10.0.0.1"
	ingressIdx := hashToGF64(clientAddr)

	r1, r2 := "https://r1.net", "https://r2.net"
	states := []RelayState{
		confirmedPolicyRelayStateWithRTT(t, r1, 800*time.Millisecond),
		confirmedPolicyRelayStateWithRTT(t, r2, 800*time.Millisecond),
	}

	selected := policy.SelectPriority(states, ClientState{LocalAddress: clientAddr})

	if len(selected) == 2 {
		s1 := molsCongestionScore(int(ingressIdx), int(hashToGF64(selected[0])), int(molsBaseM1), int(molsBaseM2), 64)
		s2 := molsCongestionScore(int(ingressIdx), int(hashToGF64(selected[1])), int(molsBaseM1), int(molsBaseM2), 64)
		if s1 < s2 {
			t.Errorf("Congestion priority failed: %d < %d", s1, s2)
		}
	}
}

func TestSelectAggregateKeepsBootstrapRelayWhenDescriptorExpired(t *testing.T) {
	policy := MOLSRelayPolicy{}
	relayURL := "https://relay-bootstrap.example"

	state := bootstrapPolicyRelayState(relayURL)
	state.LastSeenAt = time.Now().UTC().Add(-time.Minute)
	state.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Second)

	selected := policy.SelectAggregate([]RelayState{state})

	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d, want 1", len(selected))
	}
	if got := selected[0].Descriptor.APIHTTPSAddr; got != relayURL {
		t.Fatalf("selected[0] = %q, want %q", got, relayURL)
	}
}

func TestSelectPriorityFallbackPromotion(t *testing.T) {
	policy := MOLSRelayPolicy{}
	states := []RelayState{
		confirmedPolicyRelayStateWithRTT(t, "https://f1.com", 3*time.Second),
		confirmedPolicyRelayStateWithRTT(t, "https://f2.com", 4*time.Second),
	}

	selected := policy.SelectPriority(states, ClientState{LocalAddress: "1.1.1.1"})

	if len(selected) < molsMinActiveNodes {
		t.Errorf("Fallback promotion failed: got %d, want %d", len(selected), molsMinActiveNodes)
	}
}

func TestOnActiveConfirmedResetsActiveFailures(t *testing.T) {
	policy := MOLSRelayPolicy{}
	state := RelayState{
		activeFailures:      5,
		suppressActiveUntil: time.Now().UTC().Add(time.Minute),
		Confirmed:           false,
	}

	state = policy.OnActiveConfirmed(state)

	if !state.Confirmed {
		t.Fatal("Confirmed should be true")
	}
	if state.activeFailures != 0 {
		t.Errorf("activeFailures = %d, want 0", state.activeFailures)
	}
	if !state.suppressActiveUntil.IsZero() {
		t.Errorf("suppressActiveUntil = %v, want zero", state.suppressActiveUntil)
	}
}

func TestOnDiscoveryFailureBackoff(t *testing.T) {
	policy := MOLSRelayPolicy{}
	state := confirmedPolicyRelayState(t, "https://error.io")
	budget := 3

	start := time.Now()
	for i := 0; i < budget; i++ {
		var backed bool
		state, backed, _ = policy.OnDiscoveryFailure(state, errors.New("err"), budget)
		if i < budget-1 && backed {
			t.Fatal("Premature backoff")
		}
	}

	if !state.nextDiscoveryRefreshAt.After(start) {
		t.Fatal("discovery retry timer not scheduled")
	}
	if !state.suppressActiveUntil.IsZero() {
		t.Fatalf("suppressActiveUntil = %v, want zero", state.suppressActiveUntil)
	}
}

func TestOnActiveFailureBackoff(t *testing.T) {
	policy := MOLSRelayPolicy{}
	state := confirmedPolicyRelayState(t, "https://error.io")
	start := time.Now()

	var backed bool
	state, backed, _ = policy.OnActiveFailure(state, errors.New("err"), 1)
	if !backed {
		t.Fatal("active failure should back off at budget")
	}
	if !state.suppressActiveUntil.After(start) {
		t.Fatal("active suppression timer not scheduled")
	}
	if !state.nextDiscoveryRefreshAt.IsZero() {
		t.Fatalf("nextDiscoveryRefreshAt = %v, want zero", state.nextDiscoveryRefreshAt)
	}
}
