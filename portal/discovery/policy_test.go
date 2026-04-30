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

func confirmedPolicyRelayState(t *testing.T, relayURL string) RelayState {
	t.Helper()

	return RelayState{
		Descriptor: mustPolicyRelayDescriptor(t, relayURL),
		Confirmed:  true,
		LastSeenAt: time.Now().UTC(),
	}
}

func TestOnActiveConfirmedResetsActiveFailures(t *testing.T) {
	lc := NewLifecycle()
	state := RelayState{
		activeFailures:      5,
		suppressActiveUntil: time.Now().UTC().Add(time.Minute),
		Confirmed:           false,
	}

	state = lc.OnActiveConfirmed(state)

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
	lc := NewLifecycle()
	state := confirmedPolicyRelayState(t, "https://error.io")
	budget := 3

	start := time.Now()
	for i := 0; i < budget; i++ {
		var backed bool
		state, backed, _ = lc.OnDiscoveryFailure(state, errors.New("err"), budget)
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
	lc := NewLifecycle()
	state := confirmedPolicyRelayState(t, "https://error.io")
	start := time.Now()

	var backed bool
	state, backed, _ = lc.OnActiveFailure(state, errors.New("err"), 1)
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
