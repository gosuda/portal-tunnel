package policy

import (
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/mols"
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

func bootstrapPolicyRelayState(relayURL string) discovery.RelayState {
	return discovery.RelayState{
		Descriptor: types.RelayDescriptor{
			APIHTTPSAddr: relayURL,
		},
		Bootstrap: true,
	}
}

func confirmedPolicyRelayState(t *testing.T, relayURL string) discovery.RelayState {
	t.Helper()

	return discovery.RelayState{
		Descriptor: mustPolicyRelayDescriptor(t, relayURL),
		Confirmed:  true,
		LastSeenAt: time.Now().UTC(),
	}
}

func confirmedPolicyRelayStateWithRTT(t *testing.T, relayURL string, rtt time.Duration) discovery.RelayState {
	t.Helper()

	state := confirmedPolicyRelayState(t, relayURL)
	state.DiscoveryRTT = rtt
	state.DiscoveryRTTAt = time.Now().UTC()
	return state
}

func TestMOLSSelectPriorityKeepsExplicitRelaysOutsideAutoLimit(t *testing.T) {
	policy := NewMOLSRelayPolicy(mols.DefaultConfig(), nil)
	explicitRelay := "https://relay-explicit.example"
	relayA := "https://relay-a.example"
	relayB := "https://relay-b.example"

	selected := policy.SelectPriority([]discovery.RelayState{
		bootstrapPolicyRelayState(explicitRelay),
		confirmedPolicyRelayState(t, relayA),
		confirmedPolicyRelayState(t, relayB),
	}, discovery.ClientState{
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

func TestMOLSSelectAggregateKeepsBootstrapRelayWhenDescriptorExpired(t *testing.T) {
	policy := NewMOLSRelayPolicy(mols.DefaultConfig(), nil)
	relayURL := "https://relay-bootstrap.example"

	state := bootstrapPolicyRelayState(relayURL)
	state.LastSeenAt = time.Now().UTC().Add(-time.Minute)
	state.Descriptor.ExpiresAt = time.Now().UTC().Add(-time.Second)

	selected := policy.SelectAggregate([]discovery.RelayState{state})

	if len(selected) != 1 {
		t.Fatalf("len(selected) = %d, want 1", len(selected))
	}
	if got := selected[0].Descriptor.APIHTTPSAddr; got != relayURL {
		t.Fatalf("selected[0] = %q, want %q", got, relayURL)
	}
}

func TestMOLSSelectPriorityFallbackPromotion(t *testing.T) {
	policy := NewMOLSRelayPolicy(mols.DefaultConfig(), nil)
	states := []discovery.RelayState{
		confirmedPolicyRelayStateWithRTT(t, "https://f1.com", 3*time.Second),
		confirmedPolicyRelayStateWithRTT(t, "https://f2.com", 4*time.Second),
	}

	selected := policy.SelectPriority(states, discovery.ClientState{LocalAddress: "1.1.1.1"})

	if len(selected) < mols.DefaultMinActiveNodes {
		t.Errorf("Fallback promotion failed: got %d, want %d", len(selected), mols.DefaultMinActiveNodes)
	}
}
