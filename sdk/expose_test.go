package sdk

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
)

func mustRelaySet(t *testing.T, relayURLs ...string) *discovery.RelaySet {
	t.Helper()
	return discovery.NewRelaySet(relayURLs)
}

func TestExposureReconcileRemovesBannedRelayFromActiveSet(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)

	relayURL, err := url.Parse(relayA)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	relayBURL, err := url.Parse(relayB)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	exposure := &Exposure{
		explicitRelays: []string{relayA, relayB},
		relaySet:       mustRelaySet(t, relayA, relayB),
		relayListeners: make(map[string]*listener, 2),
	}
	relayAClosed := make(chan struct{})
	exposure.relayListeners = map[string]*listener{
		relayA: {
			relayURL: relayURL,
			cancel:   func() { close(relayAClosed) },
			doneCh:   relayAClosed,
		},
		relayB: {
			relayURL: relayBURL,
		},
	}

	exposure.relaySet.BanRelayURL(relayA)
	if err := exposure.reconcileRelayListeners(false); err != nil {
		t.Fatalf("reconcileRelayListeners() error = %v", err)
	}

	select {
	case <-relayAClosed:
	default:
		t.Fatal("banned relay listener was not closed")
	}

	if got := exposure.ActiveRelayURLs(); len(got) != 1 || got[0] != relayB {
		t.Fatalf("ActiveRelayURLs() = %v, want [%q]", got, relayB)
	}

	exposure.listenerMu.RLock()
	_, listenerExists := exposure.relayListeners[relayA]
	exposure.listenerMu.RUnlock()
	if listenerExists {
		t.Fatal("banned relay listener still exists in exposure.listeners")
	}
}

func TestExposureReconcileRemovesStaleListener(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)

	relayAURL, err := url.Parse(relayA)
	if err != nil {
		t.Fatalf("url.Parse(relayA) error = %v", err)
	}
	relayBURL, err := url.Parse(relayB)
	if err != nil {
		t.Fatalf("url.Parse(relayB) error = %v", err)
	}

	relayAClosed := make(chan struct{})
	exposure := &Exposure{
		explicitRelays: []string{relayA, relayB},
		relaySet:       mustRelaySet(t, relayA, relayB),
		relayListeners: make(map[string]*listener, 2),
	}
	exposure.relayListeners = map[string]*listener{
		relayA: {
			relayURL: relayAURL,
			cancel:   func() { close(relayAClosed) },
			doneCh:   relayAClosed,
		},
		relayB: {
			relayURL: relayBURL,
		},
	}

	exposure.relaySet.SetBootstrapRelayURLs([]string{relayB})
	if err := exposure.reconcileRelayListeners(false); err != nil {
		t.Fatalf("reconcileRelayListeners() error = %v", err)
	}

	select {
	case <-relayAClosed:
	default:
		t.Fatal("stale relay listener was not closed")
	}

	knownRelayURLs := exposure.ActiveRelayURLs()
	exposure.listenerMu.RLock()
	_, relayAExists := exposure.relayListeners[relayA]
	_, relayBExists := exposure.relayListeners[relayB]
	exposure.listenerMu.RUnlock()
	if len(knownRelayURLs) != 1 || knownRelayURLs[0] != relayB {
		t.Fatalf("knownRelayURLs = %v, want [%q]", knownRelayURLs, relayB)
	}
	if relayAExists {
		t.Fatal("stale relay listener still exists in exposure.listeners")
	}
	if !relayBExists {
		t.Fatal("active relay listener missing from exposure.listeners")
	}
}

func TestValidatePepperMode(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"", "passive", "active"} {
		if err := ValidatePepperMode(mode); err != nil {
			t.Fatalf("ValidatePepperMode(%q) error = %v", mode, err)
		}
	}

	if err := ValidatePepperMode("invalid"); err == nil {
		t.Fatal("expected invalid pepper mode to fail")
	}
}

func TestExposeRejectsPepperWithoutMultiHop(t *testing.T) {
	t.Parallel()

	_, err := Expose(context.Background(), ExposeConfig{
		RelayURLs:    []string{"https://relay.example"},
		TargetAddr:   "127.0.0.1:3000",
		Name:         "app",
		PepperMode:   PepperModePassive,
		IdentityJSON: `{"private_key":"0x59c6995e998f97a5a004497e5d7f4b04d7f1fa1d2d9ff6d72663218b8ba11b58","address":"0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf","name":"app"}`,
	})
	if err == nil || !strings.Contains(err.Error(), "pepper requires --multi-hop or --multi-hop-depth 2+") {
		t.Fatalf("Expose() error = %v, want pepper multi-hop validation", err)
	}
}

func TestExposeRejectsPepperActiveMode(t *testing.T) {
	t.Parallel()

	_, err := Expose(context.Background(), ExposeConfig{
		RelayURLs:    []string{"https://relay-a.example"},
		TargetAddr:   "127.0.0.1:3000",
		Name:         "app",
		MultiHop:     []string{"https://relay-a.example", "https://relay-b.example"},
		PepperMode:   PepperModeActive,
		IdentityJSON: `{"private_key":"0x59c6995e998f97a5a004497e5d7f4b04d7f1fa1d2d9ff6d72663218b8ba11b58","address":"0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf","name":"app"}`,
	})
	if err == nil || !strings.Contains(err.Error(), "pepper active mode is not implemented yet") {
		t.Fatalf("Expose() error = %v, want active mode validation", err)
	}
}
