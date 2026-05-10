package sdk

import (
	"context"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/pepper"
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

func TestExposeRejectsPepperActiveStaticPath(t *testing.T) {
	t.Parallel()

	_, err := Expose(context.Background(), ExposeConfig{
		RelayURLs:    []string{"https://relay-a.example"},
		TargetAddr:   "127.0.0.1:3000",
		Name:         "app",
		MultiHop:     []string{"https://relay-a.example", "https://relay-b.example"},
		PepperMode:   PepperModeActive,
		IdentityJSON: `{"private_key":"0x59c6995e998f97a5a004497e5d7f4b04d7f1fa1d2d9ff6d72663218b8ba11b58","address":"0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf","name":"app"}`,
	})
	if err == nil || !strings.Contains(err.Error(), "ERR_PEPPER_STATIC_ENTRY") {
		t.Fatalf("Expose() error = %v, want active static entry validation", err)
	}
}

func TestExposeRejectsPepperActiveStaticIdentity(t *testing.T) {
	t.Parallel()

	_, err := Expose(context.Background(), ExposeConfig{
		RelayURLs:     []string{"https://relay-a.example"},
		TargetAddr:    "127.0.0.1:3000",
		Name:          "app",
		Discovery:     true,
		MultiHopDepth: 2,
		PepperMode:    PepperModeActive,
		IdentityJSON:  `{"private_key":"0x59c6995e998f97a5a004497e5d7f4b04d7f1fa1d2d9ff6d72663218b8ba11b58","address":"0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf","name":"app"}`,
	})
	if err == nil || !strings.Contains(err.Error(), "ERR_PEPPER_STATIC_IDENTITY") {
		t.Fatalf("Expose() error = %v, want active static identity validation", err)
	}
}

func TestActiveCircuitResetRotatesCircuitWithoutClosingExposure(t *testing.T) {
	exposure := &Exposure{
		done:           make(chan struct{}),
		pepperMode:     PepperModeActive,
		multiHopDepth:  2,
		relaySet:       mustRelaySet(t, "https://relay-a.example", "https://relay-b.example"),
		relayListeners: make(map[string]*listener),
	}
	if err := exposure.establishActiveCircuit(false); err != nil {
		t.Fatalf("establish active circuit: %v", err)
	}
	firstID, firstKey, firstPublic, ok := exposure.activeCircuitSnapshot()
	if !ok {
		t.Fatal("active circuit missing")
	}
	defer pepper.Zero(firstKey)

	exposure.resetActiveCircuit(nil)
	secondID, secondKey, secondPublic, ok := exposure.activeCircuitSnapshot()
	if !ok {
		t.Fatal("active circuit missing after reset")
	}
	defer pepper.Zero(secondKey)

	if firstID == secondID {
		t.Fatal("circuit id did not rotate")
	}
	if firstPublic == secondPublic {
		t.Fatal("x25519 public key did not rotate")
	}
	if string(firstKey) == string(secondKey) {
		t.Fatal("session key did not rotate")
	}
	select {
	case <-exposure.done:
		t.Fatal("active reset closed exposure")
	default:
	}

	if err := exposure.Close(); err != nil {
		t.Fatalf("close exposure: %v", err)
	}
}

func TestActiveBlocksAcceptDuringReset(t *testing.T) {
	done := make(chan struct{})
	exposure := &Exposure{
		done:           done,
		pepperMode:     PepperModeActive,
		accepted:       make(chan net.Conn, 1),
		relayListeners: make(map[string]*listener),
	}
	exposure.activeMu.Lock()
	exposure.activeResetting = true
	exposure.activeMu.Unlock()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	exposure.accepted <- left

	errCh := make(chan error, 1)
	go func() {
		_, err := exposure.Accept()
		errCh <- err
	}()

	select {
	case err := <-errCh:
		t.Fatalf("Accept returned while active circuit was resetting: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(done)
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Accept returned nil error after close")
		}
	case <-time.After(time.Second):
		t.Fatal("Accept did not unblock after exposure close")
	}
	relays := exposure.relaySet.AllRelays()
	if len(relays) != 1 || relays[0].Descriptor.APIHTTPSAddr != relayA || relays[0].Banned {
		t.Fatalf("AllRelays() = %+v, want unbanned candidate %q", relays, relayA)
	}
}
