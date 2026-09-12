package sdk

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/internal/discovery"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// newTestExposure creates an Exposure with canonical state fields initialized
// for unit testing without starting real listeners.
func newTestExposure(t *testing.T, cfg ExposeConfig, relayURLs ...string) *Exposure {
	t.Helper()
	exposure := &Exposure{
		cfg:            utils.NewSnapshot(cfg, ExposeConfig.snapshot),
		relaySet:       discovery.NewRelaySet(relayURLs),
		relayListeners: make(map[string]*listener),
		relayStates:    make(map[string]*relayRuntimeState),
		notifyCh:       make(chan struct{}),
		updatesSubs:    make(map[chan RelayUpdate]struct{}),
		done:           make(chan struct{}),
	}
	return exposure
}

func TestRelaysReturnsCanonicalState(t *testing.T) {
	exposure := newTestExposure(t, ExposeConfig{RelayURLs: []string{"https://relay-a.example"}})

	exposure.emitRelayEvent("https://relay-a.example", RelayStateReady, "https://app.example", nil, "", false, "v1.0", true)

	relays := exposure.Relays()
	if len(relays) != 1 {
		t.Fatalf("Relays() = %d relays, want 1", len(relays))
	}
	r := relays[0]
	if r.RelayURL != "https://relay-a.example" {
		t.Fatalf("RelayURL = %q, want %q", r.RelayURL, "https://relay-a.example")
	}
	if r.State != RelayStateReady {
		t.Fatalf("State = %q, want %q", r.State, RelayStateReady)
	}
	if r.PublicURL != "https://app.example" {
		t.Fatalf("PublicURL = %q, want %q", r.PublicURL, "https://app.example")
	}
	if r.Version != "v1.0" {
		t.Fatalf("Version = %q, want %q", r.Version, "v1.0")
	}
	if !r.Explicit {
		t.Fatal("Explicit = false, want true")
	}
}

func TestRelaysPreservesTerminalFailure(t *testing.T) {
	exposure := newTestExposure(t, ExposeConfig{RelayURLs: []string{"https://relay-a.example"}})

	relayErr := errors.New("hostname conflict")
	exposure.emitRelayEvent("https://relay-a.example", RelayStateFailed, "", relayErr, "", false, "", true)

	relays := exposure.Relays()
	if len(relays) != 1 {
		t.Fatalf("Relays() = %d relays, want 1", len(relays))
	}
	r := relays[0]
	if r.State != RelayStateFailed {
		t.Fatalf("State = %q, want %q", r.State, RelayStateFailed)
	}
	if r.Error != relayErr.Error() {
		t.Fatalf("Error = %q, want %q", r.Error, relayErr.Error())
	}
	if r.PublicURL != "" {
		t.Fatalf("PublicURL = %q, want empty", r.PublicURL)
	}
}

func TestRelaysIndependentRelayFailure(t *testing.T) {
	exposure := newTestExposure(t, ExposeConfig{RelayURLs: []string{"https://relay-a.example", "https://relay-b.example"}})

	exposure.emitRelayEvent("https://relay-a.example", RelayStateReady, "https://app-a.example", nil, "", false, "v1", true)
	exposure.emitRelayEvent("https://relay-b.example", RelayStateFailed, "", errors.New("banned"), "", false, "", true)

	relays := exposure.Relays()
	if len(relays) != 2 {
		t.Fatalf("Relays() = %d relays, want 2", len(relays))
	}

	relayByURL := make(map[string]RelayStatus, len(relays))
	for _, r := range relays {
		relayByURL[r.RelayURL] = r
	}

	relayA := relayByURL["https://relay-a.example"]
	if relayA.State != RelayStateReady {
		t.Fatalf("relay-a State = %q, want %q", relayA.State, RelayStateReady)
	}
	if relayA.PublicURL != "https://app-a.example" {
		t.Fatalf("relay-a PublicURL = %q, want %q", relayA.PublicURL, "https://app-a.example")
	}

	relayB := relayByURL["https://relay-b.example"]
	if relayB.State != RelayStateFailed {
		t.Fatalf("relay-b State = %q, want %q", relayB.State, RelayStateFailed)
	}
	if relayB.Error != "banned" {
		t.Fatalf("relay-b Error = %q, want %q", relayB.Error, "banned")
	}
}

func TestWaitReadyReturnsWhenRelayBecomesReady(t *testing.T) {
	exposure := newTestExposure(t, ExposeConfig{RelayURLs: []string{"https://relay-a.example"}})

	exposure.emitRelayEvent("https://relay-a.example", RelayStatePending, "", nil, "", false, "", true)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- exposure.WaitReady(ctx)
	}()

	// Simulate the relay becoming ready after a short delay.
	go func() {
		time.Sleep(50 * time.Millisecond)
		exposure.emitRelayEvent("https://relay-a.example", RelayStateReady, "https://app.example", nil, "", false, "", true)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("WaitReady() error = %v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WaitReady() timed out")
	}
}

func TestWaitReadyReturnsErrNoRelaysWhenAllFailedNoDiscovery(t *testing.T) {
	exposure := newTestExposure(t, ExposeConfig{RelayURLs: []string{"https://relay-a.example"}, Discovery: false})

	exposure.emitRelayEvent("https://relay-a.example", RelayStateFailed, "", errors.New("banned"), "", false, "", true)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := exposure.WaitReady(ctx)
	if !errors.Is(err, ErrNoRelays) {
		t.Fatalf("WaitReady() error = %v, want ErrNoRelays", err)
	}
}

func TestWaitReadyWaitsWhenDiscoveryEnabled(t *testing.T) {
	exposure := newTestExposure(t, ExposeConfig{RelayURLs: []string{"https://relay-a.example"}, Discovery: true})

	exposure.emitRelayEvent("https://relay-a.example", RelayStateFailed, "", errors.New("banned"), "", false, "", true)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := exposure.WaitReady(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitReady() error = %v, want context.DeadlineExceeded", err)
	}
}

func TestWaitReadyReturnsErrNoRelaysWhenNoRelaysNoDiscovery(t *testing.T) {
	exposure := newTestExposure(t, ExposeConfig{Discovery: false})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := exposure.WaitReady(ctx)
	if !errors.Is(err, ErrNoRelays) {
		t.Fatalf("WaitReady() error = %v, want ErrNoRelays", err)
	}
}

func TestWaitDatagramReadyReturnsAddresses(t *testing.T) {
	exposure := newTestExposeWithDone(t, ExposeConfig{UDPEnabled: true, RelayURLs: []string{"https://relay-a.example"}})

	exposure.emitRelayEvent("https://relay-a.example", RelayStateDatagramReady, "https://app.example", nil, "1.2.3.4:5678", true, "", true)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	addrs, err := exposure.WaitDatagramReady(ctx)
	if err != nil {
		t.Fatalf("WaitDatagramReady() error = %v, want nil", err)
	}
	if len(addrs) != 1 || addrs[0] != "1.2.3.4:5678" {
		t.Fatalf("WaitDatagramReady() = %v, want [1.2.3.4:5678]", addrs)
	}
}

func TestWaitDatagramReadyEventDriven(t *testing.T) {
	exposure := newTestExposure(t, ExposeConfig{UDPEnabled: true, RelayURLs: []string{"https://relay-a.example"}})

	exposure.emitRelayEvent("https://relay-a.example", RelayStateReady, "https://app.example", nil, "1.2.3.4:5678", false, "", true)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	addrCh := make(chan []string, 1)
	go func() {
		addrs, err := exposure.WaitDatagramReady(ctx)
		errCh <- err
		addrCh <- addrs
	}()

	// Simulate the datagram backhaul connecting after a short delay.
	go func() {
		time.Sleep(50 * time.Millisecond)
		exposure.emitRelayEvent("https://relay-a.example", RelayStateDatagramReady, "https://app.example", nil, "1.2.3.4:5678", true, "", true)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("WaitDatagramReady() error = %v, want nil", err)
		}
		addrs := <-addrCh
		if len(addrs) != 1 || addrs[0] != "1.2.3.4:5678" {
			t.Fatalf("WaitDatagramReady() = %v, want [1.2.3.4:5678]", addrs)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WaitDatagramReady() timed out")
	}
}

func TestWaitDatagramReadyReturnsErrorWhenNoUDP(t *testing.T) {
	exposure := newTestExposure(t, ExposeConfig{UDPEnabled: true, RelayURLs: []string{"https://relay-a.example"}, Discovery: false})

	// Relay is ready but has no UDP address.
	exposure.emitRelayEvent("https://relay-a.example", RelayStateReady, "https://app.example", nil, "", false, "", true)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	addrs, err := exposure.WaitDatagramReady(ctx)
	if err == nil {
		t.Fatalf("WaitDatagramReady() error = nil, want error; addrs=%v", addrs)
	}
	if !strings.Contains(err.Error(), "did not expose udp") && !errors.Is(err, ErrNoRelays) {
		t.Fatalf("WaitDatagramReady() error = %v, want 'did not expose udp' or ErrNoRelays", err)
	}
}

func TestUpdatesReceivesEvents(t *testing.T) {
	exposure := newTestExposure(t, ExposeConfig{RelayURLs: []string{"https://relay-a.example"}})

	updates := exposure.Updates()

	exposure.emitRelayEvent("https://relay-a.example", RelayStatePending, "", nil, "", false, "", true)

	select {
	case update := <-updates:
		if update.RelayURL != "https://relay-a.example" {
			t.Fatalf("update.RelayURL = %q, want %q", update.RelayURL, "https://relay-a.example")
		}
		if update.State != RelayStatePending {
			t.Fatalf("update.State = %q, want %q", update.State, RelayStatePending)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive update event")
	}

	exposure.emitRelayEvent("https://relay-a.example", RelayStateReady, "https://app.example", nil, "", false, "", true)

	select {
	case update := <-updates:
		if update.State != RelayStateReady {
			t.Fatalf("update.State = %q, want %q", update.State, RelayStateReady)
		}
		if update.PublicURL != "https://app.example" {
			t.Fatalf("update.PublicURL = %q, want %q", update.PublicURL, "https://app.example")
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive ready update event")
	}
}

func TestUpdatesReceivesFailureEvent(t *testing.T) {
	exposure := newTestExposure(t, ExposeConfig{RelayURLs: []string{"https://relay-a.example"}})

	updates := exposure.Updates()

	relayErr := errors.New("hostname conflict")
	exposure.emitRelayEvent("https://relay-a.example", RelayStateFailed, "", relayErr, "", false, "", true)

	select {
	case update := <-updates:
		if update.State != RelayStateFailed {
			t.Fatalf("update.State = %q, want %q", update.State, RelayStateFailed)
		}
		if update.Error != relayErr.Error() {
			t.Fatalf("update.Error = %q, want %q", update.Error, relayErr.Error())
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive failure update event")
	}
}

func TestSnapshotConsumesCanonicalState(t *testing.T) {
	exposure := newTestExposure(t, ExposeConfig{
		RelayURLs: []string{"https://relay-a.example"},
	})

	exposure.emitRelayEvent("https://relay-a.example", RelayStateReady, "https://app.example", nil, "", false, "v2.0", true)

	snap := exposure.Snapshot()
	if len(snap.Relays) != 1 {
		t.Fatalf("Snapshot().Relays = %d, want 1", len(snap.Relays))
	}
	r := snap.Relays[0]
	if r.State != string(RelayStateReady) {
		t.Fatalf("State = %q, want %q", r.State, RelayStateReady)
	}
	if r.PublicURL != "https://app.example" {
		t.Fatalf("PublicURL = %q, want %q", r.PublicURL, "https://app.example")
	}
}

func TestEmitRelayEventDoesNotInferReadinessFromPublicURL(t *testing.T) {
	exposure := newTestExposure(t, ExposeConfig{RelayURLs: []string{"https://relay-a.example"}})

	// A relay in pending state with a non-empty public URL should still be pending.
	exposure.emitRelayEvent("https://relay-a.example", RelayStatePending, "https://should-not-happen.example", nil, "", false, "", true)

	relays := exposure.Relays()
	if len(relays) != 1 {
		t.Fatalf("Relays() = %d relays, want 1", len(relays))
	}
	if relays[0].State != RelayStatePending {
		t.Fatalf("State = %q, want %q", relays[0].State, RelayStatePending)
	}
}

func TestWaitReadyReturnsNetErrClosedWhenExposureClosed(t *testing.T) {
	done := make(chan struct{})
	close(done)
	exposure := &Exposure{
		cfg:         utils.NewSnapshot(ExposeConfig{RelayURLs: []string{"https://relay-a.example"}}, ExposeConfig.snapshot),
		relayStates: make(map[string]*relayRuntimeState),
		notifyCh:    make(chan struct{}),
		updatesSubs: make(map[chan RelayUpdate]struct{}),
		done:        done,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := exposure.WaitReady(ctx)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WaitReady() error = %v, want net.ErrClosed", err)
	}
}

// newTestExposureWithDone is an alias for clarity in tests that need a
// non-closed done channel.
func newTestExposeWithDone(t *testing.T, cfg ExposeConfig, relayURLs ...string) *Exposure {
	return newTestExposure(t, cfg, relayURLs...)
}
