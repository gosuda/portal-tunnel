package sdk

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func newExposureStateTest(t *testing.T, relayURLs ...string) *Exposure {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	exposure := &Exposure{
		cancel:         cancel,
		done:           ctx.Done(),
		relayURLs:      append([]string(nil), relayURLs...),
		metadata:       utils.NewSnapshot(types.LeaseMetadata{}, types.LeaseMetadata.Copy),
		accepted:       make(chan net.Conn, 2),
		relayListeners: make(map[string]*listener),
		statuses:       make(map[string]RelayStatus),
		stateChanged:   make(chan struct{}),
		updates:        make(chan RelayStatus, 1),
	}
	t.Cleanup(func() { _ = exposure.Close() })
	return exposure
}

func TestExposureWaitReadyUsesRelayStatus(t *testing.T) {
	const relayURL = "https://relay.example"
	exposure := newExposureStateTest(t, relayURL)
	exposure.setRelayStatus(relayURL, listenerStatus{
		state:     RelayReady,
		publicURL: "https://service.relay.example",
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ready, err := exposure.WaitReady(ctx)
	if err != nil {
		t.Fatalf("WaitReady() error = %v", err)
	}
	if len(ready) != 1 || ready[0].RelayURL != relayURL || ready[0].State != RelayReady {
		t.Fatalf("WaitReady() = %+v, want ready relay %q", ready, relayURL)
	}
}

func TestPublicURLForLeaseUsesCanonicalRelayPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		relayURL string
		want     string
	}{
		{"default HTTPS port", "https://relay.example.com", "https://demo.relay.example.com"},
		{"explicit default port", "https://relay.example.com:443", "https://demo.relay.example.com:443"},
		{"explicit public port", "https://relay.example.com:9443", "https://demo.relay.example.com:9443"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			relayURL, err := url.Parse(tc.relayURL)
			if err != nil {
				t.Fatal(err)
			}
			l := &listener{relayURL: relayURL}
			got := l.publicURLForLease(listenerSnapshot{
				hostname:   "demo.relay.example.com",
				publicPort: 8443,
			})
			if got != tc.want {
				t.Fatalf("publicURLForLease() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestListenerReverseSessionReadinessTracksLiveSessions(t *testing.T) {
	var states []RelayState
	l := &listener{
		status: func(status listenerStatus) {
			states = append(states, status.state)
		},
		lease: utils.NewSnapshot(listenerSnapshot{
			accessToken: "token",
			hostname:    "service.relay.example",
		}, listenerSnapshot.snapshot),
	}

	l.reportStreamReady()
	l.reportStreamReady()
	if got := l.readySessions.Load(); got != 2 {
		t.Fatalf("ready session count = %d, want 2", got)
	}
	if got := states[len(states)-1]; got != RelayReady {
		t.Fatalf("state after opening sessions = %q, want %q", got, RelayReady)
	}

	l.reportStreamClosed()
	if got := l.readySessions.Load(); got != 1 {
		t.Fatalf("ready session count after one close = %d, want 1", got)
	}
	if got := states[len(states)-1]; got != RelayReady {
		t.Fatalf("state with one live session = %q, want %q", got, RelayReady)
	}

	l.reportStreamClosed()
	if got := l.readySessions.Load(); got != 0 {
		t.Fatalf("ready session count after final close = %d, want 0", got)
	}
	if got := states[len(states)-1]; got != RelayConnecting {
		t.Fatalf("state after final close = %q, want %q", got, RelayConnecting)
	}
}

func TestExposureAcceptWaitsAfterTerminalFailures(t *testing.T) {
	const relayURL = "https://relay.example"
	exposure := newExposureStateTest(t, relayURL)
	exposure.setRelayStatus(relayURL, listenerStatus{state: RelayFailed, err: errors.New("rejected")})

	result := make(chan error, 1)
	go func() {
		_, err := exposure.Accept()
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("Accept() returned before Close: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if err := exposure.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-result; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept() error after Close = %v, want net.ErrClosed", err)
	}
}

func TestExposureAcceptDrainsQueuedConnectionBeforeNoRelays(t *testing.T) {
	const relayURL = "https://relay.example"
	exposure := newExposureStateTest(t, relayURL)
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	exposure.accepted <- server
	exposure.setRelayStatus(relayURL, listenerStatus{state: RelayFailed, err: errors.New("rejected")})

	conn, err := exposure.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v, want queued connection", err)
	}
	_ = conn.Close()
}

func TestExposeRejectsIncompleteIdentity(t *testing.T) {
	_, err := Expose(context.Background(), types.Identity{Name: "svc"}, []string{"https://relay.example"})
	if err == nil || !strings.Contains(err.Error(), "identity must include") {
		t.Fatalf("Expose() error = %v, want incomplete identity error", err)
	}
}

func TestExposeRejectsEmptyInitialRelays(t *testing.T) {
	identity := types.Identity{
		Name:       "svc",
		Address:    "address",
		PublicKey:  "public",
		PrivateKey: "private",
	}
	for _, relays := range [][]string{nil, {}} {
		_, err := Expose(context.Background(), identity, relays)
		if err == nil || !strings.Contains(err.Error(), "at least one initial relay") {
			t.Fatalf("Expose(%v) error = %v, want initial relay error", relays, err)
		}
	}
}

// The string values are load-bearing beyond the sdk: discovery.FailureKind
// deliberately mirrors this vocabulary so relay-failure classifications cross
// the boundary with a plain conversion. Drifting a value would silently
// misclassify failures at the discovery layer, so pin the literals.
func TestRelayFailureVocabularyValues(t *testing.T) {
	for value, want := range map[RelayFailure]string{
		RelayFailureNone:     "",
		RelayFailureRuntime:  "runtime",
		RelayFailureTerminal: "terminal",
		RelayFailureMITM:     "mitm",
	} {
		if string(value) != want {
			t.Fatalf("RelayFailure value = %q, want %q", string(value), want)
		}
	}
}

func TestExposeOptionsContainOnlyEndpointCapabilities(t *testing.T) {
	metadata := types.LeaseMetadata{Tags: []string{"initial"}}
	var got options
	for _, option := range []Option{
		WithUDP(),
		WithTCP(),
		WithECH(),
		WithMITMProtection(true),
		WithOverlay(),
		WithMetadata(metadata),
	} {
		option(&got)
	}
	metadata.Tags[0] = "mutated"
	if !got.UDPEnabled || !got.TCPEnabled || !got.ECH || !got.BanMITM || !got.Overlay {
		t.Fatalf("options = %+v, want all endpoint capabilities enabled", got)
	}
	if got.Metadata.Tags[0] != "initial" {
		t.Fatalf("metadata tags = %v, want copied initial value", got.Metadata.Tags)
	}
}

func TestExposeRejectsNilOption(t *testing.T) {
	_, err := Expose(context.Background(), types.Identity{}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "option is nil") {
		t.Fatalf("Expose() error = %v, want nil option error", err)
	}
}

func TestProxyValidationDoesNotCloseExposure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	exposure := &Exposure{
		cancel:         cancel,
		done:           ctx.Done(),
		accepted:       make(chan net.Conn, 1),
		relayListeners: make(map[string]*listener),
	}
	if err := ProxyWithConfig(ctx, exposure, ProxyConfig{}); err == nil {
		t.Fatal("ProxyWithConfig() succeeded without a target")
	}
	select {
	case <-ctx.Done():
		t.Fatal("ProxyWithConfig() closed exposure during validation")
	default:
	}
	_ = exposure.Close()
}

func TestExposureWaitDatagramReadyDoesNotRequireStreamReadiness(t *testing.T) {
	const relayURL = "https://relay.example"
	exposure := newExposureStateTest(t, relayURL)
	exposure.options.UDPEnabled = true
	exposure.setRelayStatus(relayURL, listenerStatus{
		state:   RelayConnecting,
		udpAddr: "relay.example:40000",
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ready, err := exposure.WaitDatagramReady(ctx)
	if err != nil {
		t.Fatalf("WaitDatagramReady() error = %v", err)
	}
	if len(ready) != 1 || ready[0].RelayURL != relayURL || ready[0].UDPAddr == "" {
		t.Fatalf("WaitDatagramReady() = %+v, want UDP-ready relay %q", ready, relayURL)
	}
}

func TestExposureWaitTCPReadyUsesRelayStatus(t *testing.T) {
	const relayURL = "https://relay.example"
	exposure := newExposureStateTest(t, relayURL)
	exposure.options.TCPEnabled = true
	exposure.setRelayStatus(relayURL, listenerStatus{
		state:   RelayConnecting,
		tcpAddr: "relay.example:40000",
	})

	ready, err := exposure.WaitTCPReady(context.Background())
	if err != nil {
		t.Fatalf("WaitTCPReady() error = %v", err)
	}
	if len(ready) != 1 || ready[0].RelayURL != relayURL || ready[0].TCPAddr != "relay.example:40000" {
		t.Fatalf("WaitTCPReady() = %+v, want TCP-ready relay %q", ready, relayURL)
	}
}

func TestExposureWaitTCPReadyWaitsAfterTerminalFailure(t *testing.T) {
	const relayURL = "https://relay.example"
	exposure := newExposureStateTest(t, relayURL)
	exposure.options.TCPEnabled = true
	exposure.setRelayStatus(relayURL, listenerStatus{
		state: RelayFailed,
		err:   errors.New("tcp_port_disabled"),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := exposure.WaitTCPReady(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitTCPReady() error = %v, want context deadline", err)
	}
}

func TestExposureMetadataSnapshotsDoNotShareMutableState(t *testing.T) {
	exposure := &Exposure{
		metadata: utils.NewSnapshot(types.LeaseMetadata{Tags: []string{"initial"}}, types.LeaseMetadata.Copy),
	}
	metadata := exposure.metadata.Load()
	metadata.Tags[0] = "mutated"
	if got := exposure.metadata.Load().Tags[0]; got != "initial" {
		t.Fatalf("Metadata.Tags[0] = %q, want initial", got)
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
		relayURLs:      []string{relayB},
		relayListeners: make(map[string]*listener, 2),
		statuses:       make(map[string]RelayStatus),
		stateChanged:   make(chan struct{}),
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

	if err := exposure.reconcileRelayListeners(false); err != nil {
		t.Fatalf("reconcileRelayListeners() error = %v", err)
	}

	select {
	case <-relayAClosed:
	default:
		t.Fatal("stale relay listener was not closed")
	}

	if got := exposure.listenerRelayURLs(); len(got) != 1 || got[0] != relayB {
		t.Fatalf("ActiveRelayURLs() = %v, want [%q]", got, relayB)
	}
}

func TestExposureReconcileDoesNotRestartMITMBlockedRelay(t *testing.T) {
	const relayURL = "https://relay.example"
	exposure := newExposureStateTest(t, relayURL)
	exposure.blockedRelays = map[string]error{relayURL: errMITMDetected}

	if err := exposure.reconcileRelayListeners(false); err != nil {
		t.Fatalf("reconcileRelayListeners() error = %v", err)
	}
	if got := exposure.listenerRelayURLs(); len(got) != 0 {
		t.Fatalf("active relay URLs = %v, want none", got)
	}

	if err := exposure.RemoveRelay(relayURL); err != nil {
		t.Fatalf("RemoveRelay() error = %v", err)
	}
	if _, blocked := exposure.blockedRelays[relayURL]; blocked {
		t.Fatal("removing relay did not clear its MITM block")
	}
}

func TestExposureRemoveRelayStopsRunningListener(t *testing.T) {
	const relayA = "https://relay-a.example"

	relayAURL, err := url.Parse(relayA)
	if err != nil {
		t.Fatalf("url.Parse(relayA) error = %v", err)
	}

	relayAClosed := make(chan struct{})
	exposure := &Exposure{
		relayURLs:      []string{relayA},
		relayListeners: make(map[string]*listener, 1),
		statuses:       make(map[string]RelayStatus),
		stateChanged:   make(chan struct{}),
	}
	exposure.relayListeners[relayA] = &listener{
		relayURL: relayAURL,
		cancel:   func() { close(relayAClosed) },
		doneCh:   relayAClosed,
	}

	if err := exposure.RemoveRelay(relayA); err != nil {
		t.Fatalf("RemoveRelay() error = %v", err)
	}

	select {
	case <-relayAClosed:
	default:
		t.Fatal("removed relay listener was not closed")
	}
	if got := exposure.listenerRelayURLs(); len(got) != 0 {
		t.Fatalf("ActiveRelayURLs() = %v, want empty", got)
	}
	if got := exposure.relayURLs; len(got) != 0 {
		t.Fatalf("RelayURLs = %v, want empty", got)
	}
}

func TestExposureListenerSelfExitKeepsExplicitRelayConfigured(t *testing.T) {
	const relayA = "https://relay-a.example"

	relayAURL, err := url.Parse(relayA)
	if err != nil {
		t.Fatalf("url.Parse(relayA) error = %v", err)
	}

	l := &listener{
		relayURL: relayAURL,
	}
	exposure := &Exposure{
		relayURLs:      []string{relayA},
		relayListeners: map[string]*listener{relayA: l},
		done:           make(chan struct{}),
	}

	exposure.runListenerAcceptLoop(l)

	if got := exposure.listenerRelayURLs(); len(got) != 0 {
		t.Fatalf("ActiveRelayURLs() = %v, want empty", got)
	}
	if got := exposure.relayURLs; len(got) != 1 || got[0] != relayA {
		t.Fatalf("RelayURLs = %v, want [%q]", got, relayA)
	}
}

func TestExposureSetRelaysReplacesStatusMembership(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)
	exposure := newExposureStateTest(t, relayA)
	exposure.syncRelayStatuses(exposure.relayURLs)

	if err := exposure.SetRelays([]string{relayB}); err != nil {
		t.Fatalf("SetRelays() error = %v", err)
	}

	relays := exposure.Relays()
	if len(relays) != 1 || relays[0].RelayURL != relayB {
		t.Fatalf("Relays() = %+v, want only relay B", relays)
	}
}

// TestExposureReconcileExcludesRelayBlockedAfterInstall verifies that a relay
// blocked (MITM) after its listener already exists is closed and not re-created
// on the next reconcile.  This is an ordinary blocked-relay postcondition test;
// it does not exercise the snapshot→newListener→install TOCTOU window, which
// would require a production hook in newListener.
func TestExposureReconcileExcludesRelayBlockedAfterInstall(t *testing.T) {
	const relayURL = "https://relay.example"
	exposure := newExposureStateTest(t, relayURL)

	// First reconcile: relay is not blocked, so newListener succeeds and a
	// listener is installed.
	if err := exposure.reconcileRelayListeners(false); err != nil {
		t.Fatalf("first reconcileRelayListeners() error = %v", err)
	}
	exposure.mu.RLock()
	_, installed := exposure.relayListeners[relayURL]
	exposure.mu.RUnlock()
	if !installed {
		t.Fatal("first reconcile did not install listener for unblocked relay")
	}

	// Block the relay after its listener exists (simulating MITM detection).
	exposure.setRelayStatus(relayURL, listenerStatus{
		state:   RelayFailed,
		failure: RelayFailureMITM,
		err:     errMITMDetected,
	})

	// Second reconcile must close the listener and not re-create it.
	if err := exposure.reconcileRelayListeners(false); err != nil {
		t.Fatalf("second reconcileRelayListeners() error = %v", err)
	}
	exposure.mu.RLock()
	_, stillInstalled := exposure.relayListeners[relayURL]
	exposure.mu.RUnlock()
	if stillInstalled {
		t.Fatal("listener retained for MITM-blocked relay")
	}
}

func testIdentity() types.Identity {
	return types.Identity{
		Name:       "svc",
		Address:    "address",
		PublicKey:  "public",
		PrivateKey: "private",
	}
}

func TestExposeWithDiscoveryRetainsExplicitRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exposure, err := Expose(ctx, testIdentity(), []string{"https://relay.example"}, WithDiscovery(1))
	if err != nil {
		t.Fatalf("Expose() error = %v", err)
	}
	defer func() { _ = exposure.Close() }()

	// The explicit relay must appear in the membership. Its listener starts
	// in RelayConnecting and will eventually fail (unreachable), but it is
	// retained because explicit relays are always kept by the discovery
	// selection. No network assertions: we only check membership presence.
	relays := exposure.Relays()
	found := false
	for _, r := range relays {
		if r.RelayURL == "https://relay.example" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Relays() = %+v, want https://relay.example present", relays)
	}

	if err := exposure.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestExposeDiscoveryStaysUsableAfterRelayFailure(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exposure, err := Expose(ctx, testIdentity(), []string{relayA, relayB}, WithDiscovery(2))
	if err != nil {
		t.Fatalf("Expose() error = %v", err)
	}
	defer func() { _ = exposure.Close() }()

	// Force one relay to fail. The failure hook reports it to the
	// discovery controller, which unconfirms and suppresses it. The
	// other relay must remain in the membership — the exposure stays
	// usable. We drive the failure the same way existing failure tests
	// do: via setRelayStatus.
	exposure.setRelayStatus(relayA, listenerStatus{
		state: RelayFailed,
		err:   errors.New("rejected"),
	})

	// relayB is an explicit relay present in the membership from
	// construction, so the exposure stays usable after the failure; the
	// discovery reaction (unconfirm + suppression → re-selection) is
	// covered by the discovery package tests. setRelayStatus exercised
	// the synchronous failure→discovery.Report hook above. The failed
	// relay's own status is not asserted because the listener retry loop
	// flips it between failed and connecting asynchronously.
	relays := exposure.Relays()
	var foundA, foundB bool
	for _, r := range relays {
		switch r.RelayURL {
		case relayA:
			foundA = true
		case relayB:
			foundB = true
		}
	}
	if !foundA || !foundB {
		t.Fatalf("Relays() = %+v, want %s and %s present after failure", relays, relayA, relayB)
	}

	if err := exposure.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestExposeSetMaxActiveRelaysDiscovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exposure, err := Expose(ctx, testIdentity(), []string{"https://relay.example"}, WithDiscovery(2))
	if err != nil {
		t.Fatalf("Expose() error = %v", err)
	}
	defer func() { _ = exposure.Close() }()

	if err := exposure.SetMaxActiveRelays(1); err != nil {
		t.Fatalf("SetMaxActiveRelays(1) error = %v", err)
	}

	// Calling again with a different value must not panic or race.
	if err := exposure.SetMaxActiveRelays(3); err != nil {
		t.Fatalf("SetMaxActiveRelays(3) error = %v", err)
	}
}

func TestExposeSetMaxActiveRelaysNoDiscovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exposure, err := Expose(ctx, testIdentity(), []string{"https://relay.example"})
	if err != nil {
		t.Fatalf("Expose() error = %v", err)
	}
	defer func() { _ = exposure.Close() }()

	// Without discovery, SetMaxActiveRelays is a no-op that returns nil.
	if err := exposure.SetMaxActiveRelays(1); err != nil {
		t.Fatalf("SetMaxActiveRelays(1) error = %v, want nil", err)
	}
}
