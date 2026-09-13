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
		statusEvents:   make(chan RelayStatus, 4),
		updates:        make(chan RelayStatus, 4),
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

func TestExposureAcceptReturnsErrNoRelaysAfterTerminalFailures(t *testing.T) {
	const relayURL = "https://relay.example"
	exposure := newExposureStateTest(t, relayURL)
	exposure.setRelayStatus(relayURL, listenerStatus{state: RelayFailed, err: errors.New("rejected")})

	if _, err := exposure.Accept(); !errors.Is(err, ErrNoRelays) {
		t.Fatalf("Accept() error = %v, want ErrNoRelays", err)
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

func TestExposureWaitTCPReadyReturnsAfterTerminalFailure(t *testing.T) {
	const relayURL = "https://relay.example"
	exposure := newExposureStateTest(t, relayURL)
	exposure.options.TCPEnabled = true
	exposure.setRelayStatus(relayURL, listenerStatus{
		state: RelayFailed,
		err:   errors.New("tcp_port_disabled"),
	})

	if _, err := exposure.WaitTCPReady(context.Background()); !errors.Is(err, ErrNoRelays) {
		t.Fatalf("WaitTCPReady() error = %v, want ErrNoRelays", err)
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

	if got := exposure.activeRelayURLs(); len(got) != 1 || got[0] != relayB {
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
	if got := exposure.activeRelayURLs(); len(got) != 0 {
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
	if got := exposure.activeRelayURLs(); len(got) != 0 {
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

	if got := exposure.activeRelayURLs(); len(got) != 0 {
		t.Fatalf("ActiveRelayURLs() = %v, want empty", got)
	}
	if got := exposure.relayURLs; len(got) != 1 || got[0] != relayA {
		t.Fatalf("RelayURLs = %v, want [%q]", got, relayA)
	}
}

func TestExposureSetRelaysReplacesStatusMembership(t *testing.T) {
	exposure := newExposureStateTest(t, "https://relay-a.example")
	exposure.syncRelayStatuses(exposure.relayURLs)

	exposure.mu.Lock()
	exposure.relayURLs = []string{"https://relay-b.example"}
	exposure.mu.Unlock()
	exposure.syncRelayStatuses(exposure.relayURLs)

	relays := exposure.Relays()
	if len(relays) != 1 || relays[0].RelayURL != "https://relay-b.example" {
		t.Fatalf("Relays() = %+v, want only relay B", relays)
	}
}
