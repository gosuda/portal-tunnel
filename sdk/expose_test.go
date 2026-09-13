package sdk

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func mustRelaySet(t *testing.T, relayURLs ...string) *discovery.RelaySet {
	t.Helper()
	return discovery.NewRelaySet(relayURLs)
}

func newExposureStateTest(t *testing.T, relayURLs ...string) *Exposure {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	exposure := &Exposure{
		cancel:         cancel,
		done:           ctx.Done(),
		cfg:            utils.NewSnapshot(ExposeConfig{RelayURLs: relayURLs}, ExposeConfig.snapshot),
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
	_, err := Expose(context.Background(), ExposeConfig{
		RelayURLs: []string{"https://relay.example"},
		Identity:  types.Identity{Name: "svc"},
	})
	if err == nil || !strings.Contains(err.Error(), "identity must include") {
		t.Fatalf("Expose() error = %v, want incomplete identity error", err)
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
	exposure.cfg.UpdateCopy(func(cfg *ExposeConfig) { cfg.UDPEnabled = true })
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

func TestExposureConfigSnapshotsDoNotShareMutableState(t *testing.T) {
	exposure := &Exposure{
		cfg: utils.NewSnapshot(ExposeConfig{
			RelayURLs: []string{"https://relay-a.example"},
			Identity: types.Identity{
				Name:    "svc",
				Address: "portal-address",
			},
			Metadata: types.LeaseMetadata{
				Tags: []string{"initial"},
			},
		}, ExposeConfig.snapshot),
	}

	snapshot := exposure.config()
	snapshot.RelayURLs[0] = "https://mutated.example"
	snapshot.Metadata.Tags[0] = "mutated"

	next := exposure.config()
	if got := next.RelayURLs[0]; got != "https://relay-a.example" {
		t.Fatalf("RelayURLs[0] = %q, want original relay", got)
	}
	if got := next.Metadata.Tags[0]; got != "initial" {
		t.Fatalf("Metadata.Tags[0] = %q, want original tag", got)
	}

	exposure.cfg.UpdateCopy(func(cfg *ExposeConfig) {
		cfg.MaxActiveRelays = 2
		cfg.Metadata = types.LeaseMetadata{Tags: []string{"updated"}}
	})

	metadata := exposure.config().Metadata
	metadata.Tags[0] = "mutated"
	if got := exposure.config().Metadata.Tags[0]; got != "updated" {
		t.Fatalf("Metadata.Tags[0] = %q, want updated", got)
	}
	if got := exposure.config().MaxActiveRelays; got != 2 {
		t.Fatalf("MaxActiveRelays = %d, want 2", got)
	}
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
		cfg:            utils.NewSnapshot(ExposeConfig{RelayURLs: []string{relayA, relayB}}, ExposeConfig.snapshot),
		relaySet:       mustRelaySet(t, relayA, relayB),
		relayListeners: make(map[string]*listener, 2),
	}
	relayAClosed := make(chan struct{})
	exposure.relayListeners = map[string]*listener{
		relayA: {
			relayURL: relayURL,
			route:    discovery.Route{RelayURL: relayA, Explicit: true},
			cancel:   func() { close(relayAClosed) },
			doneCh:   relayAClosed,
		},
		relayB: {
			relayURL: relayBURL,
			route:    discovery.Route{RelayURL: relayB, Explicit: true},
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

	if got := exposure.activeRelayURLs(); len(got) != 1 || got[0] != relayB {
		t.Fatalf("ActiveRelayURLs() = %v, want [%q]", got, relayB)
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
		cfg:            utils.NewSnapshot(ExposeConfig{RelayURLs: []string{relayB}}, ExposeConfig.snapshot),
		relaySet:       mustRelaySet(t, relayA, relayB),
		relayListeners: make(map[string]*listener, 2),
	}
	exposure.relayListeners = map[string]*listener{
		relayA: {
			relayURL: relayAURL,
			route:    discovery.Route{RelayURL: relayA, Explicit: true},
			cancel:   func() { close(relayAClosed) },
			doneCh:   relayAClosed,
		},
		relayB: {
			relayURL: relayBURL,
			route:    discovery.Route{RelayURL: relayB, Explicit: true},
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

	if got := exposure.activeRelayURLs(); len(got) != 1 || got[0] != relayB {
		t.Fatalf("ActiveRelayURLs() = %v, want [%q]", got, relayB)
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
		cfg:            utils.NewSnapshot(ExposeConfig{RelayURLs: []string{relayA}}, ExposeConfig.snapshot),
		relaySet:       mustRelaySet(t, relayA),
		relayListeners: make(map[string]*listener, 1),
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
	if got := exposure.config().RelayURLs; len(got) != 0 {
		t.Fatalf("RelayURLs = %v, want empty", got)
	}
	routes := exposure.relaySet.SelectRelays(discovery.RouteState{})
	if len(routes) != 0 {
		t.Fatalf("SelectRelays() = %v, want empty", routes)
	}
	relays := exposure.relaySet.AllRelays()
	if len(relays) != 1 || relays[0].Descriptor.APIHTTPSAddr != relayA || relays[0].Banned {
		t.Fatalf("AllRelays() = %+v, want unbanned candidate %q", relays, relayA)
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
		route:    discovery.Route{RelayURL: relayA, Explicit: true},
	}
	exposure := &Exposure{
		cfg:            utils.NewSnapshot(ExposeConfig{RelayURLs: []string{relayA}}, ExposeConfig.snapshot),
		relaySet:       mustRelaySet(t, relayA),
		relayListeners: map[string]*listener{relayA: l},
		done:           make(chan struct{}),
	}

	exposure.runListenerAcceptLoop(l)

	if got := exposure.activeRelayURLs(); len(got) != 0 {
		t.Fatalf("ActiveRelayURLs() = %v, want empty", got)
	}
	if got := exposure.config().RelayURLs; len(got) != 1 || got[0] != relayA {
		t.Fatalf("RelayURLs = %v, want [%q]", got, relayA)
	}
	if got := exposure.relaySet.BootstrapRelayURLs(); len(got) != 1 || got[0] != relayA {
		t.Fatalf("BootstrapRelayURLs() = %v, want [%q]", got, relayA)
	}
}

func TestExposureSnapshotReflectsDeadRelayStatus(t *testing.T) {
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

	relaySet := mustRelaySet(t, relayA, relayB)
	exposure := &Exposure{
		cfg:            utils.NewSnapshot(ExposeConfig{RelayURLs: []string{relayA, relayB}}, ExposeConfig.snapshot),
		relaySet:       relaySet,
		relayListeners: make(map[string]*listener, 2),
	}
	exposure.relayListeners = map[string]*listener{
		relayA: {
			relayURL: relayAURL,
			route:    discovery.Route{RelayURL: relayA, Explicit: true},
		},
		relayB: {
			relayURL: relayBURL,
			route:    discovery.Route{RelayURL: relayB, Explicit: true},
		},
	}
	exposure.syncRelayStatuses(nil, exposure.config())

	for range 3 {
		relaySet.RecordDiscoveryFailure(relayA, 3)
	}
	exposure.syncRelayStatuses(nil, exposure.config())
	relays := exposure.Relays()
	foundRelayB := false
	foundFailedRelayA := false
	for _, relayStatus := range relays {
		if relayStatus.RelayURL == relayB {
			foundRelayB = true
		}
		if relayStatus.RelayURL == relayA {
			if relayStatus.State != RelayFailed {
				t.Fatalf("Relays() state for dead relay = %s, want failed", relayStatus.State)
			}
			foundFailedRelayA = true
		}
	}
	if !foundRelayB {
		t.Fatalf("Relays() omitted active relay %q", relayB)
	}
	if !foundFailedRelayA {
		t.Fatalf("Relays() omitted failed explicit relay %q", relayA)
	}
}
