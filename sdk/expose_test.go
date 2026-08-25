package sdk

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func mustRelaySet(t *testing.T, relayURLs ...string) *discovery.RelaySet {
	t.Helper()
	return discovery.NewRelaySet(relayURLs)
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

	snapshot := exposure.Config()
	snapshot.RelayURLs[0] = "https://mutated.example"
	snapshot.Metadata.Tags[0] = "mutated"

	next := exposure.Config()
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

	metadata := exposure.Config().Metadata
	metadata.Tags[0] = "mutated"
	if got := exposure.Config().Metadata.Tags[0]; got != "updated" {
		t.Fatalf("Metadata.Tags[0] = %q, want updated", got)
	}
	if got := exposure.Config().MaxActiveRelays; got != 2 {
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
			route:    discovery.NewRoute([]string{relayA}, true),
			cancel:   func() { close(relayAClosed) },
			doneCh:   relayAClosed,
		},
		relayB: {
			relayURL: relayBURL,
			route:    discovery.NewRoute([]string{relayB}, true),
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
}

func TestRunListenerAcceptLoopRemovesMultiHopListenerByIngressRelay(t *testing.T) {
	const (
		entry = "https://entry.example"
		exit  = "https://exit.example"
	)
	exitURL, err := url.Parse(exit)
	if err != nil {
		t.Fatalf("url.Parse(exit) error = %v", err)
	}
	relayListener := &listener{
		relayURL: exitURL,
		route:    discovery.NewRoute([]string{entry, exit}, false),
	}
	exposure := &Exposure{relayListeners: map[string]*listener{entry: relayListener}}

	exposure.runListenerAcceptLoop(relayListener)

	if got := exposure.ActiveRelayURLs(); len(got) != 0 {
		t.Fatalf("ActiveRelayURLs() = %v, want terminated multi-hop listener removed", got)
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
			route:    discovery.NewRoute([]string{relayA}, true),
			cancel:   func() { close(relayAClosed) },
			doneCh:   relayAClosed,
		},
		relayB: {
			relayURL: relayBURL,
			route:    discovery.NewRoute([]string{relayB}, true),
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

	if got := exposure.ActiveRelayURLs(); len(got) != 1 || got[0] != relayB {
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
	if got := exposure.ActiveRelayURLs(); len(got) != 0 {
		t.Fatalf("ActiveRelayURLs() = %v, want empty", got)
	}
	if got := exposure.Config().RelayURLs; len(got) != 0 {
		t.Fatalf("RelayURLs = %v, want empty", got)
	}
	routes, err := exposure.relaySet.PlanRoutes(nil, discovery.RouteState{})
	if err != nil {
		t.Fatalf("PlanRoutes() error = %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("PlanRoutes() = %v, want empty", routes)
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
		route:    discovery.NewRoute([]string{relayA}, true),
	}
	exposure := &Exposure{
		cfg:            utils.NewSnapshot(ExposeConfig{RelayURLs: []string{relayA}}, ExposeConfig.snapshot),
		relaySet:       mustRelaySet(t, relayA),
		relayListeners: map[string]*listener{relayA: l},
		done:           make(chan struct{}),
	}

	exposure.runListenerAcceptLoop(l)

	if got := exposure.ActiveRelayURLs(); len(got) != 0 {
		t.Fatalf("ActiveRelayURLs() = %v, want empty", got)
	}
	if got := exposure.Config().RelayURLs; len(got) != 1 || got[0] != relayA {
		t.Fatalf("RelayURLs = %v, want [%q]", got, relayA)
	}
	if got := exposure.relaySet.BootstrapRelayURLs(); len(got) != 1 || got[0] != relayA {
		t.Fatalf("BootstrapRelayURLs() = %v, want [%q]", got, relayA)
	}
}

func TestListenerRetryBudgetDropsAutoSelectedRelayWithoutPoolBan(t *testing.T) {
	const relayA = "https://relay-a.example"

	relayAURL, err := url.Parse(relayA)
	if err != nil {
		t.Fatalf("url.Parse(relayA) error = %v", err)
	}

	relaySet := mustRelaySet(t, relayA)
	listener := &listener{
		relayURL:   relayAURL,
		route:      discovery.NewRoute([]string{relayA}, false),
		relaySet:   relaySet,
		retryCount: 1,
	}

	if listener.waitRetry(context.Background(), "lease registration", errors.New("boom"), 2, 0) {
		t.Fatal("waitRetry() = true after retry budget was exhausted")
	}

	routes, err := relaySet.PlanRoutes(nil, discovery.RouteState{})
	if err != nil {
		t.Fatalf("PlanRoutes() error = %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("PlanRoutes() = %v, want no active routes", routes)
	}

	relays := relaySet.AllRelays()
	if len(relays) != 1 || relays[0].Banned || relays[0].Descriptor.APIHTTPSAddr != relayA {
		t.Fatalf("AllRelays() = %+v, want relay retained outside active pool", relays)
	}
	if got := relaySet.BootstrapRelayURLs(); len(got) != 1 || got[0] != relayA {
		t.Fatalf("BootstrapRelayURLs() = %v, want [%q]", got, relayA)
	}
}

func TestExposureReconcileSkipsUnchangedRoutes(t *testing.T) {
	const relayA = "https://relay-a.example"

	relayAURL, err := url.Parse(relayA)
	if err != nil {
		t.Fatalf("url.Parse(relayA) error = %v", err)
	}

	closed := make(chan struct{})
	exposure := &Exposure{
		cfg:            utils.NewSnapshot(ExposeConfig{RelayURLs: []string{relayA}}, ExposeConfig.snapshot),
		relaySet:       mustRelaySet(t, relayA),
		relayListeners: make(map[string]*listener, 1),
	}
	exposure.relayListeners[relayA] = &listener{
		relayURL: relayAURL,
		cancel:   func() { close(closed) },
		doneCh:   closed,
		route:    discovery.NewRoute([]string{relayA}, true),
	}

	// First reconcile records the current route snapshot and closes nothing.
	if err := exposure.reconcileRelayListeners(false); err != nil {
		t.Fatalf("reconcileRelayListeners() error = %v", err)
	}
	select {
	case <-closed:
		t.Fatal("listener closed on first reconcile with identical routes")
	default:
	}

	// Second reconcile with the same routes must be a no-op.
	if err := exposure.reconcileRelayListeners(false); err != nil {
		t.Fatalf("reconcileRelayListeners() error = %v", err)
	}
	select {
	case <-closed:
		t.Fatal("listener closed on second reconcile with unchanged routes")
	default:
	}
}

func TestExposureSnapshotExcludesDeadRelayListener(t *testing.T) {
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
			route:    discovery.NewRoute([]string{relayA}, true),
		},
		relayB: {
			relayURL: relayBURL,
			route:    discovery.NewRoute([]string{relayB}, true),
		},
	}

	for range 3 {
		relaySet.RecordDiscoveryFailure(relayA, 3)
	}
	snap := exposure.Snapshot()
	foundRelayB := false
	for _, relayStatus := range snap.Relays {
		if relayStatus.RelayURL == relayB {
			foundRelayB = true
		}
		if relayStatus.RelayURL == relayA {
			t.Fatalf("Snapshot() included dead relay %q despite listener existing", relayA)
		}
	}
	if !foundRelayB {
		t.Fatalf("Snapshot() omitted active relay %q", relayB)
	}
}
