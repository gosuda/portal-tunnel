package discovery

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"

	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// AddRelay and RemoveRelay each apply the whole user intent as one unit:
// the explicit-list change plus the matching eligibility change.
// RemoveRelay preserves the explicit-disconnect semantic (out of active
// selection, verified descriptor kept as a future candidate); AddRelay
// makes a re-added relay immediately selectable again without waiting out
// the recovery backoff.
func TestControllerRelayIntentOpsComposeAtomicUnits(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)
	controller := NewController(nil)
	mustApplyAuthoritative(t, controller.relaySet, mustRelayDescriptor(t, relayA))
	mustApplyAuthoritative(t, controller.relaySet, mustRelayDescriptor(t, relayB))
	controller.SetExplicitRelays([]string{relayA, relayB})

	controller.RemoveRelay(relayA)

	routes := controller.relaySet.SelectRelays(routeState{})
	if len(routes) != 1 || routes[0].RelayURL != relayB {
		t.Fatalf("selection after RemoveRelay = %+v, want only relay B", routes)
	}

	controller.AddRelay(relayA)

	routes = controller.relaySet.SelectRelays(routeState{})
	if len(routes) != 2 {
		t.Fatalf("selection after AddRelay = %+v, want both relays eligible again", routes)
	}
}

// Concurrent AddRelay/RemoveRelay intents on the same relay must
// linearize: the final state always matches one serial order, so the
// relay is in the explicit list if and only if it is not suppressed. The
// pre-atomicity shape — explicit-list change and eligibility change as
// two separate critical sections — could end removed-but-allowed or
// added-but-suppressed, which violates this invariant.
func TestControllerRelayIntentOpsLinearizeUnderConcurrency(t *testing.T) {
	const relayA = "https://relay-a.example"
	controller := NewController(nil)
	mustApplyAuthoritative(t, controller.relaySet, mustRelayDescriptor(t, relayA))
	controller.SetExplicitRelays([]string{relayA})

	intentLoops := []func(){
		func() {
			for i := range 25 {
				if i%2 == 0 {
					controller.AddRelay(relayA)
				} else {
					controller.RemoveRelay(relayA)
				}
			}
		},
		func() {
			for i := range 25 {
				if i%2 == 1 {
					controller.AddRelay(relayA)
				} else {
					controller.RemoveRelay(relayA)
				}
			}
		},
	}
	var wg sync.WaitGroup
	for _, loop := range intentLoops {
		wg.Add(1)
		go func() {
			defer wg.Done()
			loop()
		}()
	}
	wg.Wait()

	controller.mu.Lock()
	inExplicit := slices.Contains(controller.explicitRelays, relayA)
	controller.mu.Unlock()
	if suppressed := controller.relaySet.IsSuppressed(relayA, time.Now().UTC()); inExplicit == suppressed {
		t.Fatalf("relay A inExplicit=%v suppressed=%v; intent ops must linearize (inExplicit requires !suppressed)", inExplicit, suppressed)
	}
}

func TestControllerReportRuntimeSuppressesRelay(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)
	controller := NewController([]string{relayA, relayB})
	mustApplyAuthoritative(t, controller.relaySet, mustRelayDescriptor(t, relayA))
	mustApplyAuthoritative(t, controller.relaySet, mustRelayDescriptor(t, relayB))

	controller.Report(relayA, FailureRuntime)

	routes := controller.relaySet.SelectRelays(routeState{
		MaxActiveRelays: 1,
	})
	if len(routes) != 1 || routes[0].RelayURL != relayB {
		t.Fatalf("selected routes = %+v, want only relay B after A failure", routes)
	}
}

func TestControllerReportMITMBansRelay(t *testing.T) {
	const relayURL = "https://relay.example"
	controller := NewController([]string{relayURL})

	controller.Report(relayURL, FailureMITM)

	routes := controller.relaySet.SelectRelays(routeState{
		ExplicitRelayURLs: []string{relayURL},
	})
	if len(routes) != 0 {
		t.Fatalf("selected routes = %+v, want banned relay excluded", routes)
	}
}

func TestControllerFailureDedupeSkipsSuppressedRelay(t *testing.T) {
	const relayURL = "https://relay.example"
	controller := NewController([]string{relayURL})
	mustApplyAuthoritative(t, controller.relaySet, mustRelayDescriptor(t, relayURL))

	controller.Report(relayURL, FailureRuntime)
	if failures := activeFailuresFor(controller, relayURL); failures != 1 {
		t.Fatalf("active failures = %d, want 1 after first report", failures)
	}
	if !controller.relaySet.IsSuppressed(relayURL, time.Now().UTC()) {
		t.Fatal("relay should be suppressed after first failure")
	}

	controller.Report(relayURL, FailureRuntime)
	if failures := activeFailuresFor(controller, relayURL); failures != 1 {
		t.Fatalf("active failures = %d, want still 1 (deduped while suppressed)", failures)
	}

	expireSuppression(controller, relayURL)
	controller.Report(relayURL, FailureRuntime)
	if failures := activeFailuresFor(controller, relayURL); failures != 2 {
		t.Fatalf("active failures = %d, want 2 after suppression expiry", failures)
	}
}

func TestControllerReportMITMVsRuntimeDistinctOutcomes(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)
	controller := NewController([]string{relayA, relayB})
	mustApplyAuthoritative(t, controller.relaySet, mustRelayDescriptor(t, relayA))
	mustApplyAuthoritative(t, controller.relaySet, mustRelayDescriptor(t, relayB))

	// MITM bans permanently — relay A is excluded even from explicit selection.
	controller.Report(relayA, FailureMITM)
	routes := controller.relaySet.SelectRelays(routeState{
		ExplicitRelayURLs: []string{relayA, relayB},
	})
	for _, r := range routes {
		if r.RelayURL == relayA {
			t.Fatal("MITM-banned relay A should not appear in selection")
		}
	}

	// Runtime failure suppresses relay B but does not ban it — it can still
	// appear as an explicit relay (just unconfirmed for auto-selection).
	controller.Report(relayB, FailureRuntime)
	if !controller.relaySet.IsSuppressed(relayB, time.Now().UTC()) {
		t.Fatal("relay B should be suppressed after runtime failure")
	}
	// Verify relay A is NOT suppressed (ban ≠ suppression).
	if controller.relaySet.IsSuppressed(relayA, time.Now().UTC()) {
		t.Fatal("relay A should not be suppressed (MITM is a ban, not suppression)")
	}
}

func TestControllerSetMaxActiveRelaysSignalsNext(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)
	controller := newSelectionTestController(t, relayA, relayB)

	changes := make(chan []string, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			urls, err := controller.Next(ctx)
			if err != nil {
				return
			}
			changes <- urls
		}
	}()

	// Wait for the initial selection (both relays, default max=3).
	select {
	case first := <-changes:
		if len(first) != 2 {
			t.Fatalf("initial selection = %v, want 2 relays", first)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for initial selection")
	}

	// Reduce max active relays — the selection loop should observe the change
	// promptly via the signal, without waiting for the 30s ticker.
	controller.SetMaxActiveRelays(1)

	select {
	case next := <-changes:
		if len(next) != 1 {
			t.Fatalf("selection after SetMaxActiveRelays = %v, want 1 relay", next)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for selection change after SetMaxActiveRelays")
	}
}

func TestControllerSetActiveRelaysSuppliesStickinessSnapshot(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)
	controller := newSelectionTestController(t, relayA, relayB)
	controller.SetMaxActiveRelays(1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := controller.Next(ctx)
	if err != nil || len(first) != 1 {
		t.Fatalf("initial selection = %v, %v, want one relay", first, err)
	}
	sticky := relayA
	if first[0] == relayA {
		sticky = relayB
	}
	controller.SetActiveRelays([]string{sticky})
	next, err := controller.Next(ctx)
	if err != nil {
		t.Fatalf("selection after active snapshot: %v", err)
	}
	if len(next) != 1 || next[0] != sticky {
		t.Fatalf("selection after active snapshot = %v, want [%s]", next, sticky)
	}
}

// A custom explicit relay that never entered through discovery must hold a
// durable RelaySet candidate state: a reported failure suppresses it, the
// next selection changes, and the selection loop republishes membership — the
// exposure reconciles to a replacement instead of keeping a selected URL
// with no live listener.
func TestControllerExplicitRelayFailureRepublishesMembership(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)
	controller := NewController(nil)
	controller.SetExplicitRelays([]string{relayA, relayB})

	changes := make(chan []string, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			urls, err := controller.Next(ctx)
			if err != nil {
				return
			}
			changes <- urls
		}
	}()

	select {
	case first := <-changes:
		if len(first) != 2 {
			t.Fatalf("initial selection = %v, want both explicit relays", first)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for initial selection")
	}

	controller.Report(relayA, FailureRuntime)

	select {
	case next := <-changes:
		if len(next) != 1 || next[0] != relayB {
			t.Fatalf("selection after explicit relay failure = %v, want only relay B", next)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for membership republish after explicit relay failure")
	}
}

func activeFailuresFor(controller *Controller, relayURL string) int {
	for _, state := range controller.relaySet.AllRelays() {
		if state.Descriptor.APIHTTPSAddr == relayURL {
			return state.activeFailures
		}
	}
	return -1
}

func expireSuppression(controller *Controller, relayURL string) {
	controller.relaySet.mu.Lock()
	defer controller.relaySet.mu.Unlock()
	state := controller.relaySet.relays[relayURL]
	state.suppressActiveUntil = time.Now().UTC().Add(-time.Minute)
	controller.relaySet.relays[relayURL] = state
}

// Selection tests exercise refresh through HTTP without depending on public DNS.
func newSelectionTestController(t *testing.T, urls ...string) *Controller {
	t.Helper()
	descriptors := make(map[string]types.RelayDescriptor)
	controller := NewController(urls)
	for _, relayURL := range urls {
		parsed, err := url.Parse(relayURL)
		if err != nil {
			t.Fatal(err)
		}
		desc := mustRelayDescriptor(t, relayURL)
		descriptors[parsed.Host] = desc
		mustApplyAuthoritative(t, controller.relaySet, desc)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.WriteAPIData(w, http.StatusOK, types.DiscoveryResponse{ProtocolVersion: types.DiscoveryVersion, Relays: []types.RelayDescriptor{descriptors[r.Host]}})
	}))
	t.Cleanup(server.Close)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	controller.refresher.httpClient = &http.Client{Transport: transport, Timeout: 5 * time.Second}
	return controller
}
