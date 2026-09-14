package discovery

import (
	"context"
	"testing"
	"time"
)

// FailureKind's string values mirror sdk.RelayFailure so callers forward
// classifications with a plain conversion (see the sdk-side value pin). If a
// value drifts here or there, failures are silently misclassified, so both
// sides pin the literals.
func TestFailureKindVocabularyValues(t *testing.T) {
	for value, want := range map[FailureKind]string{
		FailureRuntime:  "runtime",
		FailureTerminal: "terminal",
		FailureMITM:     "mitm",
	} {
		if string(value) != want {
			t.Fatalf("FailureKind value = %q, want %q", string(value), want)
		}
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

func TestControllerSetMaxActiveRelaysSignalsWatch(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)
	controller := NewController([]string{relayA})
	mustApplyAuthoritative(t, controller.relaySet, mustRelayDescriptor(t, relayA))
	mustApplyAuthoritative(t, controller.relaySet, mustRelayDescriptor(t, relayB))

	changes := make(chan []string, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = controller.Watch(ctx, nil, func(urls []string) error {
			changes <- urls
			return nil
		})
	}()

	// Wait for the initial selection (both relays, default max=3).
	select {
	case first := <-changes:
		if len(first) != 2 {
			t.Fatalf("initial selection = %v, want 2 relays", first)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for initial watch selection")
	}

	// Reduce max active relays — the watch loop should observe the change
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
