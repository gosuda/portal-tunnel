package discovery

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"
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
	if len(routes) != 1 || routes[0] != relayB {
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
	if len(routes) != 1 || routes[0] != relayB {
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
		if r == relayA {
			t.Fatal("MITM-banned relay A should not appear in selection")
		}
	}

	// Runtime failure temporarily suppresses relay B without banning it.
	controller.Report(relayB, FailureRuntime)
	if !controller.relaySet.IsSuppressed(relayB, time.Now().UTC()) {
		t.Fatal("relay B should be suppressed after runtime failure")
	}
	// Verify relay A is NOT suppressed (ban ≠ suppression).
	if controller.relaySet.IsSuppressed(relayA, time.Now().UTC()) {
		t.Fatal("relay A should not be suppressed (MITM is a ban, not suppression)")
	}
}

// A custom explicit relay that never entered through discovery must hold a
// durable RelaySet candidate state: a reported failure suppresses it, and
// Next() publishes the reconciled membership — relay B only — instead of
// keeping a selected URL with no live listener. The transition must be
// observed through the controller's publication boundary, so a broken
// Report() state change or a Next() that stops publishing the new desired
// set both fail the deadline.
func TestControllerExplicitRelayFailureRepublishesMembership(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)
	controller := NewController(nil)
	controller.SetExplicitRelays([]string{relayA, relayB})

	// With no discovery candidates the refresher is a no-op, so Next()
	// publishes the explicit selection directly.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	initial, err := controller.Next(ctx)
	if err != nil {
		t.Fatalf("initial Next() error = %v", err)
	}
	if len(initial) != 2 {
		t.Fatalf("initial published membership = %v, want both explicit relays", initial)
	}

	controller.Report(relayA, FailureRuntime)

	republished, err := controller.Next(ctx)
	if err != nil {
		t.Fatalf("Next() after Report error = %v: reconciled membership was not published before the deadline", err)
	}
	if len(republished) != 1 || republished[0] != relayB {
		t.Fatalf("republished membership = %v, want only relay B", republished)
	}
}

func activeFailuresFor(controller *Controller, relayURL string) int {
	for _, state := range controller.relaySet.currentRelayStates(time.Now().UTC()) {
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
