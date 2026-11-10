package discovery

import (
	"context"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

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

	routes := controller.relaySet.selectRelays(routeState{})
	if len(routes) != 1 || routes[0] != relayB {
		t.Fatalf("selection after RemoveRelay = %+v, want only relay B", routes)
	}

	controller.AddRelay(relayA)

	routes = controller.relaySet.selectRelays(routeState{})
	if len(routes) != 2 {
		t.Fatalf("selection after AddRelay = %+v, want both relays eligible again", routes)
	}
}

func TestControllerPassingDiscoveryDoesNotClearRuntimeSuppression(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const failed, healthy = "https://selective.example", "https://healthy.example"
		controller := NewController(nil)
		descriptor := mustRelayDescriptor(t, failed)
		mustApplyAuthoritative(t, controller.relaySet, descriptor)
		mustApplyAuthoritative(t, controller.relaySet, mustRelayDescriptor(t, healthy))
		controller.Report(failed, FailureRuntime)
		mustApplyAuthoritative(t, controller.relaySet, descriptor)
		selected := controller.relaySet.selectRelays(routeState{})
		if !slices.Equal(selected, []string{healthy}) {
			t.Fatalf("passing discovery bypassed runtime suppression: %v", selected)
		}
		synctest.Sleep(defaultDirectRecoveryBackoff + time.Second)
		selected = controller.relaySet.selectRelays(routeState{})
		if len(selected) != 2 || !slices.Contains(selected, healthy) || !slices.Contains(selected, failed) {
			t.Fatalf("temporary failure did not recover both alternatives: %v", selected)
		}
	})
}

func TestControllerLocalSecurityBanSurvivesDiscoveryUntilOperatorOverride(t *testing.T) {
	const blocked, healthy = "https://blocked.example", "https://healthy.example"
	controller := NewController(nil)
	descriptor := mustRelayDescriptor(t, blocked)
	mustApplyAuthoritative(t, controller.relaySet, descriptor)
	mustApplyAuthoritative(t, controller.relaySet, mustRelayDescriptor(t, healthy))
	controller.Report(blocked, FailureMITM)
	_, err := controller.relaySet.ApplyRelayDiscoveryResponse(blocked, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{descriptor},
	}, time.Now().UTC())
	if err == nil {
		t.Fatal("locally banned relay's advertisement was accepted as a direct target")
	}
	selected := controller.relaySet.selectRelays(routeState{})
	if !slices.Equal(selected, []string{healthy}) {
		t.Fatalf("advertisement changed a local security ban or healthy alternative: %v", selected)
	}
	controller.AddRelay(blocked)
	selected = controller.relaySet.selectRelays(controller.buildRouteState())
	if len(selected) != 2 || !slices.Contains(selected, healthy) || !slices.Contains(selected, blocked) {
		t.Fatalf("explicit operator override did not restore the relay: %v", selected)
	}
}

func toggleEvenRelayIntent(controller *Controller, relayA string) {
	for i := range 25 {
		if i%2 == 0 {
			controller.AddRelay(relayA)
			continue
		}
		controller.RemoveRelay(relayA)
	}
}

func toggleOddRelayIntent(controller *Controller, relayA string) {
	for i := range 25 {
		if i%2 == 1 {
			controller.AddRelay(relayA)
			continue
		}
		controller.RemoveRelay(relayA)
	}
}

func driveRelayIntentOps(controller *Controller, relayA string) {
	intentLoops := []func(){
		func() { toggleEvenRelayIntent(controller, relayA) },
		func() { toggleOddRelayIntent(controller, relayA) },
	}
	var wg sync.WaitGroup
	for _, loop := range intentLoops {
		wg.Go(loop)
	}
	wg.Wait()
}

func checkRelayIntentLinearized(t *testing.T, controller *Controller, relayA string) {
	t.Helper()
	controller.mu.Lock()
	inExplicit := slices.Contains(controller.explicitRelays, relayA)
	controller.mu.Unlock()
	if suppressed := controller.relaySet.IsSuppressed(relayA, time.Now().UTC()); inExplicit == suppressed {
		t.Fatalf("relay A inExplicit=%v suppressed=%v; intent ops must linearize (inExplicit requires !suppressed)", inExplicit, suppressed)
	}
}

func TestControllerRelayIntentOpsLinearizeUnderConcurrency(t *testing.T) {
	const relayA = "https://relay-a.example"
	controller := NewController(nil)
	mustApplyAuthoritative(t, controller.relaySet, mustRelayDescriptor(t, relayA))
	controller.SetExplicitRelays([]string{relayA})
	driveRelayIntentOps(controller, relayA)
	checkRelayIntentLinearized(t, controller, relayA)
}

func TestControllerReportMITMBansRelay(t *testing.T) {
	const relayURL = "https://relay.example"
	controller := NewController([]string{relayURL})

	controller.Report(relayURL, FailureMITM)

	routes := controller.relaySet.selectRelays(routeState{
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

	controller.Report(relayA, FailureMITM)
	routes := controller.relaySet.selectRelays(routeState{
		ExplicitRelayURLs: []string{relayA, relayB},
	})
	for _, r := range routes {
		if r == relayA {
			t.Fatal("MITM-banned relay A should not appear in selection")
		}
	}

	controller.Report(relayB, FailureRuntime)
	if !controller.relaySet.IsSuppressed(relayB, time.Now().UTC()) {
		t.Fatal("relay B should be suppressed after runtime failure")
	}
	if controller.relaySet.IsSuppressed(relayA, time.Now().UTC()) {
		t.Fatal("relay A should not be suppressed (MITM is a ban, not suppression)")
	}
}

func TestControllerExplicitRelayFailureRepublishesMembership(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)
	controller := NewController(nil)
	controller.SetExplicitRelays([]string{relayA, relayB})

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
