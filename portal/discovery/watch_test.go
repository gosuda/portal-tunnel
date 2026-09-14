package discovery

import (
	"testing"
	"time"
)

func TestControllerReportFailureSuppressesRelay(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)
	controller := NewController([]string{relayA, relayB})
	mustApplyAuthoritative(t, controller.relaySet, mustRelayDescriptor(t, relayA))
	mustApplyAuthoritative(t, controller.relaySet, mustRelayDescriptor(t, relayB))

	controller.ReportFailure(relayA)

	routes := controller.relaySet.SelectRelays(RouteState{
		MaxActiveRelays: 1,
	})
	if len(routes) != 1 || routes[0].RelayURL != relayB {
		t.Fatalf("selected routes = %+v, want only relay B after A failure", routes)
	}
}

func TestControllerBanExcludesExplicitRelay(t *testing.T) {
	const relayURL = "https://relay.example"
	controller := NewController([]string{relayURL})

	controller.Ban(relayURL)

	routes := controller.relaySet.SelectRelays(RouteState{
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

	controller.ReportFailure(relayURL)
	if failures := activeFailuresFor(controller, relayURL); failures != 1 {
		t.Fatalf("active failures = %d, want 1 after first report", failures)
	}
	if !controller.relaySet.IsSuppressed(relayURL, time.Now().UTC()) {
		t.Fatal("relay should be suppressed after first failure")
	}

	controller.ReportFailure(relayURL)
	if failures := activeFailuresFor(controller, relayURL); failures != 1 {
		t.Fatalf("active failures = %d, want still 1 (deduped while suppressed)", failures)
	}

	expireSuppression(controller, relayURL)
	controller.ReportFailure(relayURL)
	if failures := activeFailuresFor(controller, relayURL); failures != 2 {
		t.Fatalf("active failures = %d, want 2 after suppression expiry", failures)
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
