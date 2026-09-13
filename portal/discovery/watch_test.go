package discovery

import "testing"

func TestControllerUsesRuntimeFailureForSelection(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)
	controller := NewController([]string{relayA, relayB})
	controller.ReportActive([]string{relayA})
	controller.ReportFailure(relayA)
	controller.ReportFailure(relayA)

	routes := controller.relaySet.SelectRelays(RouteState{
		ActiveRelayURLs: controller.activeRelays(),
		MaxActiveRelays: 1,
	})
	if len(routes) != 1 || routes[0].RelayURL != relayB {
		t.Fatalf("selected routes = %+v, want only relay B", routes)
	}
	for _, state := range controller.relaySet.AllRelays() {
		if state.Descriptor.APIHTTPSAddr == relayA && state.activeFailures != 1 {
			t.Fatalf("relay A active failures = %d, want one idempotent report", state.activeFailures)
		}
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
