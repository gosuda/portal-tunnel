package sdk

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestOnlyExplicitIncompatibilityDropsRelayFromActivePool(t *testing.T) {
	if shouldDropRelayFromActivePool(errors.New("connection closed")) {
		t.Fatal("ordinary connection failure must not drop a relay from the active pool")
	}
	if shouldDropRelayFromActivePool(fmt.Errorf("request failed: %w", io.EOF)) {
		t.Fatal("EOF must be retried, not treated as relay incompatibility")
	}
	if !shouldDropRelayFromActivePool(fmt.Errorf("%w: unsupported version", errRelayIncompatible)) {
		t.Fatal("protocol mismatch must drop an incompatible relay from the active pool")
	}
	for _, code := range []string{
		types.APIErrorCodeFeatureUnavailable,
		types.APIErrorCodeUDPDisabled,
		types.APIErrorCodeTCPPortDisabled,
	} {
		if !shouldDropRelayFromActivePool(&types.APIRequestError{Code: code}) {
			t.Errorf("%s must drop an incompatible relay from the active pool", code)
		}
	}
	unknownClientError := &types.APIRequestError{StatusCode: 404, Code: "unknown_endpoint"}
	if shouldDropRelayFromActivePool(unknownClientError) {
		t.Fatal("unclassified client error must not long-term drop a relay from the active pool")
	}
	if !isTerminalRelayError(unknownClientError) {
		t.Fatal("unclassified client error must relinquish the listener for route reconciliation")
	}
}

func TestTerminalRelayFailureTargetsTheReportingRelay(t *testing.T) {
	const (
		entry = "https://entry.example"
		exit  = "https://exit.example"
	)
	listener := &listener{
		route:    discovery.Route{RelayURL: entry, Explicit: false},
		relaySet: mustRelaySet(t, entry, exit),
	}
	err := &relayEndpointError{
		relayURL: exit,
		err:      fmt.Errorf("%w: unsupported protocol", errRelayIncompatible),
	}
	if !listener.closeForTerminalRelayError(err) {
		t.Fatal("terminal relay error was not handled")
	}

	routes := listener.relaySet.SelectRelays(discovery.RouteState{})
	for _, route := range routes {
		if route.RelayURL == exit {
			t.Fatal("incompatible exit relay remains active")
		}
		if route.RelayURL != entry {
			t.Fatalf("unexpected remaining relay %q", route.RelayURL)
		}
	}
}
