package sdk

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestValidateReverseEndpoint(t *testing.T) {
	t.Parallel()
	leaseExpiry := time.Now().UTC().Add(time.Minute)
	endpoint := types.ReverseEndpoint{
		URL:        "https://relay.example/sdk/connect",
		Capability: " reverse-capability ",
		ExpiresAt:  leaseExpiry,
	}
	validated, err := validateReverseEndpoint(endpoint, leaseExpiry)
	if err != nil {
		t.Fatalf("validateReverseEndpoint() error = %v", err)
	}
	if validated.Capability != "reverse-capability" {
		t.Fatalf("validated capability = %q", validated.Capability)
	}
	endpoint.URL = "https://gateway.example/sdk/connect"
	if _, err := validateReverseEndpoint(endpoint, leaseExpiry); err != nil {
		t.Fatalf("gateway reverse endpoint rejected: %v", err)
	}

	for name, invalid := range map[string]types.ReverseEndpoint{
		"wrong path":  {URL: "https://relay.example/sdk/renew", Capability: "cap", ExpiresAt: leaseExpiry},
		"lease bound": {URL: "https://relay.example/sdk/connect", Capability: "cap", ExpiresAt: leaseExpiry.Add(time.Second)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := validateReverseEndpoint(invalid, leaseExpiry); err == nil {
				t.Fatal("validateReverseEndpoint() error = nil")
			}
		})
	}
}

func TestValidateReverseEndpointTransport(t *testing.T) {
	t.Parallel()
	relayURL, err := url.Parse("https://relay.example")
	if err != nil {
		t.Fatal(err)
	}
	direct := types.ReverseEndpoint{URL: "https://relay.example/sdk/connect"}
	overlay := types.ReverseEndpoint{URL: "https://gateway.example/sdk/connect", Overlay: true}
	legacyOverlay := types.ReverseEndpoint{URL: "https://gateway.example/sdk/connect"}

	for name, test := range map[string]struct {
		enabled  bool
		endpoint types.ReverseEndpoint
		wantErr  bool
	}{
		"direct":           {endpoint: direct},
		"overlay disabled": {endpoint: overlay, wantErr: true},
		"overlay enabled":  {enabled: true, endpoint: overlay},
		"fallback direct":  {enabled: true, endpoint: direct},
		"legacy overlay":   {endpoint: legacyOverlay, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			listener := &listener{relayURL: relayURL, overlay: test.enabled}
			err := listener.validateReverseEndpointTransport(test.endpoint)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateReverseEndpointTransport() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

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
	err := &relayRegistrationError{
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
