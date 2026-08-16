package sdk

import (
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestNewRenewRequestIncludesMetadata(t *testing.T) {
	t.Parallel()

	metadata := types.LeaseMetadata{
		Description: "live app",
		Tags:        []string{"demo", "live"},
		Owner:       "ops",
		Thumbnail:   "https://example.com/thumb.png",
		Hide:        true,
	}

	req := newRenewRequest(2*time.Minute, "token", "203.0.113.10", metadata)
	if req.AccessToken != "token" {
		t.Fatalf("AccessToken = %q, want token", req.AccessToken)
	}
	if req.TTL != 120 {
		t.Fatalf("TTL = %d, want 120", req.TTL)
	}
	if req.ReportedIP != "203.0.113.10" {
		t.Fatalf("ReportedIP = %q, want 203.0.113.10", req.ReportedIP)
	}
	if got := req.Metadata; got.Description != metadata.Description || got.Owner != metadata.Owner || got.Thumbnail != metadata.Thumbnail || got.Hide != metadata.Hide || len(got.Tags) != 2 || got.Tags[0] != "demo" || got.Tags[1] != "live" {
		t.Fatalf("Metadata = %#v, want %#v", got, metadata)
	}

	metadata.Tags[0] = "mutated"
	if req.Metadata.Tags[0] != "demo" {
		t.Fatalf("Metadata tags alias input slice: got %q", req.Metadata.Tags[0])
	}
}

func TestRelayRegistrationErrorPreservesRelayURLAndCause(t *testing.T) {
	cause := errors.New("connection closed")
	err := &relayRegistrationError{relayURL: "https://relay.example", err: cause}

	if err.relayURL != "https://relay.example" {
		t.Fatalf("relayURL = %q, want relay URL", err.relayURL)
	}
	if !errors.Is(err, cause) {
		t.Fatal("hop registration error does not unwrap its cause")
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
		route:    discovery.NewRoute([]string{entry, exit}, false),
		relaySet: mustRelaySet(t, entry, exit),
	}
	err := &relayRegistrationError{
		relayURL: exit,
		err:      fmt.Errorf("%w: unsupported protocol", errRelayIncompatible),
	}
	if !listener.closeForTerminalRelayError(err) {
		t.Fatal("terminal relay error was not handled")
	}

	routes, planErr := listener.relaySet.PlanRoutes(nil, discovery.RouteState{})
	if planErr != nil {
		t.Fatalf("PlanRoutes() error = %v", planErr)
	}
	for _, route := range routes {
		if route.ListenerRelayURL() == exit {
			t.Fatal("incompatible exit relay remains active")
		}
		if route.ListenerRelayURL() != entry {
			t.Fatalf("unexpected remaining relay %q", route.ListenerRelayURL())
		}
	}
}

func TestNewListenerUsesMultiHopExitForControl(t *testing.T) {
	entry := "https://entry.example"
	exit := "https://exit.example"
	route := discovery.NewRoute([]string{entry, "https://middle.example", exit}, false)
	entryURL, controlURL, err := routeRelayURLs(route)
	if err != nil {
		t.Fatalf("routeRelayURLs() error = %v", err)
	}

	if got := controlURL; got != exit {
		t.Fatalf("control relay = %q, want %q", got, exit)
	}
	if got := entryURL; got != entry {
		t.Fatalf("route entry = %q, want %q", got, entry)
	}
}

func TestBuildHopRoutesUsesPublicHostnameWithoutECH(t *testing.T) {
	listener := &listener{
		identity: types.Identity{
			Name:        "demo",
			Address:     "0x1234",
			TokenSecret: "test-token-secret",
		},
	}
	hopPath := []types.RelayDescriptor{
		{APIHTTPSAddr: "https://entry.example.com"},
		{APIHTTPSAddr: "https://exit.example.com"},
	}

	routes, exitHopToken, err := listener.buildHopRoutes(hopPath, "demo.example.com", "", nil)
	if err != nil {
		t.Fatalf("buildHopRoutes() error = %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("buildHopRoutes() routes = %d, want 1", len(routes))
	}
	if exitHopToken == "" {
		t.Fatal("buildHopRoutes() exit hop token is empty")
	}

	entry := routes[0]
	if entry.RouteHostname != "demo.example.com" {
		t.Fatalf("entry RouteHostname = %q, want public hostname", entry.RouteHostname)
	}
	if entry.PublicHostname != "" || entry.HostnameHash != "" || len(entry.ECHConfigList) != 0 {
		t.Fatalf("entry ECH fields = PublicHostname %q, HostnameHash %q, ECHConfigList %x; want empty", entry.PublicHostname, entry.HostnameHash, entry.ECHConfigList)
	}
}
