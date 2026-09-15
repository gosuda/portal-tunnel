package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
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

func TestAPIClientRenewUsesExplicitRequestValues(t *testing.T) {
	t.Parallel()

	want := types.RenewRequest{
		AccessToken: "access-token",
		TTL:         90,
		ReportedIP:  "192.0.2.10",
		Metadata: types.LeaseMetadata{
			Description: "updated description",
			Tags:        []string{"api", "renew"},
		},
	}
	requestCh := make(chan types.RenewRequest, 1)
	expiresAt := time.Now().UTC().Add(time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req types.RenewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode renew request: %v", err)
		}
		requestCh <- req
		utils.WriteAPIData(w, http.StatusOK, types.RenewResponse{
			AccessToken: " renewed-token ",
			ExpiresAt:   expiresAt,
			ReverseEndpoint: types.ReverseEndpoint{
				URL:        "https://relay.example/sdk/connect",
				Capability: " capability ",
				ExpiresAt:  expiresAt,
			},
		})
	}))
	defer server.Close()

	relayURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &apiClient{relayURL: relayURL, http: server.Client()}
	resp, err := client.renew(context.Background(), want)
	if err != nil {
		t.Fatalf("renew() error = %v", err)
	}
	if resp.AccessToken != "renewed-token" || resp.ReverseEndpoint.Capability != "capability" {
		t.Fatalf("renew() response = %+v", resp)
	}
	got := <-requestCh
	if got.AccessToken != want.AccessToken || got.TTL != want.TTL || got.ReportedIP != want.ReportedIP || got.Metadata.Description != want.Metadata.Description || len(got.Metadata.Tags) != len(want.Metadata.Tags) {
		t.Fatalf("renew request = %+v, want %+v", got, want)
	}
}

func TestTerminalRelayFailureClosesListener(t *testing.T) {
	relayURL, err := url.Parse("https://relay.example")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	listener := &listener{
		relayURL:      relayURL,
		cancel:        func() { close(done) },
		doneCh:        done,
		statusUpdates: make(chan listenerStatus, 1),
	}
	err = fmt.Errorf("%w: unsupported protocol", errRelayIncompatible)
	if !listener.closeForTerminalRelayError(err) {
		t.Fatal("terminal relay error was not handled")
	}

	select {
	case <-done:
	default:
		t.Fatal("listener remains open after terminal relay failure")
	}
	if failure := (<-listener.statusUpdates).failure; failure != RelayFailureTerminal {
		t.Fatalf("failure = %q, want terminal", failure)
	}
}

func TestRefreshReverseEndpointAfterFailureReportsMissingLease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeLeaseNotFound, "lease not found")
	}))
	defer server.Close()

	relayURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse relay URL: %v", err)
	}
	listener := &listener{
		relayURL: relayURL,
		api:      &apiClient{relayURL: relayURL, http: server.Client()},
		lease: utils.NewSnapshot(listenerSnapshot{
			accessToken: "access-token",
			reverse: types.ReverseEndpoint{
				URL:        "https://gateway.example/sdk/connect",
				Capability: "failed-capability",
				ExpiresAt:  time.Now().UTC().Add(time.Minute),
			},
			expiresAt: time.Now().UTC().Add(time.Minute),
		}, listenerSnapshot.snapshot),
	}

	err = listener.refreshReverseEndpointAfterFailure(context.Background(), "failed-capability")
	if !errors.Is(err, errLeaseRefreshRequired) {
		t.Fatalf("refreshReverseEndpointAfterFailure() error = %v, want lease refresh required", err)
	}
}
