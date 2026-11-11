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

	checkReverseEndpointRejects(t, leaseExpiry)
}

func checkReverseEndpointRejects(t *testing.T, leaseExpiry time.Time) {
	t.Helper()
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

func TestAPIClientRejectsTunnelProtocolMismatch(t *testing.T) {
	t.Parallel()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != types.PathSDKDomain {
			http.NotFound(w, r)
			return
		}
		utils.WriteAPIData(w, http.StatusOK, types.DomainResponse{ProtocolVersion: types.SDKVersion + "-legacy"})
	}))
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()

	relayURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &apiClient{relayURL: relayURL}
	if err := client.initHTTPTransport(context.Background()); !errors.Is(err, errRelayIncompatible) {
		t.Fatalf("initHTTPTransport() error = %v, want relay incompatibility", err)
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
	server := startAPIClientRenewExplicitServer(t, requestCh, expiresAt)
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
	checkAPIClientRenewExplicitRequest(t, got, want)
}

func startAPIClientRenewExplicitServer(t *testing.T, requestCh chan types.RenewRequest, expiresAt time.Time) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}

func checkAPIClientRenewExplicitRequest(t *testing.T, got, want types.RenewRequest) {
	t.Helper()
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
		api:           &apiClient{relayURL: relayURL},
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
		api: &apiClient{relayURL: relayURL, http: server.Client()},
		lease: utils.NewSnapshot(listenerSnapshot{
			accessToken: "access-token",
			reverse: types.ReverseEndpoint{
				URL:        "https://gateway.example/sdk/connect",
				Capability: "failed-capability",
				ExpiresAt:  time.Now().UTC().Add(time.Minute),
			},
			expiresAt: time.Now().UTC().Add(time.Minute),
		}),
	}

	err = listener.refreshReverseEndpointAfterFailure(context.Background(), "failed-capability")
	if !errors.Is(err, errLeaseRefreshRequired) {
		t.Fatalf("refreshReverseEndpointAfterFailure() error = %v, want lease refresh required", err)
	}
}

func TestRenewLeaseReportsStaleCredentialsAfterAuthorityRotation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		utils.WriteAPIError(w, http.StatusUnauthorized, types.APIErrorCodeUnauthorized, "unauthorized")
	}))
	defer server.Close()

	relayURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse relay URL: %v", err)
	}
	listener := &listener{
		api: &apiClient{relayURL: relayURL, http: server.Client()},
		lease: utils.NewSnapshot(listenerSnapshot{
			accessToken: "stale-access-token",
			expiresAt:   time.Now().UTC().Add(time.Minute),
		}),
	}

	if err := listener.renewLease(context.Background()); !errors.Is(err, errLeaseRefreshRequired) {
		t.Fatalf("renewLease() error = %v, want lease refresh required after authority rotation", err)
	}
}

func TestRenewLeaseRegistersAgainWhenTheRelayAnswersLeaseNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeLeaseNotFound, "lease not found")
	}))
	defer server.Close()
	relayURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	listener := &listener{
		api: &apiClient{relayURL: relayURL, http: server.Client()},
		lease: utils.NewSnapshot(listenerSnapshot{
			accessToken: "pinned-once-access-token",
			expiresAt:   time.Now().UTC().Add(time.Minute),
		}),
	}
	if err := listener.renewLease(context.Background()); !errors.Is(err, errLeaseRefreshRequired) {
		t.Fatalf("renewLease() error = %v, want lease refresh required", err)
	}
}

func TestRegisterRateLimitWaitIsCancelable(t *testing.T) {
	t.Parallel()
	limited := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "try later")
		close(limited)
	}))
	defer server.Close()
	relayURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &apiClient{relayURL: relayURL, http: server.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := client.register(ctx, types.RegisterChallengeRequest{}, ""); result <- err }()
	<-limited
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel registration: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("registration ignored cancellation during rate-limit wait")
	}
}

func TestRateLimitsNeverPermanentlyDisqualifyRelay(t *testing.T) {
	for _, apiErr := range []*types.APIRequestError{
		{StatusCode: http.StatusTooManyRequests},
		{Code: types.APIErrorCodeRateLimited},
		{StatusCode: http.StatusBadRequest, Code: types.APIErrorCodeRateLimited},
	} {
		if isTerminalRelayError(fmt.Errorf("register: %w", apiErr)) {
			t.Fatalf("temporary admission error is terminal: %v", apiErr)
		}
	}
	if !isTerminalRelayError(&types.APIRequestError{StatusCode: http.StatusForbidden, Code: types.APIErrorCodeUnauthorized}) {
		t.Fatal("authorization rejection stopped being terminal")
	}
}

func TestAliasHostnameMatches(t *testing.T) {
	t.Parallel()

	const canonical = "demo-0123456789abcdef0123456789abcdef01234567.relay.example"
	tests := []struct {
		name, hostname, service string
		want                    bool
	}{
		{"no alias", "", "demo", true},
		{"own alias", "demo.relay.example", "demo", true},
		{"normalized name", "demo.relay.example", "Demo", true},
		{"other name", "other.relay.example", "demo", false},
		{"other root", "demo.other.example", "demo", false},
		{"unnamed service", "demo.relay.example", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := aliasHostnameMatches(tc.hostname, tc.service, canonical); got != tc.want {
				t.Fatalf("aliasHostnameMatches(%q, %q) = %v, want %v", tc.hostname, tc.service, got, tc.want)
			}
		})
	}
}
