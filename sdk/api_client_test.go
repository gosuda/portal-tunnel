package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
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

func signTestReverseGateway(t *testing.T, rawURL string, expiresAt time.Time) types.RelayDescriptor {
	t.Helper()
	signer, err := identity.Generate("gateway")
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Now().UTC().Add(-time.Minute)
	descriptor, err := discovery.SignRelayDescriptor(types.RelayDescriptor{
		Address:         signer.Address,
		IssuedAt:        issuedAt,
		ExpiresAt:       expiresAt,
		APIHTTPSAddr:    rawURL,
		IVNPDestination: strings.Repeat("a", 52) + ".b32.i2p",
	}, identity.NewLocalAuthority(signer))
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func TestValidateReverseEndpointTransport(t *testing.T) {
	t.Parallel()
	relayURL, err := url.Parse("https://relay.example")
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().UTC().Add(time.Minute)
	gateway := signTestReverseGateway(t, "https://gateway.example", expiry.Add(time.Minute))
	otherGateway := signTestReverseGateway(t, "https://other.example", expiry.Add(time.Minute))
	localGateway := signTestReverseGateway(t, "https://127.0.0.1", expiry.Add(time.Minute))
	privateGateway := signTestReverseGateway(t, "https://10.2.3.4", expiry.Add(time.Minute))
	linkLocalGateway := signTestReverseGateway(t, "https://169.254.169.254", expiry.Add(time.Minute))
	localhostGateway := signTestReverseGateway(t, "https://service.localhost", expiry.Add(time.Minute))
	shortGateway := signTestReverseGateway(t, "https://gateway.example", expiry.Add(-time.Second))
	tamperedGateway := gateway
	tamperedGateway.APIHTTPSAddr = "https://another.example"

	direct := types.ReverseEndpoint{URL: "https://relay.example/sdk/connect"}
	overlay := types.ReverseEndpoint{URL: "https://gateway.example/sdk/connect", Overlay: true, ExpiresAt: expiry, Gateway: &gateway}
	legacyOverlay := types.ReverseEndpoint{URL: "https://gateway.example/sdk/connect"}

	for name, test := range map[string]struct {
		enabled  bool
		endpoint types.ReverseEndpoint
		wantErr  bool
	}{
		"direct":               {endpoint: direct},
		"overlay disabled":     {endpoint: overlay, wantErr: true},
		"overlay enabled":      {enabled: true, endpoint: overlay, wantErr: runtime.GOOS == "js"},
		"fallback direct":      {enabled: true, endpoint: direct},
		"legacy overlay":       {endpoint: legacyOverlay, wantErr: true},
		"unmarked alternate":   {enabled: true, endpoint: legacyOverlay, wantErr: true},
		"missing gateway":      {enabled: true, endpoint: types.ReverseEndpoint{URL: overlay.URL, Overlay: true, ExpiresAt: expiry}, wantErr: true},
		"unbound gateway":      {enabled: true, endpoint: types.ReverseEndpoint{URL: overlay.URL, Overlay: true, ExpiresAt: expiry, Gateway: &otherGateway}, wantErr: true},
		"tampered descriptor":  {enabled: true, endpoint: types.ReverseEndpoint{URL: overlay.URL, Overlay: true, ExpiresAt: expiry, Gateway: &tamperedGateway}, wantErr: true},
		"short gateway expiry": {enabled: true, endpoint: types.ReverseEndpoint{URL: overlay.URL, Overlay: true, ExpiresAt: expiry, Gateway: &shortGateway}, wantErr: true},
		"loopback":             {enabled: true, endpoint: types.ReverseEndpoint{URL: "https://127.0.0.1/sdk/connect", Overlay: true, ExpiresAt: expiry, Gateway: &localGateway}, wantErr: true},
		"private":              {enabled: true, endpoint: types.ReverseEndpoint{URL: "https://10.2.3.4/sdk/connect", Overlay: true, ExpiresAt: expiry, Gateway: &privateGateway}, wantErr: true},
		"link-local":           {enabled: true, endpoint: types.ReverseEndpoint{URL: "https://169.254.169.254/sdk/connect", Overlay: true, ExpiresAt: expiry, Gateway: &linkLocalGateway}, wantErr: true},
		"localhost suffix":     {enabled: true, endpoint: types.ReverseEndpoint{URL: "https://service.localhost/sdk/connect", Overlay: true, ExpiresAt: expiry, Gateway: &localhostGateway}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			listener := &listener{api: &apiClient{relayURL: relayURL}, overlay: test.enabled}
			err := listener.validateReverseEndpointTransport(test.endpoint)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateReverseEndpointTransport() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestReverseTCPDialerChecksResolvedAddress(t *testing.T) {
	t.Parallel()
	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, port, err := net.SplitHostPort(socket.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// The hostname case verifies enforcement after DNS resolution, not just
	// rejection of literal IP addresses before dialing.
	for _, address := range []string{socket.Addr().String(), net.JoinHostPort("localhost", port)} {
		if conn, err := reverseTCPDialer(true).DialContext(ctx, "tcp", address); err == nil {
			_ = conn.Close()
			t.Fatalf("alternate gateway dial reached loopback address %q", address)
		}
	}
	// Explicitly configured direct relays retain local development support.
	conn, err := reverseTCPDialer(false).DialContext(ctx, "tcp", socket.Addr().String())
	if err != nil {
		t.Fatalf("direct relay dial: %v", err)
	}
	_ = conn.Close()
}

func TestReverseTLSBootstrapRejectsAlternateLocalHost(t *testing.T) {
	t.Parallel()
	relay, err := url.Parse("https://relay.example")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := url.Parse("https://127.0.0.1:443/sdk/connect")
	if err != nil {
		t.Fatal(err)
	}
	l := &listener{api: &apiClient{relayURL: relay}}
	if _, err := l.reverseTLSConfig(context.Background(), endpoint); err == nil || !strings.Contains(err.Error(), "local-only") {
		t.Fatalf("reverseTLSConfig() error = %v, want local host rejection before TLS bootstrap", err)
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
		}, listenerSnapshot.snapshot),
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
		}, listenerSnapshot.snapshot),
	}

	if err := listener.renewLease(context.Background()); !errors.Is(err, errLeaseRefreshRequired) {
		t.Fatalf("renewLease() error = %v, want lease refresh required after authority rotation", err)
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
