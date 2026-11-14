package sdk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestRenewLeaseChecksTheRelayCertificateHourly(t *testing.T) {
	fixture := newRenewLeaseHourlyFixture(t, "tenant.test.example")
	checkHourlyLeaseKeepsPinnedChain(t, fixture)
	checkHourlyLeaseRepinsAfterInterval(t, fixture)
	checkHourlyLeaseDefersRecheck(t, fixture)
}

type renewLeaseHourlyFixture struct {
	serving     *atomic.Pointer[tls.Certificate]
	listener    *listener
	tenantTLS   *keyless.Client
	firstPool   *x509.CertPool
	renewedPool *x509.CertPool
	renewed     tls.Certificate
	later       tls.Certificate
}

func newRenewLeaseHourlyFixture(t *testing.T, tenantHostname string) *renewLeaseHourlyFixture {
	t.Helper()
	first, firstPool := generateSelfSignedTenantCert(t, tenantHostname, 1)
	renewed, renewedPool := generateSelfSignedTenantCert(t, tenantHostname, 2)
	later, _ := generateSelfSignedTenantCert(t, tenantHostname, 3)
	serving := &atomic.Pointer[tls.Certificate]{}
	serving.Store(&first)
	expiresAt := time.Now().UTC().Add(time.Minute)
	relay, relayURL, parsedRelayURL := startLeaseRenewRelay(t, expiresAt, serving)
	t.Cleanup(relay.Close)
	tenantTLS, err := keyless.NewClient(t.Context(), keyless.ClientConfig{RelayURL: relayURL, Hostname: tenantHostname, AccessToken: "access-token"})
	if err != nil {
		t.Fatalf("keyless.NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = tenantTLS.Close() })
	if !tenantTLS.TenantCertPool().Equal(firstPool) {
		t.Fatal("the tenant did not pin the certificate the relay served")
	}
	listener := &listener{
		api: &apiClient{relayURL: parsedRelayURL, http: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}},
		lease: utils.NewSnapshot(listenerSnapshot{
			accessToken:    "access-token",
			expiresAt:      expiresAt,
			tenantTLS:      tenantTLS,
			chainCheckedAt: time.Now(),
		}),
	}
	return &renewLeaseHourlyFixture{serving: serving, listener: listener, tenantTLS: tenantTLS, firstPool: firstPool, renewedPool: renewedPool, renewed: renewed, later: later}
}

func renewHourlyLease(t *testing.T, fixture *renewLeaseHourlyFixture) {
	t.Helper()
	if err := fixture.listener.renewLease(context.Background()); err != nil {
		t.Fatalf("renewLease() error = %v", err)
	}
}

func checkHourlyLeaseKeepsPinnedChain(t *testing.T, fixture *renewLeaseHourlyFixture) {
	t.Helper()
	fixture.serving.Store(&fixture.renewed)
	renewHourlyLease(t, fixture)
	if !fixture.tenantTLS.TenantCertPool().Equal(fixture.firstPool) {
		t.Fatal("renewLease() checked the relay chain again within the hour after it was found current")
	}
}

func checkHourlyLeaseRepinsAfterInterval(t *testing.T, fixture *renewLeaseHourlyFixture) {
	t.Helper()
	fixture.listener.lease.Update(func(lease listenerSnapshot) listenerSnapshot {
		lease.chainCheckedAt = time.Now().Add(-defaultChainCheckInterval)
		return lease
	})
	renewHourlyLease(t, fixture)
	if !fixture.tenantTLS.TenantCertPool().Equal(fixture.renewedPool) {
		t.Fatal("renewLease() an hour after the last check left the tenant on the replaced relay certificate")
	}
}

func checkHourlyLeaseDefersRecheck(t *testing.T, fixture *renewLeaseHourlyFixture) {
	t.Helper()
	fixture.serving.Store(&fixture.later)
	renewHourlyLease(t, fixture)
	if !fixture.tenantTLS.TenantCertPool().Equal(fixture.renewedPool) {
		t.Fatal("renewLease() checked the relay chain again right after a scheduled check")
	}
}

func generateSelfSignedTenantCert(t *testing.T, tenantHostname string, serial int64) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		DNSNames:     []string{tenantHostname},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func startLeaseRenewRelay(t *testing.T, expiresAt time.Time, serving *atomic.Pointer[tls.Certificate]) (*httptest.Server, string, *url.URL) {
	t.Helper()
	var relayURL string
	relay := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.WriteAPIData(w, http.StatusOK, types.RenewResponse{
			AccessToken:     "renewed-token",
			ExpiresAt:       expiresAt,
			ReverseEndpoint: types.ReverseEndpoint{URL: relayURL + types.PathSDKConnect, Capability: "capability", ExpiresAt: expiresAt},
		})
	}))
	relay.Listener = tls.NewListener(relay.Listener, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return serving.Load(), nil },
		NextProtos:     []string{"http/1.1"},
	})
	relay.Start()
	relayURL = "https://" + relay.Listener.Addr().String()
	parsedRelayURL, err := url.Parse(relayURL)
	if err != nil {
		t.Fatal(err)
	}
	return relay, relayURL, parsedRelayURL
}

func TestRenewLeaseSaysItRepinsTheRelayChain(t *testing.T) {
	requests := make(chan types.RenewRequest, 1)
	expiresAt := time.Now().UTC().Add(time.Minute)
	server := startRenewLeaseRepinsChainServer(t, requests, expiresAt)
	defer server.Close()
	relayURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	listener := &listener{
		api:   &apiClient{relayURL: relayURL, http: server.Client()},
		lease: utils.NewSnapshot(listenerSnapshot{accessToken: "access-token", expiresAt: expiresAt}),
	}
	_ = listener.renewLease(context.Background())
	checkRenewLeaseRepinsChainRequest(t, <-requests)
}

func startRenewLeaseRepinsChainServer(t *testing.T, requests chan types.RenewRequest, expiresAt time.Time) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req types.RenewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode renew request: %v", err)
		}
		requests <- req
		utils.WriteAPIData(w, http.StatusOK, types.RenewResponse{
			AccessToken:     "renewed-token",
			ExpiresAt:       expiresAt,
			ReverseEndpoint: types.ReverseEndpoint{URL: "http://" + r.Host + types.PathSDKConnect, Capability: "capability", ExpiresAt: expiresAt},
		})
	}))
}

func checkRenewLeaseRepinsChainRequest(t *testing.T, req types.RenewRequest) {
	t.Helper()
	if !req.RepinsChain {
		t.Fatal("renew request does not say the SDK re-pins the relay chain")
	}
}

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
			checkReverseEndpointTransport(t, relayURL, test.enabled, test.endpoint, test.wantErr)
		})
	}
}

func checkReverseEndpointTransport(t *testing.T, relayURL *url.URL, enabled bool, endpoint types.ReverseEndpoint, wantErr bool) {
	t.Helper()
	listener := &listener{api: &apiClient{relayURL: relayURL}, overlay: enabled}
	err := listener.validateReverseEndpointTransport(endpoint)
	if (err != nil) != wantErr {
		t.Fatalf("validateReverseEndpointTransport() error = %v, wantErr %v", err, wantErr)
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
	checkLoopbackDialRejected(t, ctx, socket, port)
	checkDirectDialSucceeds(t, ctx, socket)
}

func checkLoopbackDialRejected(t *testing.T, ctx context.Context, socket net.Listener, port string) {
	t.Helper()
	for _, address := range []string{socket.Addr().String(), net.JoinHostPort("localhost", port)} {
		if conn, err := reverseTCPDialer(true).DialContext(ctx, "tcp", address); err == nil {
			_ = conn.Close()
			t.Fatalf("alternate gateway dial reached loopback address %q", address)
		}
	}
}

func checkDirectDialSucceeds(t *testing.T, ctx context.Context, socket net.Listener) {
	t.Helper()
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
