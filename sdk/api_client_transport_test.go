package sdk

import (
	"context"
	"net"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

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
