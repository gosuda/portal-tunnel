package overlay

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/foundation"

	"github.com/gosuda/portal-tunnel/v2/internal/discovery"
	"github.com/gosuda/portal-tunnel/v2/internal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/types"
)

type endpointStub struct {
	destination string
	dial        func(context.Context, string, string) (net.Conn, error)
}

func (e endpointStub) B32() string { return e.destination }

func (e endpointStub) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return e.dial(ctx, network, address)
}

func testAuthority(t *testing.T, name string) identity.Authority {
	t.Helper()
	relay, err := identity.LoadOrCreateRelayIdentity(t.TempDir(), name+".example")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := identity.NewLocalAuthority(relay.Identity)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func testDestination(seed string) string {
	return foundation.B32(sha256.Sum256([]byte(seed)))
}

func testDescriptor(t *testing.T, authority identity.Authority, rawURL, destination string, connections int64) types.RelayDescriptor {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	descriptor, err := identity.SignRelayDescriptor(types.RelayDescriptor{
		Address:           authority.Identity().Address,
		Version:           types.DiscoveryVersion,
		IssuedAt:          now,
		ExpiresAt:         now.Add(5 * time.Minute),
		APIHTTPSAddr:      rawURL,
		IVNPDestination:   destination,
		ActiveConnections: connections,
	}, authority)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func TestCapabilityBindsIngressGatewayAndLease(t *testing.T) {
	t.Parallel()
	ingressAuthority := testAuthority(t, "ingress")
	gatewayAuthority := testAuthority(t, "gateway")
	ingress := testDescriptor(t, ingressAuthority, "https://ingress.example", testDestination("ingress"), 0)
	claims := capabilityClaims{
		Version:            1,
		LeaseIdentity:      types.Identity{Name: "lease", Address: ingressAuthority.Identity().Address},
		LeaseID:            "lease_1",
		ExpiresAt:          time.Now().UTC().Add(time.Minute).Truncate(time.Second),
		Ingress:            ingress,
		GatewayAddress:     gatewayAuthority.Identity().Address,
		GatewayDestination: testDestination("gateway"),
	}
	capability, err := signCapability(ingressAuthority, claims)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifyCapability(capability, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if verified.LeaseID != claims.LeaseID || verified.GatewayDestination != claims.GatewayDestination || verified.Ingress.IVNPDestination != claims.Ingress.IVNPDestination {
		t.Fatalf("verified capability = %#v", verified)
	}

	wrongSigner, err := signCapability(gatewayAuthority, claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyCapability(wrongSigner, time.Now().UTC()); err == nil {
		t.Fatal("capability signed by gateway was accepted as ingress capability")
	}
}

func TestIssueEndpointRotatesGatewayWithoutChangingLease(t *testing.T) {
	t.Parallel()
	ingressAuthority := testAuthority(t, "ingress")
	firstAuthority := testAuthority(t, "first")
	secondAuthority := testAuthority(t, "second")
	ingressDestination := testDestination("ingress")
	ingress := testDescriptor(t, ingressAuthority, "https://ingress.example", ingressDestination, 0)
	first := testDescriptor(t, firstAuthority, "https://first.example", testDestination("first"), 1)
	second := testDescriptor(t, secondAuthority, "https://second.example", testDestination("second"), 2)
	relays := discovery.NewRelaySet(nil)
	for _, descriptor := range []types.RelayDescriptor{first, second} {
		_, err := relays.ApplyRelayDiscoveryResponse(descriptor.APIHTTPSAddr, types.DiscoveryResponse{
			ProtocolVersion: types.DiscoveryVersion,
			Relays:          []types.RelayDescriptor{descriptor},
		}, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(relays.ConfirmedRelays()) != 0 {
		t.Fatal("discovery must not require SDK listener confirmation")
	}
	runtime := &Runtime{
		config: Config{
			Authority:      ingressAuthority,
			Descriptors:    func() []types.RelayDescriptor { return relays.Descriptors(types.RelayDescriptor{}) },
			SelfDescriptor: func(time.Time) (types.RelayDescriptor, error) { return ingress, nil },
			OfferReverse:   func(string, string, net.Conn, func() error) error { return nil },
			Bridge:         func(net.Conn, net.Conn) {},
		},
		endpoint:    endpointStub{destination: ingressDestination},
		assignments: make(map[string]string),
		failures:    make(map[string]map[string]time.Time),
	}
	runtime.ready.Store(true)
	leaseIdentity := types.Identity{Name: "lease", Address: ingressAuthority.Identity().Address}
	expiresAt := time.Now().UTC().Add(time.Minute)

	initial, ok, err := runtime.IssueEndpoint(leaseIdentity, "lease_1", expiresAt, "")
	if err != nil || !ok || initial.URL != "https://first.example/sdk/connect" {
		t.Fatalf("initial endpoint = %#v, %v, %v", initial, ok, err)
	}
	replacement, ok, err := runtime.IssueEndpoint(leaseIdentity, "lease_1", expiresAt, initial.URL)
	if err != nil || !ok || replacement.URL != "https://second.example/sdk/connect" {
		t.Fatalf("replacement endpoint = %#v, %v, %v", replacement, ok, err)
	}
	if endpoint, ok, err := runtime.IssueEndpoint(leaseIdentity, "lease_1", expiresAt, replacement.URL); err != nil || ok || endpoint.URL != "" {
		t.Fatalf("exhausted gateways did not fall back to direct transport: %#v, %v, %v", endpoint, ok, err)
	}
}

func TestGatewayLimitsSourceRequestsBeforeDial(t *testing.T) {
	t.Parallel()
	gate, capability := testGateway(t)
	var dials int
	gate.endpoint = endpointStub{
		destination: testDestination("gateway"),
		dial: func(context.Context, string, string) (net.Conn, error) {
			dials++
			return nil, errors.New("dial failed")
		},
	}
	// A fresh ingress signer is enough to pass signature checks. Source
	// admission must still bound these requests without any discovery catalog.
	gate.sourceLimiter = policy.NewSourceLimiter(1, 2)
	for range 2 {
		response := httptest.NewRecorder()
		gate.HandleConnect(response, httptest.NewRequest(http.MethodGet, "/sdk/connect", nil), capability, "192.0.2.1")
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("failed dial status = %d", response.Code)
		}
	}
	response := httptest.NewRecorder()
	gate.HandleConnect(response, httptest.NewRequest(http.MethodGet, "/sdk/connect", nil), capability, "192.0.2.1")
	if response.Code != http.StatusTooManyRequests || dials != 2 {
		t.Fatalf("rate-limited request: status=%d dials=%d", response.Code, dials)
	}
	other := httptest.NewRecorder()
	gate.HandleConnect(other, httptest.NewRequest(http.MethodGet, "/sdk/connect", nil), capability, "192.0.2.2")
	if other.Code != http.StatusServiceUnavailable || dials != 3 {
		t.Fatalf("other source: status=%d dials=%d", other.Code, dials)
	}
	if gate.outbound != 0 || len(gate.activeSources) != 0 {
		t.Fatal("failed dials retained capacity")
	}
}

func TestGatewayReservesCapacityForOtherSources(t *testing.T) {
	t.Parallel()
	gate, capability := testGateway(t)
	gate.sourceLimiter = policy.NewSourceLimiter(1000, 1000)
	entered := make(chan struct{}, sourceConnectionLimit)
	release := make(chan struct{})
	var dials atomic.Int32
	gate.endpoint = endpointStub{
		destination: testDestination("gateway"),
		dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dials.Add(1)
			entered <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil, errors.New("dial failed")
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{}, sourceConnectionLimit+1)
	for range sourceConnectionLimit {
		go func() {
			defer func() { done <- struct{}{} }()
			request := httptest.NewRequest(http.MethodGet, "/sdk/connect", nil).WithContext(ctx)
			gate.HandleConnect(httptest.NewRecorder(), request, capability, "192.0.2.1")
		}()
	}
	for range sourceConnectionLimit {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("source connections did not enter the dial")
		}
	}
	response := httptest.NewRecorder()
	gate.HandleConnect(response, httptest.NewRequest(http.MethodGet, "/sdk/connect", nil), capability, "192.0.2.1")
	if response.Code != http.StatusTooManyRequests || dials.Load() != sourceConnectionLimit {
		t.Fatalf("source capacity: status=%d dials=%d", response.Code, dials.Load())
	}
	go func() {
		defer func() { done <- struct{}{} }()
		request := httptest.NewRequest(http.MethodGet, "/sdk/connect", nil).WithContext(ctx)
		gate.HandleConnect(httptest.NewRecorder(), request, capability, "192.0.2.2")
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("one source's full budget blocked a different source")
	}
	// Release pending calls, then prove their reservations are reusable.
	close(release)
	for range sourceConnectionLimit + 1 {
		<-done
	}
	for _, source := range []string{"192.0.2.1", "192.0.2.2"} {
		response := httptest.NewRecorder()
		gate.HandleConnect(response, httptest.NewRequest(http.MethodGet, "/sdk/connect", nil), capability, source)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("released capacity for %s: status=%d", source, response.Code)
		}
	}
	if gate.outbound != 0 || len(gate.activeSources) != 0 {
		t.Fatal("released connections retained capacity")
	}
}

func testGateway(t *testing.T) (*Runtime, string) {
	t.Helper()
	ingressAuthority := testAuthority(t, "ingress")
	gatewayAuthority := testAuthority(t, "gateway")
	ingress := testDescriptor(t, ingressAuthority, "https://ingress.example", testDestination("ingress"), 0)
	capability, err := signCapability(ingressAuthority, capabilityClaims{
		Version:            1,
		LeaseIdentity:      types.Identity{Name: "lease", Address: ingressAuthority.Identity().Address},
		LeaseID:            "lease_1",
		ExpiresAt:          time.Now().UTC().Add(time.Minute),
		Ingress:            ingress,
		GatewayAddress:     gatewayAuthority.Identity().Address,
		GatewayDestination: testDestination("gateway"),
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{
		config:        Config{Authority: gatewayAuthority},
		activeSources: make(map[string]int),
	}
	runtime.ready.Store(true)
	return runtime, capability
}

type peerConn struct {
	net.Conn
	remote net.Addr
}

func (c peerConn) RemoteAddr() net.Addr { return c.remote }

func TestDialRequiresAuthenticatedIVNPPeer(t *testing.T) {
	hash := sha256.Sum256([]byte("ingress"))
	destination := foundation.B32(hash)
	for _, tc := range []struct {
		name   string
		remote net.Addr
		accept bool
	}{
		{name: "authenticated destination", remote: ivnp.Addr{Hash: hash, Port: 4017}, accept: true},
		{name: "wrong destination", remote: ivnp.Addr{Hash: sha256.Sum256([]byte("other")), Port: 4017}},
		{name: "missing identity", remote: ivnp.Addr{Port: 4017}},
		{name: "unbound peer", remote: ivnp.Addr{Hash: hash}},
		{name: "untrusted address text", remote: &net.UnixAddr{Net: "i2p", Name: destination + ":4017"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local, remote := net.Pipe()
			defer local.Close()
			defer remote.Close()
			if err := remote.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			runtime := &Runtime{endpoint: endpointStub{
				destination: testDestination("gateway"),
				dial: func(_ context.Context, network, address string) (net.Conn, error) {
					if network != "i2p" || address != net.JoinHostPort(destination, streamPort) {
						t.Fatalf("dial = %q %q, want destination-owned I2P stream", network, address)
					}
					return peerConn{Conn: local, remote: tc.remote}, nil
				},
			}}
			conn, err := runtime.dial(t.Context(), destination)
			if tc.accept {
				if err != nil || conn == nil {
					t.Fatalf("authenticated dial = %v, %v", conn, err)
				}
				return
			}
			if err == nil || conn != nil {
				t.Fatalf("untrusted dial = %v, %v", conn, err)
			}
			if _, err := remote.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("rejected peer connection was not closed: %v", err)
			}
		})
	}
}

func TestStartRejectsInvalidRouterConfiguration(t *testing.T) {
	for _, content := range []string{
		"", "null", "[router]\n", `{"Unknown":true}`, `{} {}`,
		`{"NetworkID":256}`, `{"Logger":{}}`,
	} {
		t.Run(content, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ivnp.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			runtime := &Runtime{config: Config{ConfigPath: path}}
			defer runtime.Close()
			if err := runtime.Start(t.Context()); err == nil {
				t.Fatal("invalid IVNP configuration was accepted")
			}
			if runtime.router != nil {
				t.Fatal("invalid configuration started a router")
			}
		})
	}
}

func TestUnavailableOverlayStartsAndShutsDownWithoutPeers(t *testing.T) {
	for _, mode := range []string{"cancel run", "close runtime"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "ivnp.json")
			config := `{"Bootstrap":{"ReseedURLs":[]},"NTCP2":{"Bind":"127.0.0.1:0"},"SSU2":{"Bind":"127.0.0.1:0"}}`
			if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}
			runtime := &Runtime{config: Config{ConfigPath: path}}
			defer runtime.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if err := runtime.Start(ctx); err != nil {
				t.Fatalf("local startup without peers: %v", err)
			}
			if endpoint, useOverlay, err := runtime.IssueEndpoint(types.Identity{}, "", time.Time{}, ""); err != nil || useOverlay || endpoint.URL != "" {
				t.Fatalf("unavailable overlay must retain direct fallback: %v, %v, %v", endpoint, useOverlay, err)
			}
			runCtx, cancelRun := context.WithCancel(ctx)
			defer cancelRun()
			done := make(chan error, 1)
			go func() { done <- runtime.Run(runCtx) }()
			if mode == "cancel run" {
				cancelRun()
			} else {
				runtime.Close()
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("overlay shutdown: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("shutdown did not cancel destination warmup")
			}
			if runtime.Destination() != "" || runtime.ctx.Err() == nil {
				t.Fatal("shutdown left the overlay available")
			}
			if err := runtime.router.WaitReady(t.Context()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("shutdown did not close the IVNP router: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("in-memory router wrote state beside configuration: %v, %v", entries, err)
			}
		})
	}
}
