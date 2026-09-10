package overlay

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"gosuda.org/ivnp"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/types"
)

type endpointStub struct {
	ivnp.DestinationEndpoint
	destination string
	dial        func(context.Context, string) (net.Conn, error)
}

func (e endpointStub) B32() string { return e.destination }

func (e endpointStub) DialI2P(ctx context.Context, address string) (net.Conn, error) {
	return e.dial(ctx, address)
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
	return ivnp.B32(sha256.Sum256([]byte(seed)))
}

func testDescriptor(t *testing.T, authority identity.Authority, rawURL, destination string, connections int64) types.RelayDescriptor {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	descriptor, err := auth.SignRelayDescriptor(types.RelayDescriptor{
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
		dial: func(context.Context, string) (net.Conn, error) {
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
		dial: func(ctx context.Context, _ string) (net.Conn, error) {
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
