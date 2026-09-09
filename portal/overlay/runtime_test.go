package overlay

import (
	"crypto/sha256"
	"net"
	"testing"
	"time"

	"gosuda.org/ivnp"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

type endpointStub struct {
	ivnp.DestinationEndpoint
	destination string
}

func (e endpointStub) B32() string { return e.destination }

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
	runtime := &Runtime{
		config: Config{
			Authority:      ingressAuthority,
			Descriptors:    func() []types.RelayDescriptor { return []types.RelayDescriptor{second, first} },
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
