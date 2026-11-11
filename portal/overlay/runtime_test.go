package overlay

import (
	"crypto/sha256"
	"testing"
	"time"

	"gosuda.org/ivnp/foundation"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func testAuthority(t *testing.T, name string) identity.Authority {
	t.Helper()
	generated, err := identity.Generate("relay")
	if err != nil {
		t.Fatal(err)
	}
	generated.Name = name
	return identity.NewLocalAuthority(generated)
}

func testDestination(seed string) string {
	return foundation.B32(sha256.Sum256([]byte(seed)))
}

func testDescriptor(t *testing.T, authority identity.Authority, rawURL, destination string, connections int64) types.RelayDescriptor {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	descriptor, err := discovery.SignRelayDescriptor(types.RelayDescriptor{
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
	relays := newRotationRelaySet(t, first, second)
	runtime := newRotationRuntime(t, ingressAuthority, ingressDestination)
	input := IssueInput{
		LeaseIdentity: types.Identity{Name: "lease", Address: ingressAuthority.Identity().Address},
		LeaseID:       "lease_1",
		ExpiresAt:     time.Now().UTC().Add(time.Minute),
		Self:          ingress,
		Descriptors:   relays.Descriptors(types.RelayDescriptor{}),
	}
	initial := checkInitialEndpoint(t, runtime, input, first)
	input.FailedURL = initial.URL
	replacement := checkReplacementEndpoint(t, runtime, input, second)
	input.FailedURL = replacement.URL
	checkExhaustedEndpoints(t, runtime, input)
}

func newRotationRelaySet(t *testing.T, first, second types.RelayDescriptor) *discovery.RelaySet {
	t.Helper()
	relays := discovery.NewRelaySet(nil)
	for _, descriptor := range []types.RelayDescriptor{first, second} {
		if _, err := relays.ApplyRelayDiscoveryResponse(descriptor.APIHTTPSAddr, types.DiscoveryResponse{
			ProtocolVersion: types.DiscoveryVersion,
			Relays:          []types.RelayDescriptor{descriptor},
		}, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	return relays
}

func newRotationRuntime(t *testing.T, authority identity.Authority, ingressDestination string) *Runtime {
	t.Helper()
	runtime := &Runtime{
		config:      Config{Authority: authority},
		endpoint:    endpointStub{destination: ingressDestination},
		assignments: make(map[string]string),
		failures:    make(map[string]map[string]time.Time),
	}
	runtime.ready.Store(true)
	return runtime
}

func checkInitialEndpoint(t *testing.T, runtime *Runtime, input IssueInput, first types.RelayDescriptor) types.ReverseEndpoint {
	t.Helper()
	initial, ok, err := runtime.IssueEndpoint(input)
	if err != nil || !ok || initial.URL != "https://first.example/sdk/connect" {
		t.Fatalf("initial endpoint = %#v, %v, %v", initial, ok, err)
	}
	if initial.Gateway == nil || initial.Gateway.APIHTTPSAddr != first.APIHTTPSAddr {
		t.Fatalf("initial endpoint gateway = %#v, want signed first descriptor", initial.Gateway)
	}
	if _, err := discovery.VerifyRelayDescriptor(*initial.Gateway); err != nil {
		t.Fatalf("initial gateway descriptor is not signed: %v", err)
	}
	return initial
}

func checkReplacementEndpoint(t *testing.T, runtime *Runtime, input IssueInput, second types.RelayDescriptor) types.ReverseEndpoint {
	t.Helper()
	replacement, ok, err := runtime.IssueEndpoint(input)
	if err != nil || !ok || replacement.URL != "https://second.example/sdk/connect" {
		t.Fatalf("replacement endpoint = %#v, %v, %v", replacement, ok, err)
	}
	if replacement.Gateway == nil || replacement.Gateway.APIHTTPSAddr != second.APIHTTPSAddr {
		t.Fatalf("replacement endpoint gateway = %#v, want signed second descriptor", replacement.Gateway)
	}
	return replacement
}

func checkExhaustedEndpoints(t *testing.T, runtime *Runtime, input IssueInput) {
	t.Helper()
	if endpoint, ok, err := runtime.IssueEndpoint(input); err != nil || ok || endpoint.URL != "" {
		t.Fatalf("exhausted gateways did not fall back to direct transport: %#v, %v, %v", endpoint, ok, err)
	}
}
