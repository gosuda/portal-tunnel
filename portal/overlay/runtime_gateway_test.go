package overlay

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

var errDialFailed = errors.New("dial failed")

type endpointStub struct {
	destination string
	dial        func(context.Context, string, string) (net.Conn, error)
}

func (e endpointStub) B32() string { return e.destination }

func (e endpointStub) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return e.dial(ctx, network, address)
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
		activeSources: make(map[netip.Addr]int),
	}
	runtime.ready.Store(true)
	return runtime, capability
}

func TestGatewayLimitsSourceRequestsBeforeDial(t *testing.T) {
	t.Parallel()
	gate, capability := testGateway(t)
	dials := 0
	gate.endpoint = endpointStub{
		destination: testDestination("gateway"),
		dial: func(context.Context, string, string) (net.Conn, error) {
			dials++
			return nil, errDialFailed
		},
	}
	gate.sourceLimiter = newSourceLimiter(1, 2)
	for range 2 {
		response := httptest.NewRecorder()
		gate.HandleConnect(response, httptest.NewRequest(http.MethodGet, "/sdk/connect", nil), capability, netip.MustParseAddr("192.0.2.1"))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("dial-failed request status = %d, want %d", response.Code, http.StatusServiceUnavailable)
		}
	}
	response := httptest.NewRecorder()
	gate.HandleConnect(response, httptest.NewRequest(http.MethodGet, "/sdk/connect", nil), capability, netip.MustParseAddr("192.0.2.1"))
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited request status = %d, want %d", response.Code, http.StatusTooManyRequests)
	}
	if dials != 2 {
		t.Fatalf("dial invocations = %d, want 2: the over-budget request must not reach the dial", dials)
	}
}

func TestGatewayReservesCapacityForOtherSources(t *testing.T) {
	t.Parallel()
	gate, capability := testGateway(t)
	gate.sourceLimiter = newSourceLimiter(1000, 1000)
	entered := make(chan struct{}, sourceConnectionLimit+1)
	release := make(chan struct{})
	gate.endpoint = newBlockingGatewayEndpoint(t, entered, release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{}, sourceConnectionLimit+1)
	for range sourceConnectionLimit {
		go runGatewayConnectForSource(t, ctx, gate, capability, "192.0.2.1", done)
	}
	checkGatewaySourcesEntered(t, entered)
	checkGatewayOverBudgetRejected(t, gate, capability)
	go runGatewayConnectForSource(t, ctx, gate, capability, "192.0.2.2", done)
	checkOtherGatewaySourceEntered(t, entered)
	close(release)
	for range sourceConnectionLimit + 1 {
		<-done
	}
	checkGatewayCapacityReleased(t, gate, capability)
}

func newBlockingGatewayEndpoint(t *testing.T, entered chan struct{}, release chan struct{}) endpointStub {
	t.Helper()
	return endpointStub{
		destination: testDestination("gateway"),
		dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			entered <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil, errDialFailed
		},
	}
}

func runGatewayConnectForSource(t *testing.T, ctx context.Context, gate *Runtime, capability, source string, done chan struct{}) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/sdk/connect", nil).WithContext(ctx)
	gate.HandleConnect(httptest.NewRecorder(), request, capability, netip.MustParseAddr(source))
	done <- struct{}{}
}

func checkGatewaySourcesEntered(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	for range sourceConnectionLimit {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("source connections did not enter the dial")
		}
	}
}

func checkGatewayOverBudgetRejected(t *testing.T, gate *Runtime, capability string) {
	t.Helper()
	response := httptest.NewRecorder()
	gate.HandleConnect(response, httptest.NewRequest(http.MethodGet, "/sdk/connect", nil), capability, netip.MustParseAddr("192.0.2.1"))
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("over-budget source status = %d, want %d", response.Code, http.StatusTooManyRequests)
	}
}

func checkOtherGatewaySourceEntered(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("one source's full budget blocked a different source")
	}
}

func checkGatewayCapacityReleased(t *testing.T, gate *Runtime, capability string) {
	t.Helper()
	for _, source := range []string{"192.0.2.1", "192.0.2.2"} {
		response := httptest.NewRecorder()
		gate.HandleConnect(response, httptest.NewRequest(http.MethodGet, "/sdk/connect", nil), capability, netip.MustParseAddr(source))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("released capacity for %s: status=%d", source, response.Code)
		}
	}
}
