package portal

import (
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func signLeaseRequest(t *testing.T, token string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://example.com"+types.PathV1Sign, nil)
	if err != nil {
		t.Fatalf("build sign request: %v", err)
	}
	req.Header.Set(types.HeaderAccessToken, token)
	return req
}

func newTestRegistry(t *testing.T, udpEnabled, tcpPortEnabled bool) *leaseRegistry {
	t.Helper()
	minPort, maxPort := 0, 0
	if udpEnabled || tcpPortEnabled {
		minPort, maxPort = testPortRange(t, 2)
	}
	relay, err := identity.LoadOrCreateRelayIdentity(filepath.Join(t.TempDir(), types.RelayIdentityFilename), "example.com")
	if err != nil {
		t.Fatalf("LoadOrCreateRelayIdentity() error = %v", err)
	}
	relayAuthority := identity.NewLocalAuthority(relay.Identity)
	registry, err := newLeaseRegistry(minPort, maxPort, relay.Name, relayAuthority, "https://example.com", 0)
	if err != nil {
		t.Fatalf("newLeaseRegistry() error = %v", err)
	}
	registry.setTransportPolicy(udpEnabled, 0, tcpPortEnabled, 0)
	t.Cleanup(func() { registry.CloseAll() })
	return registry
}

func testPortRange(t *testing.T, size int) (int, int) {
	t.Helper()
	for range 100 {
		first, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 0})
		if err != nil {
			t.Fatalf("reserve ephemeral TCP port: %v", err)
		}
		minPort := first.Addr().(*net.TCPAddr).Port
		maxPort := minPort + size - 1
		listeners, available := reserveEphemeralListeners(minPort, maxPort, first)
		for _, listener := range listeners {
			_ = listener.Close()
		}
		if available {
			return minPort, maxPort
		}
	}
	t.Fatal("could not find an ephemeral port range for raw transport test")
	return 0, 0
}

func reserveEphemeralListeners(minPort, maxPort int, first io.Closer) ([]io.Closer, bool) {
	listeners := []io.Closer{first}
	available := maxPort <= 65535
	for port := minPort; available && port <= maxPort; port++ {
		if port != minPort {
			listener, listenErr := net.ListenTCP("tcp", &net.TCPAddr{Port: port})
			if listenErr != nil {
				available = false
				break
			}
			listeners = append(listeners, listener)
		}
		packet, listenErr := net.ListenUDP("udp", &net.UDPAddr{Port: port})
		if listenErr != nil {
			available = false
			break
		}
		listeners = append(listeners, packet)
	}
	return listeners, available
}

func newTestLeaseIdentity(t *testing.T, name string) types.Identity {
	t.Helper()
	testIdentity, err := identity.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("identity.ResolveSecp256k1Identity() error = %v", err)
	}
	testIdentity.Name = name
	return testIdentity
}
