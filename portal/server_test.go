package portal

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestBackhaulPendingSourcesSharesIPv6SubnetBudget(t *testing.T) {
	sources := newBackhaulPendingSources()
	var held []*net.UDPAddr
	for i := 0; i < quicBackhaulPerSourceLimit; i++ {
		ip := net.ParseIP("2001:db8:1234:5678::1")
		ip[len(ip)-1] = byte(i + 1)
		remote := &net.UDPAddr{IP: ip, Port: 12345 + i}
		if !sources.acquire(remote) {
			t.Fatalf("address %s rejected within subnet budget", remote)
		}
		held = append(held, remote)
	}
	extra := &net.UDPAddr{IP: net.ParseIP("2001:db8:1234:5678::ffff"), Port: 23456}
	if sources.acquire(extra) {
		t.Fatal("another address in the same /64 bypassed the subnet budget")
	}
	other := &net.UDPAddr{IP: net.ParseIP("2001:db8:1234:5679::1"), Port: 23456}
	if !sources.acquire(other) {
		t.Fatal("a different /64 did not have an independent budget")
	}
	sources.release(held[0])
	if !sources.acquire(extra) {
		t.Fatal("released subnet slot could not be acquired by another address")
	}
	if sources.acquire(held[0]) {
		t.Fatal("reacquiring the released subnet slot exceeded the shared budget")
	}
}

func TestNewServerRejectsPortalURLCredentialsWithoutEchoingThem(t *testing.T) {
	_, err := NewServer(ServerConfig{
		PortalURL: "https://user:secret@localhost",
		StateDir:  t.TempDir(),
	})
	if err == nil {
		t.Fatal("NewServer() error = nil, want credential rejection")
	}
	if strings.Contains(err.Error(), "user") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("NewServer() error exposes PORTAL_URL credentials: %q", err)
	}
}

func TestHTTPRedirectTargetValidation(t *testing.T) {
	for _, target := range []string{"http://localhost:4017", "http://relay.example", "//relay.example", "https://user:pass@relay.example", "https://relay.example:0", "https://relay.example:65536", "https://relay.example:bad", "https://relay.example:", "https:///missing-host", "https://./"} {
		t.Run(target, func(t *testing.T) {
			if _, err := NormalizeHTTPRedirectConfig(types.HTTPRedirectConfig{Enabled: true}, target); err == nil {
				t.Fatal("NormalizeHTTPRedirectConfig() error = nil, want invalid redirect target rejection")
			}
		})
	}

	// net/url accepts HTTPS schemes regardless of their spelling.
	for _, hsts := range []bool{false, true} {
		scheme := "HTTPS"
		if hsts {
			scheme = "hTtPs"
		}
		t.Run(scheme, func(t *testing.T) {
			cfg, err := NormalizeHTTPRedirectConfig(types.HTTPRedirectConfig{
				Enabled: true,
				HSTS:    hsts,
			}, scheme+"://localhost:4017/base/?configured=discarded#fragment")
			if err != nil {
				t.Fatalf("NormalizeHTTPRedirectConfig() error = %v, want %q scheme accepted", err, scheme)
			}
			if !cfg.Enabled || cfg.Addr != types.DefaultHTTPRedirectAddr || cfg.HSTS != hsts {
				t.Fatalf("NormalizeHTTPRedirectConfig() cfg = %+v, want enabled config with default redirect address and hsts=%v", cfg, hsts)
			}
		})
	}
}

func TestNewServerSeparatesPublicAndLocalSNIPorts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		portalURL     string
		localSNIPort  int
		wantLocalPort int
	}{
		{"default ports", "https://relay.example.com", 0, 443},
		{"local bind override", "https://relay.example.com", 8443, 8443},
		{"explicit public port", "https://relay.example.com:9443", 443, 443},
		{"unoverridden listener follows public port", "https://relay.example.com:9443", 0, 9443},
		{"explicit override keeps mapped listener", "https://localhost:8443", 443, 443},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := ValidateServerConfig(ServerConfig{
				PortalURL: tc.portalURL,
				StateDir:  t.TempDir(),
				SNIPort:   tc.localSNIPort,
			})
			if err != nil {
				t.Fatalf("ValidateServerConfig() error = %v", err)
			}
			if got := cfg.SNIPort; got != tc.wantLocalPort {
				t.Fatalf("ServerConfig.SNIPort = %d, want local port %d", got, tc.wantLocalPort)
			}
		})
	}
}

func TestRegisterLeaseWithUDPAndRawTCP(t *testing.T) {
	registry := newTestRegistry(t, true, true)
	_, resp, err := registry.Register(types.RegisterChallengeRequest{
		Identity:   newTestLeaseIdentity(t, "demo"),
		UDPEnabled: true,
		TCPEnabled: true,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("registry.Register() error = %v", err)
	}
	if !resp.UDPEnabled || !resp.TCPEnabled || resp.UDPAddr == "" || resp.TCPAddr == "" {
		t.Fatalf("RegisterResponse transports = %+v, want UDP and raw TCP endpoints", resp)
	}
	if _, ok := registry.Lookup("demo.example.com"); !ok {
		t.Fatal("Lookup(derived public hostname) = false, want registered lease")
	}
}

func TestRawPortsAreAllocatedPerIdentity(t *testing.T) {
	registry := newTestRegistry(t, true, true)
	register := func(clientIP string) types.RegisterResponse {
		t.Helper()
		_, resp, err := registry.Register(types.RegisterChallengeRequest{
			AllowCanonicalFallback: true,
			Identity:               newTestLeaseIdentity(t, "shared"),
			UDPEnabled:             true,
			TCPEnabled:             true,
		}, netip.MustParseAddr(clientIP), "", types.RelayDescriptor{}, nil)
		if err != nil {
			t.Fatalf("registry.Register() error = %v", err)
		}
		return resp
	}

	first := register("203.0.113.10")
	second := register("203.0.113.11")
	if first.UDPAddr == second.UDPAddr || first.TCPAddr == second.TCPAddr {
		t.Fatalf("different identities shared raw endpoints: first=%+v second=%+v", first, second)
	}
}

// The WebSocket carrier takes its capability only from the subprotocols, beside the
// marker; the raw carrier's header does not admit it.
func TestConnectRejectsWebSocketWithoutCapability(t *testing.T) {
	t.Parallel()

	_, relayURL, capability := newConnectTestRelay(t)
	for name, opts := range map[string]*websocket.DialOptions{
		"no capability": {Subprotocols: []string{types.ReverseSubprotocol}},
		"no marker":     {Subprotocols: []string{capability}},
		"header only": {
			Subprotocols: []string{types.ReverseSubprotocol},
		},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		socket, _, err := websocket.Dial(ctx, wsURL(relayURL), opts)
		cancel()
		if err == nil {
			_ = socket.CloseNow()
			t.Errorf("%s: Dial() error = nil, want the session refused", name)
		}
	}
}

func newConnectTestRelay(t *testing.T) (*Server, *url.URL, string) {
	t.Helper()

	registry := newTestRegistry(t, false, false)
	_, registered, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "browser"),
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	server := &Server{registry: registry}
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.HandleConnect(w, r, netip.MustParseAddr("203.0.113.10"))
	}))
	t.Cleanup(relay.Close)

	relayURL, err := url.Parse(relay.URL + types.PathSDKConnect)
	if err != nil {
		t.Fatal(err)
	}
	return server, relayURL, registered.ReverseEndpoint.Capability
}

func wsURL(relayURL *url.URL) string {
	return strings.Replace(relayURL.String(), "http://", "ws://", 1)
}

func TestPublicIngressAggregateAdmissionAndRelease(t *testing.T) {
	var server Server
	var conns []net.Conn
	for range publicIngressLimit {
		conn, peer := net.Pipe()
		t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
		if !server.admitIngress(conn, false) {
			t.Fatal("connection below aggregate limit rejected")
		}
		conns = append(conns, conn)
	}
	extra, peer := net.Pipe()
	defer extra.Close()
	defer peer.Close()
	if server.admitIngress(extra, false) {
		t.Fatal("raw TCP bypassed tenant connection budget")
	}
	if !server.admitIngress(extra, true) {
		t.Fatal("tenant saturation blocked root inspection")
	}
	if server.promoteIngress() {
		t.Fatal("SNI tenant bypassed tenant connection budget")
	}
	server.releaseIngress(conns[0], false)
	if !server.promoteIngress() {
		t.Fatal("released tenant capacity was not reusable")
	}
	server.closeIngress()
	if server.admitIngress(conns[0], false) {
		t.Fatal("connection admitted after shutdown")
	}
	server.releaseIngress(extra, false)
	for _, conn := range conns[1:] {
		server.releaseIngress(conn, false)
	}
	server.ingressWorkers.Wait()
}
