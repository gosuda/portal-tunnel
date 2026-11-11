package portal

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestServerStatsLeaseLifecycleAndCumulativeTraffic(t *testing.T) {
	registry, server := newStatsLeaseFixture(t)
	response := registerStatsLease(t, registry)
	left, client := net.Pipe()
	right, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	bridgeDone := make(chan struct{})
	go func() {
		defer close(bridgeDone)
		server.proxy.bridge(t.Context(), left, right, types.ServiceIdentityKey{}, registry.bps)
	}()
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("hello"))
		writeDone <- err
	}()
	drainStatsBridge(t, peer, writeDone)
	checkStatsLeaseRegistered(t, server)
	_ = client.Close()
	_ = peer.Close()
	<-bridgeDone
	unregisterStatsLease(t, registry, response)
	checkStatsLeaseUnregistered(t, server)
}

func newStatsLeaseFixture(t *testing.T) (*leaseRegistry, *Server) {
	t.Helper()
	registry := newTestRegistry(t, false, false)
	server := &Server{registry: registry}
	if got := server.Stats(); got != (ServerStats{}) {
		t.Fatalf("initial Stats() = %+v", got)
	}
	if got := (*Server)(nil).Stats(); got != (ServerStats{}) {
		t.Fatalf("nil Stats() = %+v", got)
	}
	return registry, server
}

func registerStatsLease(t *testing.T, registry *leaseRegistry) types.RegisterResponse {
	t.Helper()
	_, _, response, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "stats"),
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func checkStatsLeaseRegistered(t *testing.T, server *Server) {
	t.Helper()
	if got := server.Stats(); got.ActiveLeases != 1 || got.ActiveConnections != 1 {
		t.Fatalf("registered Stats() = %+v", got)
	}
}

func unregisterStatsLease(t *testing.T, registry *leaseRegistry, response types.RegisterResponse) {
	t.Helper()
	if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: response.AccessToken}); err != nil {
		t.Fatal(err)
	}
}

func checkStatsLeaseUnregistered(t *testing.T, server *Server) {
	t.Helper()
	if got := server.Stats(); got != (ServerStats{ForwardedBytes: 5}) {
		t.Fatalf("unregistered Stats() = %+v", got)
	}
}
func drainStatsBridge(t *testing.T, peer net.Conn, writeDone <-chan error) {
	t.Helper()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestTransportPolicyPortRange(t *testing.T) {
	for _, tc := range []struct {
		name     string
		min, max int
		valid    bool
	}{
		{"disabled", 0, 0, false},
		{"missing minimum", 0, 3000, false},
		{"missing maximum", 3000, 0, false},
		{"negative", -1, 3000, false},
		{"overflow", 3000, 65536, false},
		{"reversed", 3001, 3000, false},
		{"single port", 3000, 3000, true},
		{"full range", 1, 65535, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ServerConfig{MinPort: tc.min, MaxPort: tc.max}
			for _, udp := range []bool{false, true} {
				if err := cfg.ValidateTransportPolicy(udp, 0, !udp, 0); (err == nil) != tc.valid {
					t.Fatalf("range %d..%d, UDP %v: %v", tc.min, tc.max, udp, err)
				}
			}
			if err := cfg.ValidateTransportPolicy(false, 0, false, 0); err != nil {
				t.Fatalf("disabled transports require no port range: %v", err)
			}
		})
	}
}

func TestTransportPolicyValidationDoesNotChangeEnforcement(t *testing.T) {
	server, err := NewServer(ServerConfig{
		PortalURL: "https://localhost", StateDir: t.TempDir(),
		MinPort: 12000, MaxPort: 12010,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ValidateTransportPolicy(true, 1, true, 2); err != nil {
		t.Fatal(err)
	}
	if server.supportsUDP() || server.supportsTCP() {
		t.Fatal("validation enabled transports before the policy was applied")
	}
	if err := server.SetTransportPolicy(true, 1, true, 2); err != nil {
		t.Fatal(err)
	}
	if err := server.SetTransportPolicy(false, -1, false, 0); err == nil {
		t.Fatal("negative capacity was accepted")
	}
	if !server.supportsUDP() || !server.supportsTCP() {
		t.Fatal("rejected policy changed transport enforcement")
	}
}

func TestServerStatsConcurrentLeaseLifecycle(t *testing.T) {
	registry, server, leaseIdentity := newConcurrentStatsFixture(t)
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 100 {
				checkConcurrentStatsBounds(t, server)
			}
		}()
	}
	reregisterConcurrentLeases(t, registry, leaseIdentity)
	readers.Wait()
	checkConcurrentStatsFinal(t, server)
}

func newConcurrentStatsFixture(t *testing.T) (*leaseRegistry, *Server, types.Identity) {
	t.Helper()
	registry := newTestRegistry(t, false, false)
	server := &Server{registry: registry}
	leaseIdentity := newTestLeaseIdentity(t, "stats-concurrent")
	return registry, server, leaseIdentity
}

func checkConcurrentStatsBounds(t *testing.T, server *Server) {
	t.Helper()
	if got := server.Stats(); got.ActiveLeases < 0 || got.ActiveLeases > 1 {
		t.Errorf("Stats() during registration = %+v", got)
	}
}

func reregisterConcurrentLeases(t *testing.T, registry *leaseRegistry, leaseIdentity types.Identity) {
	t.Helper()
	for range 10 {
		_, _, response, err := registry.Register(types.RegisterChallengeRequest{
			Identity: leaseIdentity,
		}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: response.AccessToken}); err != nil {
			t.Fatal(err)
		}
	}
}

func checkConcurrentStatsFinal(t *testing.T, server *Server) {
	t.Helper()
	if got := server.Stats(); got.ActiveLeases != 0 {
		t.Fatalf("final Stats() = %+v", got)
	}
}

func TestBackhaulPendingSourcesSharesIPv6SubnetBudget(t *testing.T) {
	sources := newBackhaulPendingSources()
	held := fillSubnetBudget(t, sources)
	extra := &net.UDPAddr{IP: net.ParseIP("2001:db8:1234:5678::ffff"), Port: 23456}
	other := &net.UDPAddr{IP: net.ParseIP("2001:db8:1234:5679::1"), Port: 23456}
	checkSubnetBudgetOverflow(t, sources, extra, other)
	checkSubnetBudgetRelease(t, sources, held, extra)
}

func fillSubnetBudget(t *testing.T, sources *backhaulPendingSources) []*net.UDPAddr {
	t.Helper()
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
	return held
}

func checkSubnetBudgetOverflow(t *testing.T, sources *backhaulPendingSources, extra, other *net.UDPAddr) {
	t.Helper()
	if sources.acquire(extra) {
		t.Fatal("another address in the same /64 bypassed the subnet budget")
	}
	if !sources.acquire(other) {
		t.Fatal("a different /64 did not have an independent budget")
	}
}

func checkSubnetBudgetRelease(t *testing.T, sources *backhaulPendingSources, held []*net.UDPAddr, extra *net.UDPAddr) {
	t.Helper()
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
			rejectRedirectTarget(t, target)
		})
	}

	for _, scheme := range []string{"HTTPS", "hTtPs"} {
		t.Run(scheme, func(t *testing.T) {
			admitRedirectTarget(t, scheme)
		})
	}
}

func rejectRedirectTarget(t *testing.T, target string) {
	t.Helper()
	if _, err := NormalizeHTTPRedirectConfig(HTTPRedirectConfig{Enabled: true}, target); err == nil {
		t.Fatal("NormalizeHTTPRedirectConfig() error = nil, want invalid redirect target rejection")
	}
}

func admitRedirectTarget(t *testing.T, scheme string) {
	t.Helper()
	hsts := scheme != "HTTPS"
	cfg, err := NormalizeHTTPRedirectConfig(HTTPRedirectConfig{
		Enabled: true,
		HSTS:    hsts,
	}, scheme+"://localhost:4017/base/?configured=discarded#fragment")
	if err != nil {
		t.Fatalf("NormalizeHTTPRedirectConfig() error = %v, want %q scheme accepted", err, scheme)
	}
	if !cfg.Enabled || cfg.Addr != DefaultHTTPRedirectAddr || cfg.HSTS != hsts {
		t.Fatalf("NormalizeHTTPRedirectConfig() cfg = %+v, want enabled config with default redirect address and hsts=%v", cfg, hsts)
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
	_, _, resp, err := registry.Register(types.RegisterChallengeRequest{
		Identity:   newTestLeaseIdentity(t, "demo"),
		UDPEnabled: true,
		TCPEnabled: true,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
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
		_, _, resp, err := registry.Register(types.RegisterChallengeRequest{
			AllowCanonicalFallback: true,
			Identity:               newTestLeaseIdentity(t, "shared"),
			UDPEnabled:             true,
			TCPEnabled:             true,
		}, netip.MustParseAddr(clientIP), "", types.RelayDescriptor{}, nil, nil)
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
	_, _, registered, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "browser"),
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
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
