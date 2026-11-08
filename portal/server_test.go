package portal

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestServerStatsLeaseLifecycleAndCumulativeTraffic(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	server := &Server{registry: registry}
	if got := server.Stats(); got != (ServerStats{}) {
		t.Fatalf("initial Stats() = %+v", got)
	}
	if got := (*Server)(nil).Stats(); got != (ServerStats{}) {
		t.Fatalf("nil Stats() = %+v", got)
	}
	_, response, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "stats"),
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
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
	buf := make([]byte, 5)
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if got := server.Stats(); got.ActiveLeases != 1 || got.ActiveConnections != 1 {
		t.Fatalf("registered Stats() = %+v", got)
	}
	_ = client.Close()
	_ = peer.Close()
	<-bridgeDone
	if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: response.AccessToken}); err != nil {
		t.Fatal(err)
	}
	if got := server.Stats(); got != (ServerStats{ForwardedBytes: 5}) {
		t.Fatalf("unregistered Stats() = %+v", got)
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
	registry := newTestRegistry(t, false, false)
	server := &Server{registry: registry}
	leaseIdentity := newTestLeaseIdentity(t, "stats-concurrent")
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 100 {
				if got := server.Stats(); got.ActiveLeases < 0 || got.ActiveLeases > 1 {
					t.Errorf("Stats() during registration = %+v", got)
				}
			}
		}()
	}
	for range 10 {
		_, response, err := registry.Register(types.RegisterChallengeRequest{
			Identity: leaseIdentity,
		}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: response.AccessToken}); err != nil {
			t.Fatal(err)
		}
	}
	readers.Wait()
	if got := server.Stats(); got.ActiveLeases != 0 {
		t.Fatalf("final Stats() = %+v", got)
	}
}

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
			if _, err := NormalizeHTTPRedirectConfig(HTTPRedirectConfig{Enabled: true}, target); err == nil {
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
		_, resp, err := registry.Register(types.RegisterChallengeRequest{
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

func TestCertificateSignerMismatchRejectsStartup(t *testing.T) {
	managerA, err := acme.NewManager(acme.Config{BaseDomain: "localhost", KeyDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := managerA.EnsureTLSMaterial(t.Context()); err != nil {
		t.Fatal(err)
	}
	certFile, _, err := managerA.TLSFiles()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}

	managerB, err := acme.NewManager(acme.Config{BaseDomain: "localhost", KeyDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := managerB.EnsureTLSMaterial(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, keyFile, err := managerB.TLSFiles()
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, "fullchain.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "privatekey.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	relay, err := NewServer(ServerConfig{
		PortalURL:     "https://localhost",
		StateDir:      stateDir,
		SNIListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = relay.Start(t.Context(), http.NotFoundHandler())
	if err == nil {
		_ = relay.Shutdown(context.Background())
		t.Fatal("Start() succeeded with mismatched certificate and private key")
	}
	if !strings.Contains(err.Error(), "private key does not match public key") {
		t.Fatalf("Start() error = %q, want key mismatch", err)
	}
}

func TestRelayHTTPRedirectListener(t *testing.T) {
	t.Run("enabled answers only with the canonical origin", func(t *testing.T) {
		for _, hsts := range []bool{false, true} {
			t.Run("hsts="+strconv.FormatBool(hsts), func(t *testing.T) {
				redirectListener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				redirectAddr := redirectListener.Addr().String()
				_ = redirectListener.Close()

				sniListener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				sniAddr := sniListener.Addr().String()
				_ = sniListener.Close()

				server, err := NewServer(ServerConfig{
					PortalURL:     "https://localhost:4017/base/?configured=discarded#fragment",
					StateDir:      t.TempDir(),
					SNIListenAddr: sniAddr,
					HTTPRedirect:  HTTPRedirectConfig{Enabled: true, Addr: redirectAddr, HSTS: hsts},
				})
				if err != nil {
					t.Fatalf("create portal server: %v", err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if err := server.Start(ctx, http.NotFoundHandler()); err != nil {
					t.Fatalf("start portal server: %v", err)
				}

				client := &http.Client{
					Transport:     &http.Transport{DisableKeepAlives: true},
					CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
					Timeout:       5 * time.Second,
				}
				t.Cleanup(client.CloseIdleConnections)

				for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodOptions} {
					req, err := http.NewRequest(method, "http://"+redirectAddr+"//tenant/path?secret=discarded", nil)
					if err != nil {
						t.Fatalf("build %s request: %v", method, err)
					}
					if method == http.MethodOptions {
						req.URL.Path = "*"
						req.URL.RawQuery = ""
					}
					req.Host = "attacker.example"
					req.Header.Set("X-Forwarded-Host", "other-attacker.example")
					resp, err := client.Do(req)
					if err != nil {
						t.Fatalf("%s redirect request: %v", method, err)
					}
					_ = resp.Body.Close()
					const wantLocation = "https://localhost:4017/base"
					if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != wantLocation {
						t.Fatalf("%s: status=%d Location=%q, want 301 to %s", method, resp.StatusCode, resp.Header.Get("Location"), wantLocation)
					}
					wantHSTS := ""
					if hsts {
						wantHSTS = "max-age=31536000"
					}
					if got := resp.Header.Get("Strict-Transport-Security"); got != wantHSTS {
						t.Fatalf("%s: Strict-Transport-Security=%q, want %q", method, got, wantHSTS)
					}
				}

				shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
				defer c()
				if err := server.Shutdown(shutdownCtx); err != nil {
					t.Fatalf("shutdown: %v", err)
				}
				if err := server.Wait(); err != nil {
					t.Fatalf("wait: %v", err)
				}
				released, err := net.Listen("tcp", redirectAddr)
				if err != nil {
					t.Fatalf("redirect port not released after shutdown: %v", err)
				}
				_ = released.Close()
			})
		}
	})

	t.Run("disabled leaves the configured address unbound", func(t *testing.T) {
		redirectListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		redirectAddr := redirectListener.Addr().String()
		_ = redirectListener.Close()

		sniListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		sniAddr := sniListener.Addr().String()
		_ = sniListener.Close()

		server, err := NewServer(ServerConfig{
			PortalURL:     "https://localhost:4017",
			StateDir:      t.TempDir(),
			SNIListenAddr: sniAddr,
			HTTPRedirect:  HTTPRedirectConfig{Addr: redirectAddr},
		})
		if err != nil {
			t.Fatalf("create portal server: %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		if err := server.Start(ctx, http.NotFoundHandler()); err != nil {
			t.Fatalf("start portal server: %v", err)
		}
		t.Cleanup(func() {
			shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
			defer c()
			_ = server.Shutdown(shutdownCtx)
			_ = server.Wait()
		})

		listener, err := net.Listen("tcp", redirectAddr)
		if err != nil {
			t.Fatalf("disabled redirect must not bind the configured address %s: %v", redirectAddr, err)
		}
		_ = listener.Close()
	})

	t.Run("bind failure cleans up and retries", func(t *testing.T) {
		occupied, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("occupy redirect address: %v", err)
		}
		redirectAddr := occupied.Addr().String()

		sniListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			_ = occupied.Close()
			t.Fatal(err)
		}
		sniAddr := sniListener.Addr().String()
		_ = sniListener.Close()

		cfg := ServerConfig{
			PortalURL:     "https://localhost:4017",
			StateDir:      t.TempDir(),
			SNIListenAddr: sniAddr,
			HTTPRedirect:  HTTPRedirectConfig{Enabled: true, Addr: redirectAddr},
		}
		server, err := NewServer(cfg)
		if err != nil {
			_ = occupied.Close()
			t.Fatalf("create portal server: %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		if startErr := server.Start(ctx, http.NotFoundHandler()); startErr == nil {
			shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
			defer c()
			_ = server.Shutdown(shutdownCtx)
			_ = server.Wait()
			_ = occupied.Close()
			t.Fatal("Start() succeeded with the redirect address already occupied")
		}
		if err := occupied.Close(); err != nil {
			t.Fatalf("release occupied redirect address: %v", err)
		}
		// A failed Start must not leak the SNI listener it had already bound.
		rebound, err := net.Listen("tcp", sniAddr)
		if err != nil {
			t.Fatalf("failed Start leaked the SNI listener: %v", err)
		}
		_ = rebound.Close()

		retry, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("create retry portal server: %v", err)
		}
		if err := retry.Start(ctx, http.NotFoundHandler()); err != nil {
			t.Fatalf("retry Start() after releasing the redirect address: %v", err)
		}
		defer func() {
			shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
			defer c()
			_ = retry.Shutdown(shutdownCtx)
			_ = retry.Wait()
		}()

		client := &http.Client{
			Transport:     &http.Transport{DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Timeout:       5 * time.Second,
		}
		t.Cleanup(client.CloseIdleConnections)
		resp, err := client.Get("http://" + redirectAddr + "/ignored")
		if err != nil {
			t.Fatalf("GET retry redirect: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "https://localhost:4017" {
			t.Fatalf("retry: status=%d Location=%q, want 301 to the canonical origin", resp.StatusCode, resp.Header.Get("Location"))
		}
	})
}
