package portal

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	testLeasePortsMu sync.Mutex
	testLeasePorts   = make(map[int]struct{})
)

func tempIdentityPath(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func tempLeasePort(t *testing.T) int {
	t.Helper()

	for range 100 {
		probe, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("allocate probe port: %v", err)
		}
		_, portText, err := net.SplitHostPort(probe.Addr().String())
		if closeErr := probe.Close(); closeErr != nil {
			t.Fatalf("close probe port: %v", closeErr)
		}
		if err != nil {
			t.Fatalf("parse probe port: %v", err)
		}
		start, err := strconv.Atoi(portText)
		if err != nil {
			t.Fatalf("parse probe port %q: %v", portText, err)
		}
		if start <= 0 || start > 65535 {
			continue
		}
		if !reserveTestLeasePort(start) {
			continue
		}
		if tempLeasePortAvailable(start) {
			return start
		}
		releaseTestLeasePort(start)
	}
	t.Fatalf("could not find a free lease port")
	return 0
}

func reserveTestLeasePort(port int) bool {
	testLeasePortsMu.Lock()
	defer testLeasePortsMu.Unlock()

	if _, exists := testLeasePorts[port]; exists {
		return false
	}
	testLeasePorts[port] = struct{}{}
	return true
}

func releaseTestLeasePort(port int) {
	testLeasePortsMu.Lock()
	defer testLeasePortsMu.Unlock()

	delete(testLeasePorts, port)
}

func tempLeasePortAvailable(port int) bool {
	addr := ":" + strconv.Itoa(port)
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	defer tcpListener.Close()

	udpListener, err := net.ListenPacket("udp", addr)
	if err != nil {
		return false
	}
	defer udpListener.Close()

	return true
}

func newTestClient(t *testing.T, cancel context.CancelFunc, server *Server) *http.Client {
	t.Helper()
	client := utils.NewHTTPClient(
		utils.WithHTTPTLSConfig(&tls.Config{InsecureSkipVerify: true}),
	)
	t.Cleanup(func() {
		client.CloseIdleConnections()
		cancel()
		if err := server.Wait(); err != nil {
			t.Fatalf("Wait() error = %v", err)
		}
	})
	return client
}

func TestHTTPRedirectTargetValidation(t *testing.T) {
	for _, target := range []string{"http://localhost:4017", "http://relay.example", "//relay.example", "https://user:pass@relay.example", "https://relay.example:65536", "https://relay.example:bad", "https:///missing-host"} {
		t.Run(target, func(t *testing.T) {
			_, err := NewServer(ServerConfig{PortalURL: target, IdentityPath: t.TempDir(), HTTPRedirectEnabled: true})
			if err == nil {
				t.Fatal("expected invalid redirect target to fail")
			}
		})
	}
	if _, err := NewServer(ServerConfig{PortalURL: "HTTPS://relay.example", IdentityPath: t.TempDir(), HTTPRedirectEnabled: true}); err != nil {
		t.Fatalf("uppercase HTTPS redirect target rejected: %v", err)
	}
	if _, err := NewServer(ServerConfig{PortalURL: "http://localhost:4017", IdentityPath: t.TempDir()}); err != nil {
		t.Fatalf("disabled redirect changed loopback behavior: err=%v", err)
	}
}

func TestHTTPRedirectLifecycle(t *testing.T) {
	for _, hsts := range []bool{false, true} {
		t.Run(strconv.FormatBool(hsts), func(t *testing.T) {
			probe, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil { t.Fatal(err) }
			addr := probe.Addr().String()
			probe.Close()
			server, err := NewServer(ServerConfig{
				PortalURL:    "https://localhost:4017/base/?configured=discarded#fragment",
				IdentityPath: t.TempDir(), ACME: acme.Config{KeyDir: t.TempDir()},
				APIListenAddr: "127.0.0.1:0", SNIListenAddr: "127.0.0.1:0",
				HTTPRedirectEnabled: true, HTTPRedirectAddr: addr, HTTPRedirectHSTS: hsts,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := server.Start(ctx, nil); err != nil {
				t.Fatal(err)
			}
			client := newTestClient(t, cancel, server)
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodOptions} {
				req, err := http.NewRequest(method, "http://"+addr+"//tenant/path?secret=discarded", nil)
				if err != nil {
					t.Fatal(err)
				}
				if method == http.MethodOptions {
					req.URL.Path = "*"
					req.URL.RawQuery = ""
				}
				req.Host = "attacker.example"
				req.Header.Set("X-Forwarded-Host", "other-attacker.example")
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "https://localhost:4017/base" {
					t.Fatalf("%s: status=%d Location=%q", method, resp.StatusCode, resp.Header.Get("Location"))
				}
				wantHSTS := ""
				if hsts {
					wantHSTS = "max-age=31536000"
				}
				if got := resp.Header.Get("Strict-Transport-Security"); got != wantHSTS {
					t.Fatalf("HSTS=%q, want %q", got, wantHSTS)
				}
			}
			cancel()
			if err := server.Wait(); err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				t.Fatalf("redirect port not released: %v", err)
			}
			listener.Close()
		})
	}
}

func TestHTTPRedirectPartialStartupCleanup(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	server, err := NewServer(ServerConfig{
		PortalURL: "https://localhost:4017", IdentityPath: t.TempDir(), ACME: acme.Config{KeyDir: t.TempDir()},
		APIListenAddr: "127.0.0.1:0", SNIListenAddr: "127.0.0.1:0",
		HTTPRedirectEnabled: true, HTTPRedirectAddr: addr,
		PProfEnabled: true, PProfListenAddr: occupied.Addr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "listen pprof") {
		if err == nil {
			server.Shutdown(context.Background())
		}
		t.Fatalf("Start error=%v, want later pprof bind failure", err)
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("partial startup leaked redirect listener: %v", err)
	}
	listener.Close()
}

func TestHTTPRedirectBindFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	server, err := NewServer(ServerConfig{
		PortalURL: "https://localhost:4017", IdentityPath: t.TempDir(), ACME: acme.Config{KeyDir: t.TempDir()},
		APIListenAddr: "127.0.0.1:0", SNIListenAddr: "127.0.0.1:0",
		HTTPRedirectEnabled: true, HTTPRedirectAddr: occupied.Addr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "listen http redirect") {
		if err == nil {
			server.Shutdown(context.Background())
		}
		t.Fatalf("Start error=%v, want redirect bind failure", err)
	}
	// Retry the same owner after releasing the occupied address.
	occupied.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := server.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestRelayDiscoveryEnabledServesDiscoveryEnvelope(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:        "https://portal.example.com",
		IdentityPath:     tempIdentityPath(t),
		DiscoveryEnabled: true,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, types.PathDiscovery, nil)
	rec := httptest.NewRecorder()
	server.handleRelayDiscovery(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET relay discovery status = %d, want %d", rec.Code, http.StatusOK)
	}
	var envelope types.APIEnvelope[types.DiscoveryResponse]
	if err := json.NewDecoder(rec.Body).Decode(&envelope); err != nil {
		t.Fatalf("json.Decode() error = %v", err)
	}
	if !envelope.OK || envelope.Data.ProtocolVersion != types.DiscoveryVersion {
		t.Fatalf("discovery envelope = %+v, want ok discovery response", envelope)
	}
}

func TestHandleHopRateLimited(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:    "https://portal.example.com",
		IdentityPath: tempIdentityPath(t),
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	server.announceLimiter = discovery.NewAnnounceLimiter(1, 2)

	statuses := make([]int, 3)
	for i := range statuses {
		req := httptest.NewRequest(http.MethodPost, types.PathSDKHop, strings.NewReader(`{}`))
		req.RemoteAddr = "192.0.2.1:1234"
		rec := httptest.NewRecorder()
		server.handleHop(rec, req)
		statuses[i] = rec.Code
	}
	if statuses[0] == http.StatusTooManyRequests || statuses[1] == http.StatusTooManyRequests {
		t.Fatalf("first statuses = %d/%d, want within burst budget", statuses[0], statuses[1])
	}
	if statuses[2] != http.StatusTooManyRequests {
		t.Fatalf("third status = %d, want %d", statuses[2], http.StatusTooManyRequests)
	}
	deleteReq := httptest.NewRequest(http.MethodDelete, types.PathSDKHop, strings.NewReader(`{}`))
	deleteReq.RemoteAddr = "192.0.2.1:1234"
	deleteRec := httptest.NewRecorder()
	server.handleHop(deleteRec, deleteReq)
	if deleteRec.Code == http.StatusTooManyRequests {
		t.Fatalf("DELETE after exhausted POST burst = %d, want cleanup to bypass the POST-only limiter", deleteRec.Code)
	}
}

func TestServerStartInitializesLocalACMEAndSigner(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:     "https://localhost:4017",
		IdentityPath:  tempIdentityPath(t),
		ACME:          acme.Config{KeyDir: t.TempDir()},
		APIListenAddr: "127.0.0.1:0",
		SNIListenAddr: "127.0.0.1:0",
		MinPort:       40000,
		MaxPort:       40000,
		UDPEnabled:    true,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := server.Start(ctx, nil); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	client := newTestClient(t, cancel, server)

	healthResp, err := client.Get("https://" + utils.HostPortOrLoopback(server.apiListener.Addr().String()) + types.PathHealthz)
	if err != nil {
		t.Fatalf("GET /api/healthz error = %v", err)
	}
	defer healthResp.Body.Close()

	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/healthz status = %d, want %d", healthResp.StatusCode, http.StatusOK)
	}

	var healthEnvelope types.APIEnvelope[map[string]string]
	if err := json.NewDecoder(healthResp.Body).Decode(&healthEnvelope); err != nil {
		t.Fatalf("decode /api/healthz response: %v", err)
	}
	if !healthEnvelope.OK || healthEnvelope.Data["status"] != "ok" {
		t.Fatalf("GET /api/healthz response = %+v, want ok status", healthEnvelope)
	}

	signResp, err := client.Get("https://" + utils.HostPortOrLoopback(server.apiListener.Addr().String()) + types.PathV1Sign)
	if err != nil {
		t.Fatalf("GET /v1/sign error = %v", err)
	}
	defer signResp.Body.Close()

	if signResp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /v1/sign status = %d, want %d", signResp.StatusCode, http.StatusForbidden)
	}
}

func TestServerStartDomainReportsCompatibilityInfo(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:     "https://localhost:4017",
		IdentityPath:  tempIdentityPath(t),
		ACME:          acme.Config{KeyDir: t.TempDir()},
		SNIPort:       4443,
		APIListenAddr: "127.0.0.1:0",
		SNIListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := server.Start(ctx, nil); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	client := newTestClient(t, cancel, server)

	resp, err := client.Get("https://" + utils.HostPortOrLoopback(server.apiListener.Addr().String()) + types.PathSDKDomain)
	if err != nil {
		t.Fatalf("GET /sdk/domain error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /sdk/domain status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /sdk/domain response: %v", err)
	}

	var envelope types.APIEnvelope[types.DomainResponse]
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode /sdk/domain response: %v", err)
	}
	if !envelope.OK {
		t.Fatalf("GET /sdk/domain response = %+v, want ok=true", envelope)
	}
	if envelope.Data.ProtocolVersion != types.SDKVersion {
		t.Fatalf("DomainResponse.ProtocolVersion = %q, want %q", envelope.Data.ProtocolVersion, types.SDKVersion)
	}
	if envelope.Data.ReleaseVersion != types.ReleaseVersion {
		t.Fatalf("DomainResponse.ReleaseVersion = %q, want %q", envelope.Data.ReleaseVersion, types.ReleaseVersion)
	}
	if envelope.Data.X402.Enabled {
		t.Fatalf("DomainResponse.X402.Enabled = true, want false")
	}
}

func TestRegisterLeaseDerivesFixedHostnameFromName(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:    "https://portal.example.com",
		IdentityPath: tempIdentityPath(t),
		MinPort:      40000,
		MaxPort:      40000,
		UDPEnabled:   true,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	record, _, err := server.registry.Register(types.RegisterChallengeRequest{
		Identity: types.Identity{
			Name:    "Demo-App",
			Address: server.identity.Address,
		},
	}, "203.0.113.10", "")
	if err != nil {
		t.Fatalf("registry.Register() error = %v", err)
	}

	wantHostname := "demo-app.portal.example.com"
	if record.Hostname != wantHostname {
		t.Fatalf("registry.Register() route hostname = %q, want %q", record.Hostname, wantHostname)
	}

	lease := server.registry.publicLease(record)
	if lease.Name != "demo-app" {
		t.Fatalf("publicLease().Name = %q, want %q", lease.Name, "demo-app")
	}
	if lease.Hostname != wantHostname {
		t.Fatalf("publicLease().Hostname = %q, want %q", lease.Hostname, wantHostname)
	}
}

func TestRegisterLeaseCombinesECHWithUDPAndRawTCP(t *testing.T) {
	t.Parallel()

	port := tempLeasePort(t)
	server, err := NewServer(ServerConfig{
		PortalURL:    "https://portal.example.com",
		IdentityPath: tempIdentityPath(t),
		SNIPort:      4443,
		MinPort:      port,
		MaxPort:      port,
		UDPEnabled:   true,
		TCPEnabled:   true,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	server.SetUDPPolicy(true, 0)

	publicHostname := "demo-ech.portal.example.com"
	routeHostname := "ech-demo-ech.portal.example.com"
	_, echConfigList, err := keyless.EncryptedClientHelloMaterials("test-seed", routeHostname)
	if err != nil {
		t.Fatalf("EncryptedClientHelloMaterials() error = %v", err)
	}
	record, resp, err := server.registry.Register(types.RegisterChallengeRequest{
		Identity: types.Identity{
			Name:    "demo-ech",
			Address: server.identity.Address,
		},
		RouteHostname: routeHostname,
		HostnameHash:  utils.HostnameHash(publicHostname),
		ECHConfigList: echConfigList,
		UDPEnabled:    true,
		TCPEnabled:    true,
	}, "203.0.113.10", "")
	if err != nil {
		t.Fatalf("registry.Register() error = %v", err)
	}
	t.Cleanup(record.Close)

	if resp.SNIPort != server.config().SNIPort {
		t.Fatalf("RegisterResponse.SNIPort = %d, want %d", resp.SNIPort, server.config().SNIPort)
	}
	if !resp.UDPEnabled || !resp.TCPEnabled || resp.UDPAddr == "" || resp.TCPAddr == "" {
		t.Fatalf("RegisterResponse transports = %+v, want UDP and raw TCP endpoints", resp)
	}
	if lookedUp, ok := server.registry.Lookup(publicHostname); !ok || lookedUp != record {
		t.Fatalf("Lookup(public hostname) = %v, %v, want ECH fallback lease", lookedUp, ok)
	}
	if lookedUp, ok := server.registry.Lookup(routeHostname); !ok || lookedUp != record {
		t.Fatalf("Lookup(route hostname) = %v, %v, want ECH route lease", lookedUp, ok)
	}
}

func TestServerStartHidesDiscoveryRoutesWhenDisabled(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:     "https://localhost:4017",
		IdentityPath:  tempIdentityPath(t),
		ACME:          acme.Config{KeyDir: t.TempDir()},
		APIListenAddr: "127.0.0.1:0",
		SNIListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := server.Start(ctx, nil); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	client := newTestClient(t, cancel, server)

	resp, err := client.Get("https://" + utils.HostPortOrLoopback(server.apiListener.Addr().String()) + types.PathDiscovery)
	if err != nil {
		t.Fatalf("GET relay discovery error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET relay discovery status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	if server.config().DiscoveryEnabled {
		t.Fatal("cfg.DiscoveryEnabled = true, want false without configured discovery service")
	}
}
