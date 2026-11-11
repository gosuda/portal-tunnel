package portal

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
)

func TestPublicIngressAggregateAdmissionAndRelease(t *testing.T) {
	var server Server
	conns := fillIngressBudget(t, &server)
	extra, peer := net.Pipe()
	defer extra.Close()
	defer peer.Close()
	checkIngressSaturation(t, &server, extra)
	checkIngressCapacityReuse(t, &server, conns)
	checkIngressShutdown(t, &server, conns, extra)
}

func fillIngressBudget(t *testing.T, server *Server) []net.Conn {
	t.Helper()
	var conns []net.Conn
	for range publicIngressLimit {
		conn, peer := net.Pipe()
		t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
		if !server.admitIngress(conn, false) {
			t.Fatal("connection below aggregate limit rejected")
		}
		conns = append(conns, conn)
	}
	return conns
}

func checkIngressSaturation(t *testing.T, server *Server, extra net.Conn) {
	t.Helper()
	if server.admitIngress(extra, false) {
		t.Fatal("raw TCP bypassed tenant connection budget")
	}
	if !server.admitIngress(extra, true) {
		t.Fatal("tenant saturation blocked root inspection")
	}
	if server.promoteIngress() {
		t.Fatal("SNI tenant bypassed tenant connection budget")
	}
}

func checkIngressCapacityReuse(t *testing.T, server *Server, conns []net.Conn) {
	t.Helper()
	server.releaseIngress(conns[0], false)
	if !server.promoteIngress() {
		t.Fatal("released tenant capacity was not reusable")
	}
}

func checkIngressShutdown(t *testing.T, server *Server, conns []net.Conn, extra net.Conn) {
	t.Helper()
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
	certPEM := loadMismatchedCert(t)
	keyPEM := loadMismatchedKey(t)
	stateDir := writeMismatchedStateDir(t, certPEM, keyPEM)
	checkMismatchedKeyRejected(t, stateDir)
}

func loadMismatchedCert(t *testing.T) []byte {
	t.Helper()
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
	return certPEM
}

func loadMismatchedKey(t *testing.T) []byte {
	t.Helper()
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
	return keyPEM
}

func writeMismatchedStateDir(t *testing.T, certPEM, keyPEM []byte) string {
	t.Helper()
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, "fullchain.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "privatekey.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return stateDir
}

func checkMismatchedKeyRejected(t *testing.T, stateDir string) {
	t.Helper()
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
				wantHSTS := ""
				if hsts {
					wantHSTS = "max-age=31536000"
				}
				verifyCanonicalRedirect(t, wantHSTS)
			})
		}
	})

	t.Run("disabled leaves the configured address unbound", func(t *testing.T) {
		verifyDisabledRedirect(t)
	})

	t.Run("bind failure cleans up and retries", func(t *testing.T) {
		verifyContendedRedirect(t)
	})
}

func reserveRedirectAddrs(t *testing.T) (string, string) {
	t.Helper()
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
	return redirectAddr, sniAddr
}

func newRedirectProbeClient(t *testing.T) *http.Client {
	t.Helper()
	client := &http.Client{
		Transport:     &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       5 * time.Second,
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func startCanonicalRedirectServer(t *testing.T, redirectAddr, sniAddr, wantHSTS string) (*Server, context.Context, context.CancelFunc) {
	t.Helper()
	server, err := NewServer(ServerConfig{
		PortalURL:     "https://localhost:4017/base/?configured=discarded#fragment",
		StateDir:      t.TempDir(),
		SNIListenAddr: sniAddr,
		HTTPRedirect:  HTTPRedirectConfig{Enabled: true, Addr: redirectAddr, HSTS: wantHSTS != ""},
	})
	if err != nil {
		t.Fatalf("create portal server: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	if err := server.Start(ctx, http.NotFoundHandler()); err != nil {
		t.Fatalf("start portal server: %v", err)
	}
	return server, ctx, cancel
}

func checkRedirectMethod(t *testing.T, client *http.Client, redirectAddr, method, wantHSTS string) {
	t.Helper()
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
	if got := resp.Header.Get("Strict-Transport-Security"); got != wantHSTS {
		t.Fatalf("%s: Strict-Transport-Security=%q, want %q", method, got, wantHSTS)
	}
}

func checkRedirectShutdown(t *testing.T, server *Server, redirectAddr string) {
	t.Helper()
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
}

func verifyCanonicalRedirect(t *testing.T, wantHSTS string) {
	t.Helper()
	redirectAddr, sniAddr := reserveRedirectAddrs(t)
	server, _, cancel := startCanonicalRedirectServer(t, redirectAddr, sniAddr, wantHSTS)
	defer cancel()
	client := newRedirectProbeClient(t)
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodOptions} {
		checkRedirectMethod(t, client, redirectAddr, method, wantHSTS)
	}
	checkRedirectShutdown(t, server, redirectAddr)
}

func startDisabledRedirectServer(t *testing.T, redirectAddr, sniAddr string) (*Server, context.Context, context.CancelFunc) {
	t.Helper()
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
	if err := server.Start(ctx, http.NotFoundHandler()); err != nil {
		t.Fatalf("start portal server: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = server.Shutdown(shutdownCtx)
		_ = server.Wait()
	})
	return server, ctx, cancel
}

func checkDisabledRedirectUnbound(t *testing.T, redirectAddr string) {
	t.Helper()
	listener, err := net.Listen("tcp", redirectAddr)
	if err != nil {
		t.Fatalf("disabled redirect must not bind the configured address %s: %v", redirectAddr, err)
	}
	_ = listener.Close()
}

func verifyDisabledRedirect(t *testing.T) {
	t.Helper()
	redirectAddr, sniAddr := reserveRedirectAddrs(t)
	_, _, cancel := startDisabledRedirectServer(t, redirectAddr, sniAddr)
	defer cancel()
	checkDisabledRedirectUnbound(t, redirectAddr)
}

func reserveOccupiedRedirectAddrs(t *testing.T) (net.Listener, string, string) {
	t.Helper()
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
	return occupied, redirectAddr, sniAddr
}

func newContendedRedirectServer(t *testing.T, cfg ServerConfig, occupied net.Listener) *Server {
	t.Helper()
	server, err := NewServer(cfg)
	if err != nil {
		_ = occupied.Close()
		t.Fatalf("create portal server: %v", err)
	}
	return server
}

func checkContendedRedirectStart(t *testing.T, ctx context.Context, server *Server, occupied net.Listener, sniAddr string) {
	t.Helper()
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
	rebound, err := net.Listen("tcp", sniAddr)
	if err != nil {
		t.Fatalf("failed Start leaked the SNI listener: %v", err)
	}
	_ = rebound.Close()
}

func startRetryRedirectServer(ctx context.Context, t *testing.T, cfg ServerConfig) *Server {
	t.Helper()
	retry, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("create retry portal server: %v", err)
	}
	if err := retry.Start(ctx, http.NotFoundHandler()); err != nil {
		t.Fatalf("retry Start() after releasing the redirect address: %v", err)
	}
	return retry
}

func checkRetryRedirect(t *testing.T, client *http.Client, redirectAddr string) {
	t.Helper()
	resp, err := client.Get("http://" + redirectAddr + "/ignored")
	if err != nil {
		t.Fatalf("GET retry redirect: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "https://localhost:4017" {
		t.Fatalf("retry: status=%d Location=%q, want 301 to the canonical origin", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func verifyContendedRedirect(t *testing.T) {
	t.Helper()
	occupied, redirectAddr, sniAddr := reserveOccupiedRedirectAddrs(t)
	cfg := ServerConfig{
		PortalURL:     "https://localhost:4017",
		StateDir:      t.TempDir(),
		SNIListenAddr: sniAddr,
		HTTPRedirect:  HTTPRedirectConfig{Enabled: true, Addr: redirectAddr},
	}
	server := newContendedRedirectServer(t, cfg, occupied)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	checkContendedRedirectStart(t, ctx, server, occupied, sniAddr)
	retry := startRetryRedirectServer(ctx, t, cfg)
	defer func() {
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = retry.Shutdown(shutdownCtx)
		_ = retry.Wait()
	}()
	client := newRedirectProbeClient(t)
	checkRetryRedirect(t, client, redirectAddr)
}
