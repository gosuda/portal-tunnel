package e2e_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/cmd/relay-server/policy"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
)

const marker = "portal-e2e-ok"

func relayHandler(server *portal.Server, fallback http.Handler) http.Handler {
	return policy.Mux(server, fallback, nil, nil, nil, policy.DefaultPreAuthConfig())
}

type harness struct {
	t           *testing.T
	cancel      context.CancelFunc
	server      *portal.Server
	exposure    *sdk.Exposure
	service     *httptest.Server
	sniAddr     string
	certificate string
	sniPort     int
	stateDir    string
	proxyDone   chan error
	mitm        *mitmIngress
}

func newHarness(t *testing.T, opts ...sdk.Option) *harness {
	t.Helper()
	return newHarnessWithName(t, "e2e", "127.0.0.1", "", opts...)
}

func listenOriginService(t *testing.T, host string) (*httptest.Server, *url.URL) {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		if host == "::1" {
			t.Skipf("IPv6 loopback is unavailable: %v", err)
		}
		t.Fatalf("listen HTTP origin: %v", err)
	}
	service := &httptest.Server{
		Listener: listener,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, marker)
		})},
	}
	service.Start()
	target, err := url.Parse(service.URL)
	if err != nil {
		service.Close()
		t.Fatalf("parse local service URL: %v", err)
	}
	return service, target
}

func bootHarnessRelay(t *testing.T, ctx context.Context, host, attack string, h *harness) (*portal.Server, string, int, string, *mitmIngress) {
	t.Helper()
	sniPort := harnessPort(t, host)
	stateDir := t.TempDir()
	sniAddr := net.JoinHostPort(host, strconv.Itoa(sniPort))
	ingressAddr := sniAddr
	if attack != "" {
		ingressAddr = net.JoinHostPort(host, strconv.Itoa(harnessPort(t, host)))
	}
	relay, err := portal.NewServer(portal.ServerConfig{
		TenantCertificates: true,
		PortalURL:          "https://" + sniAddr,
		StateDir:           stateDir,
		SNIListenAddr:      ingressAddr,
		SNIPort:            sniPort,
	})
	if err != nil {
		h.cancel()
		h.service.Close()
		t.Fatalf("create relay: %v", err)
	}
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		h.cancel()
		h.service.Close()
		t.Fatalf("start relay: %v", err)
	}
	var ingress *mitmIngress
	if attack != "" {
		ingress = startMITMIngress(t, ctx, sniAddr, ingressAddr, stateDir, attack)
	}
	return relay, sniAddr, sniPort, stateDir, ingress
}

func exposeHarnessService(t *testing.T, ctx context.Context, h *harness, relayURL, name string, opts ...sdk.Option) {
	t.Helper()
	clientIdentity, err := identity.Generate(name)
	if err != nil {
		h.cancel()
		_ = h.server.Shutdown(context.Background())
		_ = h.server.Wait()
		h.service.Close()
		t.Fatalf("generate client identity: %v", err)
	}
	exposure, err := sdk.Expose(ctx, clientIdentity, []string{relayURL}, opts...)
	if err != nil {
		h.cancel()
		_ = h.server.Shutdown(context.Background())
		_ = h.server.Wait()
		h.service.Close()
		t.Fatalf("expose local service: %v", err)
	}
	h.exposure = exposure
}

func buildPortalTunnelBinary(t *testing.T) string {
	t.Helper()
	portalBin := filepath.Join(t.TempDir(), "portal")
	if runtime.GOOS == "windows" {
		portalBin += ".exe"
	}
	build := exec.Command("go", "build", "-o", portalBin, "./cmd/portal-tunnel")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build portal binary: %v\n%s", err, out)
	}
	return portalBin
}

func newHarnessWithName(t *testing.T, name, host, attack string, opts ...sdk.Option) *harness {
	t.Helper()
	service, target := listenOriginService(t, host)
	h := &harness{t: t, service: service}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	relay, sniAddr, sniPort, stateDir, ingress := bootHarnessRelay(t, ctx, host, attack, h)
	h.server = relay
	h.sniAddr = sniAddr
	h.sniPort = sniPort
	h.stateDir = stateDir
	h.certificate = filepath.Join(stateDir, "fullchain.pem")
	h.mitm = ingress
	h.proxyDone = make(chan error, 1)
	relayURL := "https://" + sniAddr
	exposeHarnessService(t, ctx, h, relayURL, name, opts...)
	go func() {
		h.proxyDone <- sdk.Proxy(ctx, h.exposure, target.Host)
	}()
	t.Cleanup(h.close)
	return h
}

func (h *harness) close() {
	h.cancel()
	_ = h.exposure.Close()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.server.Shutdown(shutdownCtx); err != nil {
		h.t.Errorf("shutdown relay: %v", err)
	}
	if err := h.server.Wait(); err != nil {
		h.t.Errorf("wait for relay: %v", err)
	}
	h.service.Close()
	select {
	case err := <-h.proxyDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			h.t.Errorf("proxy exposure: %v", err)
		}
	case <-time.After(5 * time.Second):
		h.t.Errorf("proxy exposure did not stop")
	}
}

func (h *harness) waitForPublicURL() string {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	relays, err := h.exposure.WaitReady(ctx)
	if err != nil {
		h.t.Fatalf("tunnel did not become ready: %v", err)
	}
	if len(relays) == 0 || relays[0].PublicURL == "" {
		h.t.Fatal("ready relay did not report a public URL")
	}
	return relays[0].PublicURL
}

func (h *harness) get(publicURL string) string {
	h.t.Helper()
	body, ok := h.tryGet(publicURL)
	if !ok {
		h.t.Fatalf("tenant request to %s failed: no successful round trip", publicURL)
	}
	return body
}

func tenantTLSClient(sniAddr, certPath string) (*http.Client, *http.Transport, bool) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, false
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		return nil, nil, false
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, sniAddr)
		},
		ForceAttemptHTTP2: false,
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, transport, true
}

func tenantGet(sniAddr, certPath, publicURL string) (string, bool) {
	client, transport, ok := tenantTLSClient(sniAddr, certPath)
	if !ok {
		return "", false
	}
	defer transport.CloseIdleConnections()
	resp, err := client.Get(publicURL + "/marker")
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false
	}
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	return string(body), true
}

func (h *harness) tryGet(publicURL string) (string, bool) {
	return tenantGet(h.sniAddr, h.certificate, publicURL)
}

var (
	harnessPortsMu sync.Mutex
	harnessPorts   = map[int]struct{}{}
)

func harnessPort(t *testing.T, host string) int {
	t.Helper()
	harnessPortsMu.Lock()
	defer harnessPortsMu.Unlock()
	lo, hi := ephemeralPortRange()
	start, end := 31000, 32100
	if start <= hi && end >= lo {
		start, end = hi+1, min(hi+1100, 65535)
	}
	for port := start; port <= end; port++ {
		if _, used := harnessPorts[port]; used {
			continue
		}
		listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			continue
		}
		if err := listener.Close(); err != nil {
			t.Fatalf("close harness port probe: %v", err)
		}
		harnessPorts[port] = struct{}{}
		return port
	}
	t.Fatal("no free listener port outside the ephemeral range")
	return 0
}

func ephemeralPortRange() (lo, hi int) {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 49152, 65535
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return 49152, 65535
	}
	parsedLo, loErr := strconv.Atoi(fields[0])
	parsedHi, hiErr := strconv.Atoi(fields[1])
	if loErr != nil || hiErr != nil {
		return 49152, 65535
	}
	return parsedLo, parsedHi
}
