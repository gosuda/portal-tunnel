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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
)

const marker = "portal-e2e-ok"

type harness struct {
	t           *testing.T
	cancel      context.CancelFunc
	server      *portal.Server
	exposure    *sdk.Exposure
	service     *httptest.Server
	sniAddr     string
	certificate string
	apiPort     int
	sniPort     int
	stateDir    string
	proxyDone   chan error
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, marker)
	}))
	target, err := url.Parse(service.URL)
	if err != nil {
		service.Close()
		t.Fatalf("parse local service URL: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	apiPort := harnessPort(t)
	sniPort := harnessPort(t)
	stateDir := t.TempDir()
	relayURL := "https://127.0.0.1:" + strconv.Itoa(sniPort)
	relay, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     relayURL,
		StateDir:      stateDir,
		APIListenAddr: "127.0.0.1:" + strconv.Itoa(apiPort),
		SNIListenAddr: "127.0.0.1:" + strconv.Itoa(sniPort),
		SNIPort:       sniPort,
	})
	if err != nil {
		cancel()
		service.Close()
		t.Fatalf("create relay: %v", err)
	}
	if err := relay.Start(ctx, nil); err != nil {
		cancel()
		service.Close()
		t.Fatalf("start relay: %v", err)
	}

	clientIdentity, err := identity.Generate("e2e")
	if err != nil {
		cancel()
		_ = relay.Shutdown(context.Background())
		_ = relay.Wait()
		service.Close()
		t.Fatalf("generate client identity: %v", err)
	}
	exposure, err := sdk.Expose(ctx, clientIdentity, []string{relayURL})
	if err != nil {
		cancel()
		_ = relay.Shutdown(context.Background())
		_ = relay.Wait()
		service.Close()
		t.Fatalf("expose local service: %v", err)
	}

	h := &harness{
		t:           t,
		cancel:      cancel,
		server:      relay,
		exposure:    exposure,
		service:     service,
		sniAddr:     "127.0.0.1:" + strconv.Itoa(sniPort),
		certificate: filepath.Join(stateDir, "fullchain.pem"),
		apiPort:     apiPort,
		sniPort:     sniPort,
		stateDir:    stateDir,
		proxyDone:   make(chan error, 1),
	}
	go func() {
		h.proxyDone <- sdk.Proxy(ctx, exposure, target.Host)
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

// tryGet performs a single tenant round trip against the relay
// certificate current at call time and reports whether it succeeded.
// Recovery tests poll it while the exposure re-registers.
func (h *harness) tryGet(publicURL string) (string, bool) {
	certPEM, err := os.ReadFile(h.certificate)
	if err != nil {
		return "", false
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		return "", false
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, h.sniAddr)
		},
		ForceAttemptHTTP2: false,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
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

var (
	harnessPortsMu sync.Mutex
	harnessPorts   = map[int]struct{}{}
)

// harnessPort allocates an explicit listener port outside the kernel's
// ephemeral range. The relay config needs concrete ports before startup — the
// lease registry issues reverse endpoints from the configured port — so the
// harness cannot bind :0 and read the result back, and probing an ephemeral
// port and rebinding it races every concurrent bind(":0") in parallel test
// binaries. Only an explicit bind can take a port outside the ephemeral range,
// and nothing else binds there, so the released probe address stays free until
// the relay binds it.
func harnessPort(t *testing.T) int {
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
		listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
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

// ephemeralPortRange reports the kernel's automatic port allocation range,
// assuming the common default when it cannot be read.
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
