package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/relay/l4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
)

type mitmIngress struct {
	backend     string
	cert        tls.Certificate
	roots       *x509.CertPool
	reject      bool
	rejected    chan struct{}
	probeStarts atomic.Int64
	workers     sync.WaitGroup
}

func startMITMIngress(t *testing.T, parent context.Context, addr, backend, stateDir, attack string) *mitmIngress {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(stateDir, "fullchain.pem"), filepath.Join(stateDir, "privatekey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := os.ReadFile(filepath.Join(stateDir, "fullchain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(chain) {
		t.Fatal("parse relay certificate")
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(parent)
	m := &mitmIngress{
		backend: backend, cert: cert, roots: roots, reject: attack == "reject",
		rejected: make(chan struct{}, 16),
	}
	m.acceptLoop(ctx, listener)
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		m.workers.Wait()
	})
	return m
}

func (m *mitmIngress) acceptLoop(ctx context.Context, listener net.Listener) {
	m.workers.Add(1)
	go func() {
		defer m.workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			m.serveAccepted(ctx, conn)
		}
	}()
}

func (m *mitmIngress) serveAccepted(ctx context.Context, conn net.Conn) {
	m.workers.Add(1)
	go func() {
		defer m.workers.Done()
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		m.serve(ctx, conn)
	}()
}

func (m *mitmIngress) dialPlainBackend(ctx context.Context, dialer *net.Dialer) (net.Conn, bool) {
	upstream, err := dialer.DialContext(ctx, "tcp", m.backend)
	if err != nil {
		return nil, false
	}
	return upstream, true
}

func (m *mitmIngress) establishUpstream(ctx context.Context, client net.Conn, hello l4.ClientHelloInfo) (net.Conn, net.Conn, bool) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if hello.ServerName == "" {
		upstream, ok := m.dialPlainBackend(ctx, dialer)
		if !ok {
			return nil, nil, false
		}
		return client, upstream, true
	}
	if len(hello.ALPNProtocols) == 0 {
		m.probeStarts.Add(1)
		if m.reject {
			select {
			case m.rejected <- struct{}{}:
			case <-ctx.Done():
			}
			return nil, nil, false
		}
	}
	return m.terminateAndDialBackend(ctx, dialer, client, hello)
}

func (m *mitmIngress) terminateAndDialBackend(ctx context.Context, dialer *net.Dialer, client net.Conn, hello l4.ClientHelloInfo) (net.Conn, net.Conn, bool) {
	handshakeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	terminated := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{m.cert}, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	})
	if err := terminated.HandshakeContext(handshakeCtx); err != nil {
		return nil, nil, false
	}
	upstream, err := (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{
		ServerName: hello.ServerName, RootCAs: m.roots, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	}}).DialContext(handshakeCtx, "tcp", m.backend)
	if err != nil {
		return nil, nil, false
	}
	return terminated, upstream, true
}

func (m *mitmIngress) serve(ctx context.Context, raw net.Conn) {
	hello, client, err := l4.InspectClientHello(raw, 5*time.Second)
	if err != nil {
		return
	}
	client, upstream, ok := m.establishUpstream(ctx, client, hello)
	if !ok {
		return
	}
	defer upstream.Close()
	stop := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	defer stop()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, client)
		_ = upstream.Close()
		close(done)
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	_ = upstream.Close()
	<-done
}
func awaitMITMVerdict(t *testing.T, h *harness) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		statuses := h.exposure.Relays()
		if len(statuses) == 1 && statuses[0].State == sdk.RelayFailed && statuses[0].Failure == sdk.RelayFailureMITM {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("forwarded TLS termination did not exclude relay: %+v", statuses)
		case <-tick.C:
		}
	}
}

func TestMITMTerminationExcludesRelay(t *testing.T) {
	h := newHarnessWithName(t, "termination", "127.0.0.1", "terminate", sdk.WithMITMProtection(true))
	awaitMITMVerdict(t, h)
}

func exerciseProbeBudget(t *testing.T, h *harness, publicURL string) {
	t.Helper()
	started := time.Now()
	if got := h.get(publicURL); got != marker {
		t.Fatalf("visitor response = %q, want %q", got, marker)
	}
	select {
	case <-h.mitm.rejected:
	case <-time.After(10 * time.Second):
		t.Fatal("relay did not receive the first probe")
	}
	for range 10 {
		if got := h.get(publicURL); got != marker {
			t.Fatalf("visitor response = %q, want %q", got, marker)
		}
	}
	if time.Since(started) >= 30*time.Second {
		t.Fatal("visitor burst exceeded the retry interval observation window")
	}
	if probes := h.mitm.probeStarts.Load(); probes > 1 {
		t.Fatalf("failed-probe budget exceeded: %d connections during one interval", probes)
	}
}

func TestMITMProbeFailureBudget(t *testing.T) {
	h := newHarnessWithName(t, "failure-budget", "127.0.0.1", "reject", sdk.WithMITMProtection(true))
	publicURL := h.waitForPublicURL()
	exerciseProbeBudget(t, h, publicURL)
	if statuses := h.exposure.Relays(); len(statuses) != 1 || statuses[0].State != sdk.RelayReady || statuses[0].Failure != "" {
		t.Fatalf("probe handshake failure must preserve service without a MITM verdict: %+v", statuses)
	}
}

func assertSplitChannelBindingRefused(t *testing.T, conn net.Conn, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "exporter mismatch") {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("DialCanonicalTLS through a terminating relay = %v; want an exporter mismatch error", err)
	}
}

func loadRelayCertPool(t *testing.T, certPath string) *x509.CertPool {
	t.Helper()
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("parse relay certificate")
	}
	return roots
}

func fetchBoundMarker(t *testing.T, publicURL string, conn net.Conn) {
	t.Helper()
	transport := &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return conn, nil },
	}
	defer transport.CloseIdleConnections()
	resp, err := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Get(publicURL + "/marker")
	if err != nil {
		t.Fatalf("request over the bound connection: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != marker {
		t.Fatalf("response over the bound connection = %q, %v; want %q", body, err, marker)
	}
}

func checkTLSChannelBinding(t *testing.T, label, attack string) {
	t.Helper()
	h := newHarnessWithName(t, label, "127.0.0.1", attack)
	publicURL := h.waitForPublicURL()
	parsed, err := url.Parse(publicURL)
	if err != nil {
		t.Fatalf("parse public URL %q: %v", publicURL, err)
	}
	roots := loadRelayCertPool(t, h.certificate)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := sdk.DialCanonicalTLS(ctx, h.sniAddr, parsed.Hostname(), &tls.Config{RootCAs: roots})
	if attack != "" {
		assertSplitChannelBindingRefused(t, conn, err)
		return
	}
	if err != nil {
		t.Fatalf("DialCanonicalTLS through an honest relay: %v", err)
	}
	fetchBoundMarker(t, publicURL, conn)
}

func TestTLSChannelBindingThroughRelays(t *testing.T) {
	for _, tc := range []struct {
		name   string
		label  string
		attack string
	}{
		{"honest relay", "bind-ok", ""},
		{"relay terminating TLS", "bind-split", "terminate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkTLSChannelBinding(t, tc.label, tc.attack)
		})
	}
}

func captureSDKLogs(t *testing.T) *logCapture {
	t.Helper()

	capture := &logCapture{buf: &bytes.Buffer{}}
	previousLogger := log.Logger
	previousLevel := zerolog.GlobalLevel()
	log.Logger = zerolog.New(capture).With().Timestamp().Logger()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() {
		zerolog.SetGlobalLevel(previousLevel)
		log.Logger = previousLogger
	})
	return capture
}

type logCapture struct {
	mu  sync.Mutex
	buf *bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) contains(needle string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Contains(c.buf.String(), needle)
}

func (c *logCapture) snapshot() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func TestMITMSelfProbeRunsWithoutTenantTraffic(t *testing.T) {
	logs := captureSDKLogs(t)

	h := newHarness(t, sdk.WithMITMProtection(true))
	publicURL := h.waitForPublicURL()

	deadline := time.Now().Add(20 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for !logs.contains("tls passthrough self-probe passed") {
		if logs.contains(types.MITMProbeReasonProbeTimeout) {
			t.Fatalf("mitm self-probe timed out instead of reporting passthrough; sdk logs: %s", logs.snapshot())
		}
		if logs.contains(types.MITMProbeReasonExporterMismatch) {
			t.Fatalf("clean relay produced an exporter mismatch verdict; sdk logs: %s", logs.snapshot())
		}
		if time.Now().After(deadline) {
			t.Fatalf("mitm self-probe did not report passthrough within 20s; sdk logs: %s", logs.snapshot())
		}
		<-tick.C
	}

	if got := h.get(publicURL); got != marker {
		t.Fatalf("post-probe tenant response = %q, want %q", got, marker)
	}
}
