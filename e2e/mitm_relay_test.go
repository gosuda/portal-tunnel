package e2e_test

import (
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

	"github.com/gosuda/portal-tunnel/v2/sdk"
)

// mitmIngress holds the real relay's key and splits tenant TLS into two real
// sessions. Control, reverse transport and transcript signing remain unchanged.
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
	m.workers.Add(1)
	go func() {
		defer m.workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			m.workers.Add(1)
			go func() {
				defer m.workers.Done()
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
				defer stop()
				m.serve(ctx, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		m.workers.Wait()
	})
	return m
}

func (m *mitmIngress) serve(ctx context.Context, raw net.Conn) {
	hello, client, err := l4.InspectClientHello(raw, 5*time.Second)
	if err != nil {
		return
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	var upstream net.Conn
	if hello.ServerName == "" {
		// IP-literal API/reverse connections have no SNI.
		upstream, err = dialer.DialContext(ctx, "tcp", m.backend)
	} else {
		// Visitors explicitly offer HTTP/1.1. Only the native probe omits
		// ALPN in this fixture; the rejection rule uses public metadata.
		if len(hello.ALPNProtocols) == 0 {
			m.probeStarts.Add(1)
			if m.reject {
				select {
				case m.rejected <- struct{}{}:
				case <-ctx.Done():
				}
				return
			}
		}
		handshakeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		terminated := tls.Server(client, &tls.Config{
			Certificates: []tls.Certificate{m.cert}, MinVersion: tls.VersionTLS13,
			NextProtos: []string{"http/1.1"},
		})
		if err := terminated.HandshakeContext(handshakeCtx); err != nil {
			return
		}
		client = terminated
		upstream, err = (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{
			ServerName: hello.ServerName, RootCAs: m.roots, MinVersion: tls.VersionTLS13,
			NextProtos: []string{"http/1.1"},
		}}).DialContext(handshakeCtx, "tcp", m.backend)
	}
	if err != nil {
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

func TestMITMTerminationExcludesRelay(t *testing.T) {
	h := newHarnessWithName(t, "termination", "127.0.0.1", "terminate", sdk.WithMITMProtection(true))
	// No visitor traffic: reverse readiness alone must start the probe and
	// expose the TLS split through the SDK's public MITM failure verdict.
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

// Failure must not amplify an ordinary visitor burst into fresh probe retries.
func TestMITMProbeFailureBudget(t *testing.T) {
	h := newHarnessWithName(t, "failure-budget", "127.0.0.1", "reject", sdk.WithMITMProtection(true))
	publicURL := h.waitForPublicURL()
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
	if statuses := h.exposure.Relays(); len(statuses) != 1 || statuses[0].State != sdk.RelayReady || statuses[0].Failure != "" {
		t.Fatalf("probe handshake failure must preserve service without a MITM verdict: %+v", statuses)
	}
}

// A native client binds its own TLS connection to the tunnel identity in the
// hostname. Through an honest relay the binding succeeds and application
// traffic continues on the verified connection; through a relay that
// terminates TLS, even for this client alone, the client aborts before it
// sends any application data.
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
			h := newHarnessWithName(t, tc.label, "127.0.0.1", tc.attack)
			publicURL := h.waitForPublicURL()
			parsed, err := url.Parse(publicURL)
			if err != nil {
				t.Fatalf("parse public URL %q: %v", publicURL, err)
			}
			certPEM, err := os.ReadFile(h.certificate)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(certPEM) {
				t.Fatal("parse relay certificate")
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := sdk.DialCanonicalTLS(ctx, h.sniAddr, parsed.Hostname(), &tls.Config{RootCAs: roots})
			if tc.attack != "" {
				if err == nil || !strings.Contains(err.Error(), "exporter mismatch") {
					if conn != nil {
						_ = conn.Close()
					}
					t.Fatalf("DialCanonicalTLS through a terminating relay = %v; want an exporter mismatch error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("DialCanonicalTLS through an honest relay: %v", err)
			}
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
		})
	}
}
