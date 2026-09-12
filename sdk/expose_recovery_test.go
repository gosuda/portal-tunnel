package sdk_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
)

// TestClientReregistersAfterRelayRestart proves the recovery path for #422:
// a relay restart wipes the in-memory lease registry, and a live client must
// receive lease_not_found on its next reverse-session attempt and
// re-register with the same identity without being restarted.
func TestClientReregistersAfterRelayRestart(t *testing.T) {
	const marker = "portal-restart-ok"

	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, marker)
	}))
	defer service.Close()
	target, err := url.Parse(service.URL)
	if err != nil {
		t.Fatalf("parse service URL: %v", err)
	}

	apiAddr, sniAddr := freeAddr(t), freeAddr(t)
	relayIdentityDir := t.TempDir()
	parsedAPI, err := url.Parse("https://" + apiAddr)
	if err != nil {
		t.Fatalf("parse relay URL: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startRelay := func(t *testing.T) *portal.Server {
		t.Helper()
		relay, err := portal.NewServer(portal.ServerConfig{
			PortalURL:     parsedAPI.String(),
			IdentityPath:  relayIdentityDir,
			APIListenAddr: apiAddr,
			SNIListenAddr: sniAddr,
		})
		if err != nil {
			t.Fatalf("create relay: %v", err)
		}
		if err := relay.Start(ctx, nil); err != nil {
			t.Fatalf("start relay: %v", err)
		}
		return relay
	}

	relay := startRelay(t)
	clientIdentity, err := identity.LoadOrCreate("restart-e2e", target.Host, filepath.Join(t.TempDir(), "identity.json"), "")
	if err != nil {
		t.Fatalf("resolve client identity: %v", err)
	}
	exposure, err := sdk.Expose(ctx, sdk.ExposeConfig{
		RelayURLs: []string{parsedAPI.String()},
		Identity:  clientIdentity,
	})
	if err != nil {
		t.Fatalf("expose: %v", err)
	}
	proxyDone := make(chan error, 1)
	go func() { proxyDone <- sdk.Proxy(ctx, exposure, target.Host) }()
	defer func() {
		cancel()
		_ = exposure.Close()
		select {
		case err := <-proxyDone:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("proxy: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("proxy did not stop")
		}
	}()

	publicURL := waitForTunnelReady(t, exposure, relay)
	if got := tunnelGet(t, publicURL, sniAddr); got != marker {
		t.Fatalf("tunnel response before restart = %q, want %q", got, marker)
	}

	// Restart only the relay: same identity dir, so the authority (and thus
	// the public hostname) survives while every lease record is gone.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if err := relay.Shutdown(shutdownCtx); err != nil {
		t.Logf("relay shutdown: %v (continuing; the restart scenario kills the relay)", err)
	}
	if err := relay.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("wait for relay: %v", err)
	}
	relay = startRelay(t)
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = relay.Shutdown(shutdownCtx)
		_ = relay.Wait()
	}()

	// The same client process must re-register and serve traffic again.
	recoveredURL := waitForTunnelReady(t, exposure, relay)
	if got := tunnelGet(t, recoveredURL, sniAddr); got != marker {
		t.Fatalf("tunnel response after restart = %q, want %q", got, marker)
	}
}

func waitForTunnelReady(t *testing.T, exposure *sdk.Exposure, relay *portal.Server) string {
	t.Helper()
	ready := func() string {
		for _, status := range exposure.Relays() {
			if status.PublicURL == "" {
				continue
			}
			for _, lease := range relay.PublicLeases() {
				if lease.Ready > 0 {
					return status.PublicURL
				}
			}
		}
		return ""
	}
	if publicURL := ready(); publicURL != "" {
		return publicURL
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case <-ticker.C:
			if publicURL := ready(); publicURL != "" {
				return publicURL
			}
		case <-timeout.C:
			t.Fatal("tunnel did not become ready within 30s")
			return ""
		}
	}
}

// tunnelGet fetches publicURL over the relay SNI listener. TLS verification
// is disabled: this test proves lease re-registration, not certificate
// trust, which the keyless and handshake suites cover.
func tunnelGet(t *testing.T, publicURL, sniAddr string) string {
	t.Helper()
	parsed, err := url.Parse(publicURL)
	if err != nil {
		t.Fatalf("parse public URL: %v", err)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test-only loopback tunnel
			ServerName:         parsed.Hostname(),
			MinVersion:         tls.VersionTLS12,
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, sniAddr)
		},
		ForceAttemptHTTP2: false,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	resp, err := client.Get(publicURL)
	if err != nil {
		t.Fatalf("request public URL: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public URL status = %d, want 200", resp.StatusCode)
	}
	return string(body)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve address: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release address: %v", err)
	}
	return addr
}
