package portal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
)

const rotationMarker = "portal-rotation-ok"

// TestSDKExposureReRegistersAfterAuthorityRotation models a relay restart
// that rotates its lease signing authority while keeping its TLS identity:
// the restart kills the live reverse sessions and drops the in-memory
// registry, and because the signing authority changed, the listener's
// previous access token and reverse capability answer "unauthorized"
// instead of "lease not found". The SDK must classify both answers as a
// lost lease and re-register on its own; restarting the application must
// never be required (issue #471).
func TestSDKExposureReRegistersAfterAuthorityRotation(t *testing.T) {
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, rotationMarker)
	}))
	defer service.Close()
	target, err := url.Parse(service.URL)
	if err != nil {
		t.Fatalf("parse local service URL: %v", err)
	}

	stateDir := t.TempDir()
	apiPort := loopbackPort(t)
	sniPort := loopbackPort(t)
	cfg := ServerConfig{
		PortalURL:     "https://127.0.0.1:" + strconv.Itoa(sniPort),
		StateDir:      stateDir,
		APIListenAddr: "127.0.0.1:" + strconv.Itoa(apiPort),
		SNIListenAddr: "127.0.0.1:" + strconv.Itoa(sniPort),
		SNIPort:       sniPort,
	}
	certPath := filepath.Join(stateDir, "fullchain.pem")
	sniAddr := "127.0.0.1:" + strconv.Itoa(sniPort)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	relay, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}
	if err := relay.Start(ctx, nil); err != nil {
		t.Fatalf("start relay: %v", err)
	}
	stopRelay := func(s *Server) {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := s.Shutdown(shutdownCtx); err != nil {
			t.Errorf("shutdown relay: %v", err)
		}
		if err := s.Wait(); err != nil {
			t.Errorf("wait for relay shutdown: %v", err)
		}
	}
	defer func() { stopRelay(relay) }()

	clientIdentity, err := identity.Generate("rotation")
	if err != nil {
		t.Fatalf("generate client identity: %v", err)
	}
	exposure, err := sdk.Expose(ctx, clientIdentity, []string{cfg.PortalURL})
	if err != nil {
		t.Fatalf("expose local service: %v", err)
	}
	defer exposure.Close()
	go func() { _ = sdk.Proxy(ctx, exposure, target.Host) }()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 15*time.Second)
	relays, err := exposure.WaitReady(readyCtx)
	readyCancel()
	if err != nil {
		t.Fatalf("tunnel did not become ready: %v", err)
	}
	if len(relays) == 0 || relays[0].PublicURL == "" {
		t.Fatal("ready relay did not report a public URL")
	}
	publicURL := relays[0].PublicURL
	if got, ok := tenantRoundTrip(publicURL, certPath, sniAddr); !ok || got != rotationMarker {
		t.Fatalf("tenant response before rotation = %q, %v, want %q", got, ok, rotationMarker)
	}

	// Restart the relay with a rotated token authority but the same TLS
	// identity: the fresh registry is empty, and its authority no longer
	// verifies the listener's stored credentials.
	stopRelay(relay)
	relay, err = NewServer(cfg)
	if err != nil {
		t.Fatalf("create restarted relay: %v", err)
	}
	rotatedIdentity, err := identity.Generate("rotated")
	if err != nil {
		t.Fatalf("generate rotated authority identity: %v", err)
	}
	relay.registry.mu.Lock()
	relay.registry.tokenAuthority = identity.NewLocalAuthority(rotatedIdentity)
	relay.registry.mu.Unlock()
	if err := relay.Start(ctx, nil); err != nil {
		t.Fatalf("start restarted relay: %v", err)
	}

	// The exposure must recover without being recreated: a complete new
	// registration, fresh reverse sessions, and the public hostname
	// routing again.
	deadline := time.Now().Add(45 * time.Second)
	for {
		if got, ok := tenantRoundTrip(publicURL, certPath, sniAddr); ok && got == rotationMarker {
			return
		}
		if !time.Now().Before(deadline) {
			break
		}
		<-time.After(250 * time.Millisecond)
	}
	t.Fatal("exposure did not route again after relay restart with rotated authority")
}

// loopbackPort reserves a loopback port for the relay config, which needs
// concrete ports before startup.
func loopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release loopback port: %v", err)
	}
	return port
}

// tenantRoundTrip performs a single tenant round trip against the relay
// certificate on disk and reports whether it succeeded.
func tenantRoundTrip(publicURL, certPath, sniAddr string) (string, bool) {
	certPEM, err := os.ReadFile(certPath)
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
			return (&net.Dialer{}).DialContext(ctx, network, sniAddr)
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
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", false
	}
	return string(body), true
}
