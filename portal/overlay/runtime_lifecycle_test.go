package overlay

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/foundation"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestDialRequiresAuthenticatedIVNPPeer(t *testing.T) {
	hash := sha256.Sum256([]byte("ingress"))
	destination := foundation.B32(hash)
	for _, tc := range []struct {
		name   string
		remote net.Addr
		accept bool
	}{
		{name: "authenticated destination", remote: ivnp.Addr{Hash: hash, Port: 4017}, accept: true},
		{name: "wrong destination", remote: ivnp.Addr{Hash: sha256.Sum256([]byte("other")), Port: 4017}},
		{name: "missing identity", remote: ivnp.Addr{Port: 4017}},
		{name: "unbound peer", remote: ivnp.Addr{Hash: hash}},
		{name: "untrusted address text", remote: &net.UnixAddr{Net: "i2p", Name: destination + ":4017"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.accept {
				checkAuthenticatedDialAccepted(t, destination, tc.remote)
				return
			}
			checkAuthenticatedDialRejected(t, destination, tc.remote)
		})
	}
}

func newAuthenticatedPeerRuntime(t *testing.T, destination string, local net.Conn, remoteAddr net.Addr) *Runtime {
	t.Helper()
	return &Runtime{endpoint: endpointStub{
		destination: testDestination("gateway"),
		dial: func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "i2p" || address != net.JoinHostPort(destination, types.OverlayStreamPort) {
				t.Fatalf("dial = %q %q, want destination-owned I2P stream", network, address)
			}
			return peerConn{Conn: local, remote: remoteAddr}, nil
		},
	}}
}

func checkAuthenticatedDialAccepted(t *testing.T, destination string, remoteAddr net.Addr) {
	t.Helper()
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	if err := remote.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	runtime := newAuthenticatedPeerRuntime(t, destination, local, remoteAddr)
	conn, err := runtime.dial(t.Context(), destination)
	if err != nil || conn == nil {
		t.Fatalf("authenticated dial = %v, %v", conn, err)
	}
}

func checkAuthenticatedDialRejected(t *testing.T, destination string, remoteAddr net.Addr) {
	t.Helper()
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	if err := remote.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	runtime := newAuthenticatedPeerRuntime(t, destination, local, remoteAddr)
	conn, err := runtime.dial(t.Context(), destination)
	if err == nil || conn != nil {
		t.Fatalf("untrusted dial = %v, %v", conn, err)
	}
	if _, err := remote.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("rejected peer connection was not closed: %v", err)
	}
}

func TestStartRejectsInvalidRouterConfiguration(t *testing.T) {
	for _, content := range []string{
		"", "null", "[router]\n", `{"Unknown":true}`, `{} {}`,
		`{"NetworkID":256}`, `{"Logger":{}}`,
	} {
		t.Run(content, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ivnp.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			runtime := &Runtime{config: Config{ConfigPath: path}}
			defer runtime.Close()
			if err := runtime.Start(t.Context()); err == nil {
				t.Fatal("invalid IVNP configuration was accepted")
			}
			if runtime.router != nil {
				t.Fatal("invalid configuration started a router")
			}
		})
	}
}

func TestUnavailableOverlayStartsAndShutsDownWithoutPeers(t *testing.T) {
	for _, mode := range []string{"cancel run", "close runtime"} {
		t.Run(mode, func(t *testing.T) {
			checkUnavailableOverlayMode(t, mode)
		})
	}
}

func writeUnavailableOverlayConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ivnp.json")
	config := `{"Bootstrap":{"ReseedURLs":[]},"NTCP2":{"Bind":"127.0.0.1:0"},"SSU2":{"Bind":"127.0.0.1:0"}}`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func startUnavailableOverlay(t *testing.T, ctx context.Context, runtime *Runtime) {
	t.Helper()
	if err := runtime.Start(ctx); err != nil {
		t.Fatalf("local startup without peers: %v", err)
	}
	if endpoint, useOverlay, err := runtime.IssueEndpoint(IssueInput{}); err != nil || useOverlay || endpoint.URL != "" {
		t.Fatalf("unavailable overlay must retain direct fallback: %v, %v, %v", endpoint, useOverlay, err)
	}
}

func checkUnavailableOverlayShutdown(t *testing.T, ctx context.Context, runtime *Runtime, mode string) {
	t.Helper()
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	done := make(chan error, 1)
	go func() { done <- runtime.Run(runCtx) }()
	if mode == "cancel run" {
		cancelRun()
	} else {
		runtime.Close()
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("overlay shutdown: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("shutdown did not cancel destination warmup")
	}
	if runtime.Destination() != "" {
		t.Fatal("shutdown left the overlay available")
	}
}

func checkUnavailableOverlayMode(t *testing.T, mode string) {
	t.Helper()
	path := writeUnavailableOverlayConfig(t)
	runtime := &Runtime{config: Config{ConfigPath: path}}
	defer runtime.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	startUnavailableOverlay(t, ctx, runtime)
	checkUnavailableOverlayShutdown(t, ctx, runtime, mode)
}
