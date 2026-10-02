package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
)

// TestPackagedBrowserWASM loads the artifacts produced by make build-tunnel,
// exposes an HTTP handler through a real relay, and reaches it through tenant TLS.
func TestPackagedBrowserWASM(t *testing.T) {
	wasmPath := filepath.Join("..", "cmd", "relay-server", "dist", "tunnel", "portal-js-wasm.wasm")
	wasmExecPath := filepath.Join("..", "cmd", "relay-server", "dist", "tunnel", "wasm_exec.js")
	if _, err := os.Stat(wasmPath); err != nil {
		t.Skip("browser artifact is not built; run make build-tunnel")
	}
	if _, err := os.Stat(wasmExecPath); err != nil {
		t.Skip("WASM runtime glue is not built; run make build-tunnel")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	port := harnessPort(t)
	stateDir := t.TempDir()
	relayURL := "https://127.0.0.1:" + strconv.Itoa(port)
	relay, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     relayURL,
		StateDir:      stateDir,
		SNIListenAddr: "127.0.0.1:" + strconv.Itoa(port),
		SNIPort:       port,
	})
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}
	if err := relay.Start(ctx, nil); err != nil {
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = relay.Shutdown(shutdownCtx)
		_ = relay.Wait()
	})

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "node", "browser_smoke.cjs", wasmPath, wasmExecPath, relayURL, "browser-smoke")
	cmd.Env = append(os.Environ(), "NODE_TLS_REJECT_UNAUTHORIZED=0")
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("open browser smoke output: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start browser smoke: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	var ready struct {
		PublicURL string `json:"publicURL"`
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		payload, found := strings.CutPrefix(line, "PORTAL_READY ")
		if !found {
			continue
		}
		if err := json.Unmarshal([]byte(payload), &ready); err != nil {
			t.Fatalf("decode browser ready state: %v", err)
		}
		break
	}
	if ready.PublicURL == "" {
		t.Fatalf("browser connector did not become ready: %s", stderr.String())
	}

	certificate := filepath.Join(stateDir, "fullchain.pem")
	body, ok := tenantGet("127.0.0.1:"+strconv.Itoa(port), certificate, ready.PublicURL)
	if !ok || body != "portal-browser-smoke-ok" {
		t.Fatalf("browser tunnel response = %q, ok=%v, want packaged handler response; stderr=%s", body, ok, stderr.String())
	}
}
