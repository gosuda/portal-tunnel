package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
)

const browserSmokePage = `<!doctype html>
<script src="/wasm_exec.js"></script>
<script>
async function main() {
  const go = new Go();
  const result = await WebAssembly.instantiateStreaming(fetch("/portal-js-wasm.wasm"), go.importObject);
  void go.run(result.instance);
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (window.portalTunnel) break;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  if (!window.portalTunnel) throw new Error("portalTunnel was not installed by the WASM artifact");
  const ready = await window.portalTunnel.start({
    relayURL: window.location.origin,
    body: "portal-browser-smoke-ok",
  });
  await fetch("/browser-ready", {method: "POST", body: JSON.stringify(ready)});
}
main().catch(async (error) => {
  await fetch("/browser-error", {method: "POST", body: String(error?.stack ?? error)});
});
</script>`

// waitBrowserExit tears down the browser tree and waits for the launcher to
// be reaped, bounded so a surviving browser helper can never wedge the suite.
func waitBrowserExit(t *testing.T, browserDone <-chan struct{}, tree *browserTree) {
	t.Helper()
	if err := tree.kill(); err != nil {
		t.Logf("kill browser tree: %v", err)
	}
	select {
	case <-browserDone:
	case <-time.After(10 * time.Second):
		t.Error("browser did not exit after its process tree was killed")
	}
}

func readBrowserLog(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}

type browserSmokeResult struct {
	publicURL string
	err       error
}

// TestPackagedBrowserWASM loads the artifacts produced by make build-tunnel
// in a real browser, exposes a handler, and reaches it through tenant TLS.
func TestPackagedBrowserWASM(t *testing.T) {
	wasmPath := filepath.Join("..", "cmd", "relay-server", "dist", "tunnel", "portal-js-wasm.wasm")
	wasmExecPath := filepath.Join("..", "cmd", "relay-server", "dist", "tunnel", "wasm_exec.js")
	if _, err := os.Stat(wasmPath); err != nil {
		t.Skip("browser artifact is not built; run make build-tunnel")
	}
	if _, err := os.Stat(wasmExecPath); err != nil {
		t.Skip("WASM runtime glue is not built; run make build-tunnel")
	}

	var browser string
	for _, candidate := range []string{"google-chrome", "chromium", "chromium-browser"} {
		if path, err := exec.LookPath(candidate); err == nil {
			browser = path
			break
		}
	}
	if browser == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("Chrome or Chromium is required for the browser connector test")
		}
		t.Skip("Chrome or Chromium is not installed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	port := harnessPort(t)
	stateDir := t.TempDir()
	relayURL := "https://127.0.0.1:" + strconv.Itoa(port)
	result := make(chan browserSmokeResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /browser-smoke", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(browserSmokePage))
	})
	mux.HandleFunc("GET /wasm_exec.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, wasmExecPath)
	})
	mux.HandleFunc("GET /portal-js-wasm.wasm", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/wasm")
		http.ServeFile(w, r, wasmPath)
	})
	mux.HandleFunc("POST /browser-ready", func(w http.ResponseWriter, r *http.Request) {
		var ready struct {
			PublicURL string `json:"publicURL"`
		}
		if err := json.NewDecoder(r.Body).Decode(&ready); err != nil {
			result <- browserSmokeResult{err: fmt.Errorf("decode browser ready state: %w", err)}
			return
		}
		result <- browserSmokeResult{publicURL: ready.PublicURL}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /browser-error", func(w http.ResponseWriter, r *http.Request) {
		var message bytes.Buffer
		_, _ = message.ReadFrom(http.MaxBytesReader(w, r.Body, 64<<10))
		result <- browserSmokeResult{err: fmt.Errorf("browser connector failed: %s", message.String())}
		w.WriteHeader(http.StatusNoContent)
	})

	relay, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     relayURL,
		StateDir:      stateDir,
		SNIListenAddr: "127.0.0.1:" + strconv.Itoa(port),
		SNIPort:       port,
	})
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}
	if err := relay.Start(ctx, relayHandler(relay, mux)); err != nil {
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = relay.Shutdown(shutdownCtx)
		_ = relay.Wait()
	})

	// The browser writes to files rather than pipes: browsers hand off to
	// helper processes that outlive the launcher and inherit its descriptors,
	// and an inherited pipe keeps cmd.Wait blocked long after the launcher
	// exits.
	browserLog := filepath.Join(t.TempDir(), "browser.log")
	logFile, err := os.Create(browserLog)
	if err != nil {
		t.Fatalf("create browser log: %v", err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	cmd := exec.CommandContext(ctx, browser,
		"--headless",
		"--disable-gpu",
		"--ignore-certificate-errors",
		"--no-sandbox",
		"--user-data-dir="+filepath.Join(t.TempDir(), "chrome"),
		relayURL+"/browser-smoke",
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = browserSysProcAttr()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start browser: %v", err)
	}
	tree := newBrowserTree(cmd)
	browserDone := make(chan struct{})
	var browserErr error
	go func() {
		browserErr = cmd.Wait()
		close(browserDone)
	}()
	t.Cleanup(func() { waitBrowserExit(t, browserDone, tree) })

	var ready browserSmokeResult
	waitBrowser := browserDone
waitReady:
	for {
		select {
		case ready = <-result:
			break waitReady
		case <-waitBrowser:
			if browserErr != nil {
				t.Fatalf("browser launcher exited with error before connector became ready: %v; browser log=%s", browserErr, readBrowserLog(browserLog))
			}
			// Clean launcher exit is normal on platforms that hand off to helper processes.
			waitBrowser = nil
		case <-ctx.Done():
			t.Fatalf("browser connector did not become ready: %v; browser log=%s", ctx.Err(), readBrowserLog(browserLog))
		}
	}
	if ready.err != nil {
		t.Fatal(ready.err)
	}
	if ready.publicURL == "" {
		t.Fatal("browser connector returned an empty public URL")
	}
	if strings.Contains(ready.publicURL, "undefined") {
		t.Fatalf("browser connector public URL = %q contains 'undefined'", ready.publicURL)
	}

	leases := relay.PublicLeases()
	if len(leases) != 1 {
		t.Fatalf("relay public leases = %d, want 1", len(leases))
	}
	if leases[0].Hostname != "" {
		t.Fatalf("lease hostname = %q, want empty for unnamed browser lease", leases[0].Hostname)
	}
	if !strings.Contains(ready.publicURL, leases[0].CanonicalHostname) {
		t.Fatalf("browser connector public URL = %q, want canonical hostname %q", ready.publicURL, leases[0].CanonicalHostname)
	}

	certificate := filepath.Join(stateDir, "fullchain.pem")
	body, ok := tenantGet("127.0.0.1:"+strconv.Itoa(port), certificate, ready.publicURL)
	if !ok || body != "portal-browser-smoke-ok" {
		t.Fatalf("browser tunnel response = %q, ok=%v, want packaged handler response", body, ok)
	}
}
