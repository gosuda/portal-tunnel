package e2e_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
)

// The machine-readable relay lifecycle contract is the structured log
// stream (issue #596): this test builds the real portal binary, runs
// `portal expose --log-format json` as a subprocess the way an external
// integration launches it, and consumes its stdout. A ready record names
// the relay and the tenant-ready canonical URL; relay deselection and
// retraction are covered by the SDK unit tests driving the authoritative
// status paths.
func TestPortalExposeJSONRelayLifecycleLogs(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the portal binary")
	}
	portalBin := filepath.Join(t.TempDir(), "portal")
	build := exec.Command("go", "build", "-o", portalBin, "./cmd/portal-tunnel")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build portal binary: %v\n%s", err, out)
	}

	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, marker)
	}))
	defer service.Close()
	target, err := url.Parse(service.URL)
	if err != nil {
		t.Fatalf("parse local service URL: %v", err)
	}

	relayCtx, relayCancel := context.WithCancel(context.Background())
	defer relayCancel()
	relayMembership := startMembershipRelay(t, relayCtx)

	var identityPath = filepath.Join(t.TempDir(), "identity.json")
	cmd := exec.Command(portalBin, "expose", "--log-format", "json",
		"--relays", relayMembership.relayURL, "--discovery=false",
		"--identity-path", identityPath, target.Host)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start portal expose: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	records := make(chan map[string]any, 64)
	go readLifecycleRecords(t, stdout, records)
	go drainLifecycleStderr(stderr)

	ready := waitLifecycleRecord(t, records, func(record map[string]any) bool {
		return record["event"] == "relay_status" && record["state"] == "ready"
	}, 60*time.Second)
	relayURL, _ := ready["relay_url"].(string)
	if relayURL != relayMembership.relayURL {
		t.Fatalf("ready record = %v, want relay_url %s", ready, relayMembership.relayURL)
	}
	publicURL, _ := ready["public_url"].(string)
	if publicURL == "" {
		t.Fatalf("ready record = %v, want the tenant-ready canonical public_url", ready)
	}
	if alias, hasAlias := ready["alias_url"]; hasAlias && alias != "" {
		t.Fatalf("ready record = %v, want no alias for an address-only identity", ready)
	}

	// Closing the relay drops its reverse sessions. The CLI must report
	// readiness loss before the relay returns with the same identity.
	relayCancel()
	stopJSONRelay(t, relayMembership.sniAddr)
	connecting := waitLifecycleRecord(t, records, func(record map[string]any) bool {
		return record["event"] == "relay_status" && record["state"] == "connecting"
	}, 60*time.Second)
	if connecting["relay_url"] != relayURL {
		t.Fatalf("connecting record = %v, want relay_url %s", connecting, relayURL)
	}
	if _, ok := connecting["alias_url"]; ok {
		t.Fatalf("connecting record = %v, want no alias while reconnecting", connecting)
	}
	restartCtx, restartCancel := context.WithCancel(context.Background())
	defer restartCancel()
	restartJSONRelay(t, restartCtx, relayMembership.stateDir, relayMembership.sniAddr, relayMembership.sniPort)

	restarted := waitLifecycleRecord(t, records, func(record map[string]any) bool {
		return record["event"] == "relay_status" && record["state"] == "ready"
	}, 60*time.Second)
	if restartedURL, _ := restarted["relay_url"].(string); restartedURL != relayURL {
		t.Fatalf("re-ready record = %v, want relay_url %s", restarted, relayURL)
	}
	if restartedPublic, _ := restarted["public_url"].(string); restartedPublic != publicURL {
		t.Fatalf("re-ready record = %v, want the same canonical public_url %s", restarted, publicURL)
	}
}

// stopJSONRelay polls until the relay's SNI listener port is free, so
// the restart reusing the same state dir and coordinates cannot race
// the shutdown.
func stopJSONRelay(t *testing.T, sniAddr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", sniAddr, time.Second)
		if err != nil {
			return
		}
		_ = conn.Close()
		if !time.Now().Before(deadline) {
			t.Fatalf("relay SNI listener on %s never closed", sniAddr)
		}
		<-time.After(100 * time.Millisecond)
	}
}

// restartJSONRelay boots one real relay on the already-probed member
// coordinates so the CLI re-registration reconnects to the same origin.
func restartJSONRelay(t *testing.T, ctx context.Context, stateDir, sniAddr string, sniPort int) *portal.Server {
	t.Helper()
	relay, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     "https://" + sniAddr,
		StateDir:      stateDir,
		SNIListenAddr: sniAddr,
		SNIPort:       sniPort,
	})
	if err != nil {
		t.Fatalf("create restarted relay: %v", err)
	}
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		t.Fatalf("start restarted relay: %v", err)
	}
	return relay
}

func readLifecycleRecords(t *testing.T, stdout io.Reader, records chan<- map[string]any) {
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		var record map[string]any
		if !strings.HasPrefix(line, "{") ||
			json.Unmarshal([]byte(line), &record) != nil {
			records <- map[string]any{"event": "non-json", "line": line}
			continue
		}
		records <- record
	}
}

func drainLifecycleStderr(stderr io.Reader) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		// Consumer-facing stderr messages stay human-readable; this test
		// only requires stdout parseability.
	}
}

func waitLifecycleRecord(t *testing.T, records <-chan map[string]any, match func(map[string]any) bool, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case record := <-records:
			if match(record) {
				return record
			}
		case <-deadline:
			t.Fatalf("no matching lifecycle record within %v", timeout)
			return nil
		}
	}
}

// repoRoot locates the module root from the test binary's working
// directory: the e2e package dir or the repo root, whichever applies.
func repoRoot(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"..", "."} {
		if _, err := os.Stat(filepath.Join(candidate, "go.mod")); err == nil {
			return candidate
		}
	}
	t.Fatal("locate repository root")
	return ""
}
