package e2e_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// These are released modules, not local replacements or copies of wire structs.
// Keep this list aligned with docs/maintainer/sdk-compatibility.md.
func TestReleasedSDKCompatibility(t *testing.T) {
	for _, release := range []string{"v2.7.3", "v2.7.4"} {
		t.Run(release, func(t *testing.T) {
			t.Parallel()
			binary := buildReleasedSDK(t, release)
			for _, name := range []string{"compat", ""} {
				t.Run("name="+name, func(t *testing.T) {
					t.Parallel()
					testReleasedSDKLifecycle(t, binary, release, name)
				})
			}
		})
	}
}

func buildReleasedSDK(t *testing.T, release string) string {
	t.Helper()
	dir := t.TempDir()
	source, err := os.ReadFile(filepath.Join(repoRoot(t), "e2e", "testdata", "released-sdk", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), source, 0600); err != nil {
		t.Fatal(err)
	}
	module := "module portal-released-sdk-test\n\ngo 1.27.3\n\nrequire github.com/gosuda/portal-tunnel/v2 " + release + "\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(module), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "released-sdk")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-mod=mod", "-o", binary, ".")
	build.Dir = dir
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "GOWORK=") && !strings.HasPrefix(value, "GOFLAGS=") {
			build.Env = append(build.Env, value)
		}
	}
	build.Env = append(build.Env, "GOWORK=off", "GOFLAGS=")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build pinned %s SDK: %v\n%s", release, err, output)
	}
	return binary
}

func testReleasedSDKLifecycle(t *testing.T, binary, release, name string) {
	t.Helper()
	service, target := listenOriginService(t, "127.0.0.1")
	defer service.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	h := &harness{t: t, service: service, cancel: cancel}
	h.server, h.sniAddr, h.sniPort, h.stateDir, _ = bootHarnessRelay(t, ctx, "127.0.0.1", "", h)
	h.certificate = filepath.Join(h.stateDir, "fullchain.pem")
	defer func() { stopRelay(t, h.server) }()
	command := exec.CommandContext(ctx, binary, h.server.PortalURL(), target.Host, name)
	command.Stderr = os.Stderr
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		_ = input.Close()
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	var ready struct{ Release, PublicURL, AliasURL string }
	if err := json.NewDecoder(output).Decode(&ready); err != nil {
		t.Fatalf("released SDK readiness: %v", err)
	}
	if ready.Release != release || ready.PublicURL == "" || (name != "" && ready.AliasURL == "") || (name == "" && ready.AliasURL != "") {
		t.Fatalf("released SDK returned unexpected endpoints: %+v", ready)
	}
	if got := h.get(ready.PublicURL); got != marker {
		t.Fatalf("released SDK canonical response = %q", got)
	}
	if ready.AliasURL != "" && h.get(ready.AliasURL) != marker {
		t.Fatal("released SDK friendly alias did not serve the origin")
	}
	awaitReleasedSDKRenewal(t, h)
	shutdownRelayForRestart(t, h)
	startRestartedRelay(t, h)
	if !awaitExposureRouted(t, h, ready.PublicURL) {
		t.Fatal("released SDK did not reconnect after relay restart")
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	err = command.Wait()
	waited = true
	if err != nil {
		t.Fatalf("released SDK close: %v", err)
	}
	if leases := h.server.PublicLeases(); len(leases) != 0 {
		t.Fatalf("released SDK close left public leases: %+v", leases)
	}
	if _, ok := h.tryGet(ready.PublicURL); ok {
		t.Fatal("closed released SDK still serves its origin")
	}
}

func awaitReleasedSDKRenewal(t *testing.T, h *harness) {
	t.Helper()
	leases := h.server.PublicLeases()
	if len(leases) != 1 {
		t.Fatalf("released SDK public leases = %+v", leases)
	}
	initial := leases[0]
	deadline := time.NewTimer(2 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("released SDK did not renew its normal lease")
		case <-ticker.C:
			current := h.server.PublicLeases()
			if len(current) == 1 && current[0].ExpiresAt.After(initial.ExpiresAt) {
				if current[0].CanonicalHostname != initial.CanonicalHostname || current[0].Namespace != "" {
					t.Fatal("renewal changed the endpoint or opted it into Local TLS")
				}
				return
			}
		}
	}
}
