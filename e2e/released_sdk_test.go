package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// These are released modules, not local replacements or copies of wire structs.
// Keep this list aligned with docs/maintainer/sdk-compatibility.md.
func TestReleasedSDKRejectsRemovedProtocol(t *testing.T) {
	for _, release := range []string{"v2.7.3", "v2.7.4"} {
		t.Run(release, func(t *testing.T) {
			t.Parallel()
			binary := buildReleasedSDK(t, release)
			for _, name := range []string{"compat", ""} {
				t.Run("name="+name, func(t *testing.T) {
					t.Parallel()
					testReleasedSDKRejection(t, binary, release, name)
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

func testReleasedSDKRejection(t *testing.T, binary, release, name string) {
	t.Helper()
	service, _ := listenOriginService(t, "127.0.0.1")
	defer service.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	h := &harness{t: t, service: service, cancel: cancel}
	server, _, _, _, _ := bootHarnessRelay(t, ctx, "127.0.0.1", "", h)
	defer stopRelay(t, server)
	command := exec.CommandContext(ctx, binary, server.PortalURL(), name)
	command.Stderr = os.Stderr
	output, err := command.Output()
	if err != nil {
		t.Fatalf("run pinned %s SDK: %v", release, err)
	}
	var result struct {
		Release         string
		ProtocolVersion string
		Error           string
		Terminal        bool
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode released SDK result: %v\n%s", err, output)
	}
	if result.Release != release || result.ProtocolVersion != "10" {
		t.Fatalf("unexpected released SDK: %+v", result)
	}
	want := fmt.Sprintf("relay=%q client=%q", types.SDKVersion, result.ProtocolVersion)
	if !result.Terminal || !strings.Contains(result.Error, "relay sdk protocol version mismatch: "+want) {
		t.Fatalf("released SDK must reject the removed protocol during negotiation: %+v", result)
	}
	if leases := server.PublicLeases(); len(leases) != 0 {
		t.Fatalf("incompatible released SDK registered public leases: %+v", leases)
	}
}
