package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The helper is a real application process owning the Portal child's stdin.
// os.Exit and Process.Kill exercise OS pipe closure without Go test cleanup.
func TestPortalStdinOwnerProcess(t *testing.T) {
	role := os.Getenv("PORTAL_STDIN_LIFETIME_HELPER")
	if role == "" {
		return
	}
	if role == "writer" {
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("PORTAL_STDIN_LIFETIME_ARGS")), &args); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(args[0], args[1:]...)
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	writer, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	holderPID := 0
	if role == "retain" {
		// Deliberately give another process a copy of the lifetime writer.
		holder := exec.Command(os.Args[0], "-test.run=^TestPortalStdinOwnerProcess$")
		holder.Env = append(os.Environ(), "PORTAL_STDIN_LIFETIME_HELPER=writer")
		holder.Stdin, holder.Stdout, holder.Stderr = os.Stdin, writer, os.Stderr
		if err := holder.Start(); err != nil {
			t.Fatal(err)
		}
		holderPID = holder.Process.Pid
	}
	fmt.Fprintf(os.Stdout, "{\"child_pid\":%d,\"holder_pid\":%d}\n", child.Process.Pid, holderPID)
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func TestPortalExposeStdinLifetime(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs portal and its owning application")
	}
	bin := filepath.Join(t.TempDir(), "portal")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./cmd/portal-tunnel")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build portal: %v\n%s", err, out)
	}

	t.Run("requires-pipe", func(t *testing.T) {
		input, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()
		cmd := exec.CommandContext(t.Context(), bin, "expose", "--exit-on-stdin-eof", "3000")
		cmd.Stdin = input
		if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "requires a caller-owned stdin pipe") {
			t.Fatalf("non-pipe stdin: err=%v output=%s", err, out)
		}
	})
	t.Run("closed", func(t *testing.T) {
		relay := startMembershipRelay(t, t.Context())
		process := newStdinLifetimeProcess(t, bin, relay.relayURL, "--exit-on-stdin-eof")
		process.stdin.Close()
		process.start(t, "")
		process.waitExit(t)
	})
	t.Run("startup", func(t *testing.T) {
		contacted := make(chan struct{}, 1)
		relay := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			select {
			case contacted <- struct{}{}:
			default:
			}
			<-r.Context().Done()
		}))
		t.Cleanup(relay.Close)
		process := newStdinLifetimeProcess(t, bin, relay.URL, "--exit-on-stdin-eof")
		process.start(t, "")
		select {
		case <-contacted:
		case <-time.After(30 * time.Second):
			t.Fatal("portal never contacted the relay during startup")
		}
		process.stdin.Close()
		process.waitExit(t)
	})
	t.Run("ready", func(t *testing.T) {
		relay := startMembershipRelay(t, t.Context())
		process := newStdinLifetimeProcess(t, bin, relay.relayURL, "--exit-on-stdin-eof")
		process.start(t, "")
		publicURL := process.waitReady(t, relay)
		if _, err := io.WriteString(process.stdin, "ignored bytes\n"); err != nil {
			t.Fatal(err)
		}
		process.assertRunning(t)
		waitServesMarker(t, "after stdin bytes", relay, publicURL, 15*time.Second)
		process.stdin.Close()
		process.waitExit(t)
		if _, served := tenantGet(relay.sniAddr, relay.certPath, publicURL); served {
			t.Fatal("tunnel still served after owner shutdown")
		}
	})
	t.Run("reconnect", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		relay := startMembershipRelay(t, ctx)
		process := newStdinLifetimeProcess(t, bin, relay.relayURL, "--exit-on-stdin-eof")
		process.start(t, "")
		process.waitReady(t, relay)
		cancel()
		stopJSONRelay(t, relay.sniAddr)
		waitLifecycleRecord(t, process.records, func(r map[string]any) bool {
			return r["event"] == "relay_status" && r["state"] == "connecting"
		}, 30*time.Second)
		process.stdin.Close()
		process.waitExit(t)
	})
	t.Run("failed", func(t *testing.T) {
		// An incompatible relay is a permanent SDK failure, without retries.
		relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true,"data":{"protocol_version":"incompatible"}}`)
		}))
		t.Cleanup(relay.Close)
		process := newStdinLifetimeProcess(t, bin, relay.URL, "--exit-on-stdin-eof")
		process.start(t, "")
		waitLifecycleRecord(t, process.records, func(r map[string]any) bool {
			return r["event"] == "relay_status" && r["state"] == "failed"
		}, 30*time.Second)
		process.stdin.Close()
		process.waitExit(t)
	})
	t.Run("parent-exit", func(t *testing.T) {
		relay := startMembershipRelay(t, t.Context())
		process := newStdinLifetimeProcess(t, bin, relay.relayURL, "--exit-on-stdin-eof")
		process.start(t, "owner")
		publicURL := process.waitReady(t, relay)
		process.stdin.Close()
		process.waitExit(t)
		if _, served := tenantGet(relay.sniAddr, relay.certPath, publicURL); served {
			t.Fatal("tunnel still served after parent exit")
		}
	})
	t.Run("parent-kill", func(t *testing.T) {
		relay := startMembershipRelay(t, t.Context())
		process := newStdinLifetimeProcess(t, bin, relay.relayURL, "--exit-on-stdin-eof")
		process.start(t, "owner")
		publicURL := process.waitReady(t, relay)
		if err := process.cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		process.waitOutputClosed(t)
		if _, served := tenantGet(relay.sniAddr, relay.certPath, publicURL); served {
			t.Fatal("tunnel still served after parent kill")
		}
	})
	t.Run("retained-writer", func(t *testing.T) {
		relay := startMembershipRelay(t, t.Context())
		process := newStdinLifetimeProcess(t, bin, relay.relayURL, "--exit-on-stdin-eof")
		process.start(t, "retain")
		publicURL := process.waitReady(t, relay)
		if err := process.cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		// Killing the owner cannot deliver EOF while the holder keeps a writer.
		process.assertRunning(t)
		waitServesMarker(t, "with inherited writer", relay, publicURL, 15*time.Second)
		process.stdin.Close()
		process.waitOutputClosed(t)
		if _, served := tenantGet(relay.sniAddr, relay.certPath, publicURL); served {
			t.Fatal("tunnel still served after the last writer closed")
		}
	})
	t.Run("default", func(t *testing.T) {
		relay := startMembershipRelay(t, t.Context())
		process := newStdinLifetimeProcess(t, bin, relay.relayURL)
		process.start(t, "")
		publicURL := process.waitReady(t, relay)
		process.stdin.Close()
		process.assertRunning(t)
		waitServesMarker(t, "without lifetime flag", relay, publicURL, 15*time.Second)
	})
}

// stdinLifetimeProcess owns real subprocess pipes and cleanup. Scenarios choose
// when to close stdin, kill the owner, or stop the relay themselves.
type stdinLifetimeProcess struct {
	args         []string
	inputReader  *os.File
	stdin        *os.File
	cmd          *exec.Cmd
	records      <-chan map[string]any
	done         <-chan error
	descendants  []*os.Process
	ready        map[string]any
	outputClosed bool
}

func newStdinLifetimeProcess(t *testing.T, bin, relayURL string, flags ...string) *stdinLifetimeProcess {
	t.Helper()
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, marker)
	}))
	t.Cleanup(service.Close)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		reader.Close()
		writer.Close()
	})
	args := []string{bin, "expose", "--log-format=json", "--discovery=false",
		"--relays", relayURL, "--identity-path", filepath.Join(t.TempDir(), "identity.json"),
		"--http-route", "/=" + service.URL}
	return &stdinLifetimeProcess{args: append(args, flags...), inputReader: reader, stdin: writer}
}

func (p *stdinLifetimeProcess) start(t *testing.T, ownerRole string) {
	t.Helper()
	cmd := exec.Command(p.args[0], p.args[1:]...)
	if ownerRole != "" {
		helperArgs, err := json.Marshal(p.args)
		if err != nil {
			t.Fatal(err)
		}
		cmd = exec.Command(os.Args[0], "-test.run=^TestPortalStdinOwnerProcess$")
		cmd.Env = append(os.Environ(), "PORTAL_STDIN_LIFETIME_HELPER="+ownerRole,
			"PORTAL_STDIN_LIFETIME_ARGS="+string(helperArgs))
	}
	// Keep reading after the owner's Wait: an orphan child still owns stdout.
	stdout, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdout.Close() })
	cmd.Stdin, cmd.Stdout, cmd.Stderr = p.inputReader, writer, os.Stderr
	if err := cmd.Start(); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	p.inputReader.Close()
	writer.Close()
	p.cmd = cmd
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	p.done = done
	records := make(chan map[string]any, 64)
	go readLifecycleRecords(t, stdout, records)
	p.records = records
	t.Cleanup(func() {
		p.stdin.Close()
		if !p.outputClosed {
			_ = cmd.Process.Kill()
			for _, process := range p.descendants {
				_ = process.Kill()
			}
		}
		for _, process := range p.descendants {
			_ = process.Release()
		}
		for range p.records {
		}
	})
	if ownerRole == "" {
		return
	}
	record := waitLifecycleRecord(t, p.records, func(r map[string]any) bool {
		if r["event"] == "relay_status" && r["state"] == "ready" {
			p.ready = r
		}
		return r["child_pid"] != nil
	}, 30*time.Second)
	for _, field := range []string{"child_pid", "holder_pid"} {
		pid := int(record[field].(float64))
		if pid == 0 {
			continue
		}
		process, err := os.FindProcess(pid)
		if err != nil {
			t.Fatal(err)
		}
		p.descendants = append(p.descendants, process)
	}
}

func (p *stdinLifetimeProcess) waitReady(t *testing.T, relay membershipRelay) string {
	t.Helper()
	if p.ready == nil {
		p.ready = waitLifecycleRecord(t, p.records, func(r map[string]any) bool {
			return r["event"] == "relay_status" && r["state"] == "ready"
		}, 60*time.Second)
	}
	publicURL := p.ready["public_url"].(string)
	waitServesMarker(t, "before owner shutdown", relay, publicURL, 15*time.Second)
	return publicURL
}

func (p *stdinLifetimeProcess) assertRunning(t *testing.T) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		select {
		case <-deadline:
			return
		case _, ok := <-p.records:
			if !ok {
				t.Fatal("portal stopped while it should still be running")
			}
		}
	}
}

func (p *stdinLifetimeProcess) waitOutputClosed(t *testing.T) {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case _, ok := <-p.records:
			if !ok {
				p.outputClosed = true
				return
			}
		case <-deadline:
			t.Fatal("portal did not close its output after owner shutdown")
		}
	}
}

func (p *stdinLifetimeProcess) waitExit(t *testing.T) {
	t.Helper()
	p.waitOutputClosed(t)
	select {
	case err := <-p.done:
		if err != nil {
			t.Fatalf("owner shutdown failed: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("owner did not exit after closing its output")
	}
}
