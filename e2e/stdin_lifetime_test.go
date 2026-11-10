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

	for _, mode := range []string{"closed", "startup", "ready", "reconnect", "failed", "parent-exit", "parent-kill", "retained-writer", "default"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			relay := startMembershipRelay(t, ctx)
			service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, marker)
			}))
			defer service.Close()
			args := []string{bin, "expose", "--log-format=json", "--discovery=false",
				"--relays", relay.relayURL, "--identity-path", filepath.Join(t.TempDir(), "identity.json"),
				"--http-route", "/=" + service.URL}
			if mode != "default" {
				args = append(args, "--exit-on-stdin-eof")
			}
			var contacted <-chan struct{}
			if mode == "startup" || mode == "failed" {
				requests := make(chan struct{}, 1)
				unavailable := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					select {
					case requests <- struct{}{}:
					default:
					}
					if mode == "startup" {
						<-r.Context().Done()
						return
					}
					// An incompatible relay is a permanent SDK failure, without retries.
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"ok":true,"data":{"protocol_version":"incompatible"}}`)
				}))
				t.Cleanup(unavailable.Close)
				args[5] = unavailable.URL
				contacted = requests
			}

			cmd := exec.Command(args[0], args[1:]...)
			owner := mode == "parent-exit" || mode == "parent-kill" || mode == "retained-writer"
			if owner {
				helperArgs, err := json.Marshal(args)
				if err != nil {
					t.Fatal(err)
				}
				cmd = exec.Command(os.Args[0], "-test.run=^TestPortalStdinOwnerProcess$")
				role := "owner"
				if mode == "retained-writer" {
					role = "retain"
				}
				cmd.Env = append(os.Environ(), "PORTAL_STDIN_LIFETIME_HELPER="+role,
					"PORTAL_STDIN_LIFETIME_ARGS="+string(helperArgs))
			}
			inputReader, stdin, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer inputReader.Close()
			defer stdin.Close()
			cmd.Stdin = inputReader
			// Keep reading after the owner's Wait: an orphan child still owns stdout.
			stdout, outputWriter, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { stdout.Close() })
			cmd.Stdout, cmd.Stderr = outputWriter, os.Stderr
			if mode == "closed" {
				stdin.Close()
			}
			if err := cmd.Start(); err != nil {
				outputWriter.Close()
				t.Fatal(err)
			}
			inputReader.Close()
			outputWriter.Close()
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			records := make(chan map[string]any, 64)
			go readLifecycleRecords(t, stdout, records)
			var descendants []*os.Process
			outputClosed := false
			t.Cleanup(func() {
				stdin.Close()
				_ = cmd.Process.Kill()
				for _, process := range descendants {
					if !outputClosed {
						_ = process.Kill()
					}
					_ = process.Release()
				}
				for range records {
				}
			})
			var ready map[string]any
			if owner {
				record := waitLifecycleRecord(t, records, func(r map[string]any) bool {
					if r["event"] == "relay_status" && r["state"] == "ready" {
						ready = r
					}
					return r["child_pid"] != nil
				}, 30*time.Second)
				for _, field := range []string{"child_pid", "holder_pid"} {
					if field == "holder_pid" && mode != "retained-writer" {
						continue
					}
					process, err := os.FindProcess(int(record[field].(float64)))
					if err != nil {
						t.Fatal(err)
					}
					descendants = append(descendants, process)
				}
			}
			publicURL := ""
			if mode == "startup" {
				select {
				case <-contacted:
				case <-time.After(30 * time.Second):
					t.Fatal("portal never contacted the relay during startup")
				}
			} else if mode == "failed" {
				waitLifecycleRecord(t, records, func(r map[string]any) bool {
					return r["event"] == "relay_status" && r["state"] == "failed"
				}, 30*time.Second)
			} else if mode != "closed" {
				if ready == nil {
					ready = waitLifecycleRecord(t, records, func(r map[string]any) bool {
						return r["event"] == "relay_status" && r["state"] == "ready"
					}, 60*time.Second)
				}
				publicURL = ready["public_url"].(string)
				waitServesMarker(t, "before owner shutdown", relay, publicURL, 15*time.Second)
			}
			if mode == "reconnect" {
				cancel()
				stopJSONRelay(t, relay.sniAddr)
				waitLifecycleRecord(t, records, func(r map[string]any) bool {
					return r["event"] == "relay_status" && r["state"] == "connecting"
				}, 30*time.Second)
			}
			if mode == "parent-kill" || mode == "retained-writer" {
				if err := cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				<-done
				if mode == "retained-writer" {
					// EOF must wait for the extra writer, even after the owner dies.
					observe := time.NewTimer(time.Second)
				observeWriter:
					for {
						select {
						case <-observe.C:
							break observeWriter
						case _, ok := <-records:
							if !ok {
								t.Fatal("portal stopped while another process retained a writer")
							}
						}
					}
					waitServesMarker(t, "with inherited writer", relay, publicURL, 15*time.Second)
				}
			}
			if mode != "closed" {
				if _, err := io.WriteString(stdin, "ignored bytes\n"); err != nil && !owner {
					t.Fatal(err)
				}
			}
			stdin.Close()
			if mode == "default" {
				waitServesMarker(t, "without lifetime flag", relay, publicURL, 15*time.Second)
				select {
				case err := <-done:
					t.Fatalf("default expose stopped on EOF: %v", err)
				case <-time.After(time.Second):
				}
				return
			}
			deadline := time.After(20 * time.Second)
			for {
				select {
				case _, ok := <-records:
					if !ok {
						outputClosed = true
						if mode != "parent-kill" && mode != "retained-writer" {
							if err := <-done; err != nil {
								t.Fatalf("owner shutdown failed: %v", err)
							}
						}
						if publicURL != "" && mode != "reconnect" {
							if _, served := tenantGet(relay.sniAddr, relay.certPath, publicURL); served {
								t.Fatal("tunnel still served after owner shutdown")
							}
						}
						return
					}
				case <-deadline:
					t.Fatal("portal did not close its output after owner shutdown")
				}
			}
		})
	}
}
