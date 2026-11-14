package e2e_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func isRelayStatusRecord(record map[string]any) bool { return record["event"] == "relay_status" }

func serveTCPEchoTarget(t *testing.T) net.Listener {
	t.Helper()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return target
}

func exposeProcessPipes(t *testing.T, cmd *exec.Cmd) (io.Reader, io.Reader) {
	t.Helper()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	return stdout, stderr
}

func launchTCPExpose(t *testing.T, portalBin, relayPort, targetAddr string) chan map[string]any {
	t.Helper()
	cmd := exec.Command(portalBin, "expose", "--log-format", "json", "--tcp",
		"--relays", "https://localhost:"+relayPort, "--discovery=false",
		"--identity-path", filepath.Join(t.TempDir(), "identity.json"), targetAddr)
	stdout, stderr := exposeProcessPipes(t, cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	records := make(chan map[string]any, 4096)
	go readLifecycleRecords(t, stdout, records)
	go drainLifecycleStderr(stderr)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		for range records {
		}
		_ = cmd.Wait()
	})
	return records
}

func assertApprovalWaiting(t *testing.T, records <-chan map[string]any) {
	t.Helper()
	waiting := waitLifecycleRecord(t, records, func(record map[string]any) bool {
		if record["message"] == "raw transport endpoints allocated" || (isRelayStatusRecord(record) && record["state"] == "ready") {
			t.Fatalf("usable output while waiting: %v", record)
		}
		return isRelayStatusRecord(record) && record["approval"] == "pending"
	}, 30*time.Second)
	if fmt.Sprint(waiting["message"]) != "waiting for relay approval" || waiting["public_url"] != "" {
		t.Fatalf("waiting record = %v", waiting)
	}
}

func approveAndAwaitRawEndpoints(t *testing.T, ctx context.Context, records chan map[string]any, client *http.Client, base *url.URL) (string, string) {
	t.Helper()
	key := waitPolicyLease(t, ctx, client, base).IdentityKey
	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsApproved: ptr(true)})
	const rawLine = "raw transport endpoints allocated"
	var ready bool
	var raw map[string]any
	waitLifecycleRecord(t, records, func(record map[string]any) bool {
		ready = ready || (isRelayStatusRecord(record) && record["state"] == "ready")
		if record["message"] == rawLine {
			raw = record
		}
		return ready && raw != nil
	}, 30*time.Second)

	_, port, err := net.SplitHostPort(fmt.Sprint(raw["tcp_addr"]))
	if err != nil {
		t.Fatalf("raw line = %v: %v", raw, err)
	}
	return key, port
}

func burstRawConnections(t *testing.T, port string) {
	t.Helper()
	for range 10 {
		var burst sync.WaitGroup
		for range 4 {
			burst.Go(func() {
				conn, dialErr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 2*time.Second)
				if dialErr != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn.Write([]byte("x"))
				_, _ = io.ReadFull(conn, make([]byte, 1))
			})
		}
		burst.Wait()
	}
}

func revokeAndAwaitReconnect(t *testing.T, ctx context.Context, records chan map[string]any, client *http.Client, base *url.URL, key string) {
	t.Helper()
	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsApproved: ptr(false)})
	waitLifecycleRecord(t, records, func(record map[string]any) bool {
		if record["message"] == "raw transport endpoints allocated" {
			t.Fatalf("the address printed again: %v", record)
		}
		return isRelayStatusRecord(record) && record["state"] == "connecting"
	}, 30*time.Second)
	waitLifecycleRecord(t, records, func(record map[string]any) bool {
		return isRelayStatusRecord(record) && record["approval"] == "pending"
	}, 30*time.Second)
}

func TestPortalExposeWaitsForRelayApproval(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the portal binary")
	}
	portalBin := buildPortalTunnelBinary(t)
	lo, hi := ephemeralPortRange()
	ctx, base, client := startPolicyRelay(t, t.TempDir(),
		"--approval-mode", "manual",
		"--tcp-enabled=true",
		"--min-port="+strconv.Itoa(lo),
		"--max-port="+strconv.Itoa(hi),
	)
	target := serveTCPEchoTarget(t)
	records := launchTCPExpose(t, portalBin, base.Port(), target.Addr().String())
	assertApprovalWaiting(t, records)
	key, port := approveAndAwaitRawEndpoints(t, ctx, records, client, base)
	burstRawConnections(t, port)
	revokeAndAwaitReconnect(t, ctx, records, client, base, key)
}

func checkLiveUDPDisablesAtRuntime(t *testing.T) {
	t.Helper()
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	lo, hi := ephemeralPortRange()
	ctx, base, client := startPolicyRelay(t, t.TempDir(),
		"--udp-enabled=true",
		"--min-port="+strconv.Itoa(lo),
		"--max-port="+strconv.Itoa(hi),
	)
	var settings types.PolicySettings
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathPolicy,
		types.PolicySettings{ApprovalMode: "auto"}, headers, &settings); err != nil {
		t.Fatalf("runtime udp disable: %v", err)
	}
	if settings.UDP.Enabled {
		t.Fatal("udp policy still enabled after runtime disable")
	}
}

func checkUDPEnableRequiresRestart(t *testing.T) {
	t.Helper()
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	ctx, base, client := startPolicyRelay(t, t.TempDir())
	err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathPolicy,
		types.PolicySettings{ApprovalMode: "auto", UDP: types.PolicyPortSettings{Enabled: true}}, headers, new(types.PolicySettings))
	if err == nil {
		t.Fatal("enabling udp without a backhaul listener must be refused")
	}
}

func TestUDPRuntimeToggle(t *testing.T) {
	t.Run("disable while listener is live", func(t *testing.T) {
		checkLiveUDPDisablesAtRuntime(t)
	})

	t.Run("enable without listener requires restart", func(t *testing.T) {
		checkUDPEnableRequiresRestart(t)
	})
}
