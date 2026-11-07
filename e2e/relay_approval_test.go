package e2e_test

import (
	"context"
	"errors"
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

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func ptr[T any](value T) *T { return &value }

func waitPolicyLease(t *testing.T, ctx context.Context, client *http.Client, base *url.URL) types.PolicyLease {
	t.Helper()
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	deadline := time.After(15 * time.Second)
	for {
		var state types.PolicyStateResponse
		if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodGet, types.PathPolicyState, nil, headers, &state); err != nil {
			t.Fatal(err)
		}
		if len(state.Leases) > 0 {
			return state.Leases[0]
		}
		select {
		case <-deadline:
			t.Fatal("lease never registered")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func setLeasePolicy(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, update types.LeasePolicyUpdate) {
	t.Helper()
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathPolicyLeases, update, headers, new(struct{})); err != nil {
		t.Fatal(err)
	}
}

// A running SDK follows every admin decision on a manual relay. Old SDKs get
// the same retraction, because the relay closes the lease's idle streams.
func TestManualRelayApprovalLifecycle(t *testing.T) {
	ctx, base, client := startPolicyRelay(t, t.TempDir(), "--approval-mode", "manual")
	leaseIdentity, err := identity.Generate("approval-lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	exposure, err := sdk.Expose(ctx, leaseIdentity, []string{"https://localhost:" + base.Port()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exposure.Close() })
	go func() {
		_ = sdk.RunHTTP(ctx, exposure, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "approved tenant")
		}), "")
	}()

	waitStatus := func(name string, match func(sdk.RelayStatus) bool) sdk.RelayStatus {
		t.Helper()
		deadline := time.After(20 * time.Second)
		for {
			if relays := exposure.Relays(); len(relays) == 1 && match(relays[0]) {
				return relays[0]
			}
			select {
			case <-deadline:
				t.Fatalf("status never reached %s: %+v", name, exposure.Relays())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	waitApproval := func(want sdk.RelayApproval) {
		t.Helper()
		status := waitStatus(string(want), func(status sdk.RelayStatus) bool { return status.Approval == want })
		if status.State != sdk.RelayConnecting || status.PublicURL != "" || status.Active() {
			t.Fatalf("%s status = %+v, want no usable endpoint", want, status)
		}
	}
	waitReady := func() string {
		t.Helper()
		status := waitStatus("ready", func(status sdk.RelayStatus) bool { return status.State == sdk.RelayReady })
		if status.Approval != "" {
			t.Fatalf("ready status = %+v", status)
		}
		return status.PublicURL
	}
	key := leaseIdentity.Key()

	waitApproval(sdk.RelayApprovalPending)

	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsApproved: ptr(true)})
	publicURL := waitReady()
	tenantClient := relayTenantClient(t, client, base)
	response, err := tenantClient.Get(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "approved tenant" {
		t.Fatalf("approved lease answered %d %q", response.StatusCode, body)
	}

	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsApproved: ptr(false)})
	waitApproval(sdk.RelayApprovalPending)
	if lease := waitPolicyLease(t, ctx, client, base); lease.Ready != 0 {
		t.Fatalf("a revoked lease kept %d idle streams", lease.Ready)
	}

	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsApproved: ptr(true)})
	waitReady()

	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsDenied: ptr(true)})
	waitApproval(sdk.RelayApprovalRefused)

	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsDenied: ptr(false), IsApproved: ptr(true)})
	waitReady()

	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsBanned: ptr(true)})
	waitApproval(sdk.RelayApprovalRefused)
}

// One reverse capability outlives every decision: an approved lease needs no
// new registration, and the refusal names the decision.
func TestReverseCapabilitySurvivesApproval(t *testing.T) {
	ctx, base, client := startPolicyRelay(t, t.TempDir(), "--approval-mode", "manual")
	leaseIdentity, err := identity.Generate("approval-capability")
	if err != nil {
		t.Fatal(err)
	}
	var challenge types.RegisterChallengeResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{Identity: leaseIdentity}, nil, &challenge); err != nil {
		t.Fatal(err)
	}
	signature, err := identity.NewLocalAuthority(leaseIdentity).SignEthereumPersonalMessage(challenge.SIWEMessage)
	if err != nil {
		t.Fatal(err)
	}
	var registered types.RegisterResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{ChallengeID: challenge.ChallengeID, SIWEMessage: challenge.SIWEMessage, SIWESignature: signature}, nil, &registered); err != nil {
		t.Fatal(err)
	}
	connect := func() error {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+types.PathSDKConnect, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set(types.HeaderReverseCapability, registered.ReverseEndpoint.Capability)
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "raw")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode == http.StatusSwitchingProtocols {
			return nil
		}
		return utils.DecodeAPIRequestError(response)
	}
	key := leaseIdentity.Key()

	if err := connect(); !errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseRejected}) {
		t.Fatalf("waiting connect = %v", err)
	}
	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsApproved: ptr(true)})
	if err := connect(); err != nil {
		t.Fatalf("approved connect = %v", err)
	}
	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsDenied: ptr(true)})
	if err := connect(); !errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseDenied}) {
		t.Fatalf("denied connect = %v", err)
	}
}

// The CLI's machine-readable output never reads as usable while a raw TCP lease
// waits, and it retracts readiness when the lease loses approval.
func TestPortalExposeWaitsForRelayApproval(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the portal binary")
	}
	portalBin := filepath.Join(t.TempDir(), "portal")
	build := exec.Command("go", "build", "-o", portalBin, "./cmd/portal-tunnel")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build portal binary: %v\n%s", err, out)
	}
	lo, hi := ephemeralPortRange()
	ctx, base, client := startPolicyRelay(t, t.TempDir(),
		"--approval-mode", "manual",
		"--tcp-enabled=true",
		"--min-port="+strconv.Itoa(lo),
		"--max-port="+strconv.Itoa(hi),
	)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
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

	cmd := exec.Command(portalBin, "expose", "--log-format", "json", "--tcp",
		"--relays", "https://localhost:"+base.Port(), "--discovery=false",
		"--identity-path", filepath.Join(t.TempDir(), "identity.json"), target.Addr().String())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
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
	isStatus := func(record map[string]any) bool { return record["event"] == "relay_status" }

	waiting := waitLifecycleRecord(t, records, func(record map[string]any) bool {
		if record["message"] == "raw transport endpoints allocated" || (isStatus(record) && record["state"] == "ready") {
			t.Fatalf("usable output while waiting: %v", record)
		}
		return isStatus(record) && record["approval"] == "pending"
	}, 30*time.Second)
	if fmt.Sprint(waiting["message"]) != "waiting for relay approval" || waiting["public_url"] != "" {
		t.Fatalf("waiting record = %v", waiting)
	}

	key := waitPolicyLease(t, ctx, client, base).IdentityKey
	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsApproved: ptr(true)})
	const rawLine = "raw transport endpoints allocated"
	var ready bool
	var raw map[string]any
	waitLifecycleRecord(t, records, func(record map[string]any) bool {
		ready = ready || (isStatus(record) && record["state"] == "ready")
		if record["message"] == rawLine {
			raw = record
		}
		return ready && raw != nil
	}, 30*time.Second)

	// Visitors claim streams, which must not print the address again.
	_, port, err := net.SplitHostPort(fmt.Sprint(raw["tcp_addr"]))
	if err != nil {
		t.Fatalf("raw line = %v: %v", raw, err)
	}
	for range 10 {
		var burst sync.WaitGroup
		for range 4 {
			burst.Go(func() {
				conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 2*time.Second)
				if err != nil {
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

	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsApproved: ptr(false)})
	waitLifecycleRecord(t, records, func(record map[string]any) bool {
		if record["message"] == rawLine {
			t.Fatalf("the address printed again: %v", record)
		}
		return isStatus(record) && record["state"] == "connecting"
	}, 30*time.Second)
	waitLifecycleRecord(t, records, func(record map[string]any) bool {
		return isStatus(record) && record["approval"] == "pending"
	}, 30*time.Second)
}
