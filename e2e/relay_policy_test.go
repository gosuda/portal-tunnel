package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func buildRelayBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "relay-server.exe")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./cmd/relay-server")
	build.Dir = ".."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build relay: %v\n%s", err, output)
	}
	return bin
}

// relayTenantClient reaches tenant hostnames through the local relay listener.
func relayTenantClient(t *testing.T, client *http.Client, base *url.URL) *http.Client {
	t.Helper()
	transport := client.Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, base.Host)
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func startPolicyRelay(t *testing.T, stateDir string, args ...string) (context.Context, *url.URL, *http.Client) {
	t.Helper()
	bin := buildRelayBinary(t)
	frontend := t.TempDir()
	if err := os.WriteFile(filepath.Join(frontend, "index.html"), []byte("portal"), 0o600); err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(harnessPort(t, "127.0.0.1"))
	base, err := url.Parse("https://127.0.0.1:" + port)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	commandArgs := []string{
		"--portal-url", "https://localhost:" + port,
		"--identity-path", stateDir,
		"--frontend-dir", frontend,
		"--admin-token", "admin-test",
	}
	command := exec.CommandContext(ctx, bin, append(commandArgs, args...)...)
	command.Dir = t.TempDir()
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	exited := make(chan struct{})
	go func() {
		serveResult <- command.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		cancel()
		<-exited
		if t.Failed() {
			t.Log(output.String())
		}
	})
	waitForRelayCertificateMaterial(t, stateDir)
	client := relayControlClient(t, stateDir)
	waitRelayReady(t, client, base.String(), serveResult)
	return ctx, base, client
}

// Exercise admin persistence and registration through the real relay binary.
// A failed allow-side policy write must leave the existing denial effective.
func TestRelayAccessPolicyTransaction(t *testing.T) {
	leaseIdentity, err := identity.Generate("policy-transaction")
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	policyPath := filepath.Join(stateDir, types.RelayPolicyFilename)
	initial, err := json.Marshal(map[string]any{
		"approval_mode": "auto", "banned_identity_keys": []string{leaseIdentity.Key()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, base, client := startPolicyRelay(t, stateDir, "--cache-enabled=false")

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
	setPolicy := func(body string, status int) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+types.PathPolicyLeases, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer admin-test")
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != status {
			t.Fatalf("policy status = %d, want %d", response.StatusCode, status)
		}
	}
	assertBlocked := func() {
		t.Helper()
		// Registration publishes access again, including after a failed save.
		if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{Identity: leaseIdentity}, nil, &challenge); err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+types.PathSDKConnect, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set(types.HeaderReverseCapability, registered.ReverseEndpoint.Capability)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("connect status = %d, want forbidden", response.StatusCode)
		}
	}
	assertBlocked()
	setPolicy(`{"identity_key":"`+leaseIdentity.Key()+`","is_banned":false,"is_denied":true}`, http.StatusOK)
	assertBlocked()

	// Make atomic replacement fail without permissions or filesystem mocks.
	// The relay has already loaded its state; a directory cannot be replaced
	// by the new policy file on either Windows or Unix.
	if err := os.Rename(policyPath, policyPath+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(policyPath, 0o700); err != nil {
		t.Fatal(err)
	}
	setPolicy(`{"identity_key":"`+leaseIdentity.Key()+`","is_denied":false}`, http.StatusInternalServerError)
	assertBlocked()
	var state types.PolicyStateResponse
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodGet, types.PathPolicyState, nil, headers, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Leases) != 1 || state.Leases[0].IsBanned || !state.Leases[0].IsDenied {
		t.Fatalf("failed save changed committed policy: %+v", state.Leases)
	}
}

// The startup mode applies before any admin call, and a mode saved in
// policy.json wins over it in both directions.
func TestRelayInitialApprovalMode(t *testing.T) {
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	effectiveMode := func(t *testing.T, ctx context.Context, base *url.URL, client *http.Client) string {
		t.Helper()
		var settings types.PolicySettings
		if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodGet, types.PathPolicy, nil, headers, &settings); err != nil {
			t.Fatal(err)
		}
		return settings.ApprovalMode
	}

	t.Run("manual routes nothing before an admin call", func(t *testing.T) {
		ctx, base, client := startPolicyRelay(t, t.TempDir(), "--approval-mode", "manual")
		leaseIdentity, err := identity.Generate("initial-manual")
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

		// A pending lease has registered, so the admin can see and approve it.
		pending := waitPolicyLease(t, ctx, client, base)
		if pending.IsApproved {
			t.Fatalf("manual relay approved a lease on its own: %+v", pending)
		}
		waitCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		if ready, err := exposure.WaitReady(waitCtx); err == nil {
			t.Fatalf("unapproved lease became ready: %+v", ready)
		}
		tenantClient := relayTenantClient(t, client, base)
		publicURL := "https://" + pending.CanonicalHostname + ":" + base.Port()
		if response, err := tenantClient.Get(publicURL); err == nil {
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if string(body) == "approved tenant" {
				t.Fatal("an unapproved lease received a visitor request")
			}
		}

		setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: leaseIdentity.Key(), IsApproved: ptr(true)})
		readyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if _, err := exposure.WaitReady(readyCtx); err != nil {
			t.Fatalf("approved lease never became ready: %v", err)
		}
		response, err := tenantClient.Get(publicURL)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if body, _ := io.ReadAll(response.Body); string(body) != "approved tenant" {
			t.Fatalf("approved lease answered %d %q", response.StatusCode, body)
		}
	})

	for _, tc := range []struct {
		name, saved, flag, want string
	}{
		{"saved auto wins over a manual flag", `{"approval_mode":"auto"}`, "manual", "auto"},
		{"saved manual wins over an auto flag", `{"approval_mode":"manual"}`, "auto", "manual"},
		{"a saved policy without a mode keeps the flag", `{}`, "manual", "manual"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stateDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(stateDir, types.RelayPolicyFilename), []byte(tc.saved), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, base, client := startPolicyRelay(t, stateDir, "--approval-mode", tc.flag)
			if got := effectiveMode(t, ctx, base, client); got != tc.want {
				t.Fatalf("effective mode = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("invalid value stops startup", func(t *testing.T) {
		bin := buildRelayBinary(t)
		for _, value := range []string{"off", "Manual", ""} {
			// The deadline turns a relay that wrongly starts into a failure.
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, bin, "--identity-path", t.TempDir(), "--approval-mode="+value)
			command.Dir = t.TempDir()
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("relay started with --approval-mode=%q:\n%s", value, output)
			}
			if !bytes.Contains(output, []byte("invalid approval mode")) {
				t.Fatalf("--approval-mode=%q did not name the setting:\n%s", value, output)
			}
		}
	})
}

func TestManualModeRevokesOfflineCache(t *testing.T) {
	stateDir, siteDir := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(siteDir, "index.html"), []byte("cached policy site"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, base, client := startPolicyRelay(t, stateDir,
		"--cache-enabled=true",
		"--cache-max-bytes=1024",
		"--cache-max-ttl=30s",
	)
	leaseIdentity, err := identity.Generate("cached-policy")
	if err != nil {
		t.Fatal(err)
	}
	relayURL := "https://localhost:" + base.Port()
	exposure, err := sdk.Expose(ctx, leaseIdentity, []string{relayURL}, sdk.WithStaticRelayCache(siteDir, 30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	static := utils.NewStaticSiteHandler("/", siteDir, "index.html")
	go func() { _ = sdk.RunHTTP(ctx, exposure, static, "") }()
	readyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ready, err := exposure.WaitReady(readyCtx)
	if err != nil || len(ready) != 1 {
		t.Fatalf("ready: %v, %v", ready, err)
	}
	tenantClient := relayTenantClient(t, client, base)
	publicURL := ready[0].PublicURL
	for {
		response, err := tenantClient.Get(publicURL)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.Header.Get("ETag") != "" {
			if response.StatusCode != http.StatusOK || string(body) != "cached policy site" {
				t.Fatalf("cache response: %d, %q", response.StatusCode, body)
			}
			break
		}
		select {
		case <-readyCtx.Done():
			t.Fatal("cache did not populate")
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err := exposure.Close(); err != nil {
		t.Fatal(err)
	}
	response, err := tenantClient.Get(publicURL)
	if err != nil {
		t.Fatalf("offline cache unavailable before policy change: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "cached policy site" {
		t.Fatalf("offline cache before policy change: %d, %q", response.StatusCode, body)
	}
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	var settings types.PolicySettings
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathPolicy, types.PolicySettings{ApprovalMode: "manual"}, headers, &settings); err != nil {
		t.Fatal(err)
	}
	response, err = tenantClient.Get(publicURL)
	if err != nil {
		return
	}
	defer response.Body.Close()
	body, _ = io.ReadAll(response.Body)
	if response.StatusCode == http.StatusOK && string(body) == "cached policy site" {
		t.Fatal("manual mode left an unapproved offline cache routable")
	}
}

// Runtime UDP toggling must preserve pre-refactor semantics: disabling UDP
// takes effect immediately even while the QUIC backhaul listener is live,
// while enabling UDP without a listener stays a restart-required operation.
func TestUDPRuntimeToggle(t *testing.T) {
	headers := http.Header{"Authorization": {"Bearer admin-test"}}

	t.Run("disable while listener is live", func(t *testing.T) {
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
	})

	t.Run("enable without listener requires restart", func(t *testing.T) {
		ctx, base, client := startPolicyRelay(t, t.TempDir())
		err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathPolicy,
			types.PolicySettings{ApprovalMode: "auto", UDP: types.PolicyPortSettings{Enabled: true}}, headers, new(types.PolicySettings))
		if err == nil {
			t.Fatal("enabling udp without a backhaul listener must be refused")
		}
	})
}
