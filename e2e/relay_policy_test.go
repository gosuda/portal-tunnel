package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/sdk/staticsite"
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

// waitForRelayCertificateMaterial polls until the relay has persisted both
// halves of its local certificate material under dir.
func waitForRelayCertificateMaterial(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		persisted := true
		for _, name := range []string{"fullchain.pem", "privatekey.pem"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				persisted = false
				break
			}
		}
		if persisted {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay did not persist certificate material under %s", dir)
		}
		<-time.After(10 * time.Millisecond)
	}
}

// relayControlClient returns an HTTPS client that trusts the relay's local certificate.
func relayControlClient(t *testing.T, stateDir string) *http.Client {
	t.Helper()
	certPEM, err := os.ReadFile(filepath.Join(stateDir, "fullchain.pem"))
	if err != nil {
		t.Fatalf("read relay certificate: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatalf("relay certificate is not a usable PEM chain")
	}
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

// waitRelayReady polls healthz until the serve loop accepts traffic.
func waitRelayReady(t *testing.T, client *http.Client, baseURL string, serveResult <-chan error) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		resp, err := client.Get(baseURL + types.PathHealthz)
		if err == nil {
			resp.Body.Close()
			return
		}
		select {
		case serveErr := <-serveResult:
			t.Fatalf("Serve() exited before readiness: %v", serveErr)
		case <-deadline:
			t.Fatalf("Serve() did not become ready: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
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
	static := staticsite.NewHandler("/", siteDir, "index.html")
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
	if runtime.GOOS == "windows" {
		portalBin += ".exe"
	}
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
