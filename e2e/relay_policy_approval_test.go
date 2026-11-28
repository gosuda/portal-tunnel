package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/sdk/staticsite"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func registerRawLease(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, leaseIdentity types.Identity) types.RegisterResponse {
	t.Helper()
	registered, err := tryRegisterLease(ctx, client, base, types.RegisterChallengeRequest{Identity: leaseIdentity})
	if err != nil {
		t.Fatal(err)
	}
	return registered
}

func tryRegisterLease(ctx context.Context, client *http.Client, base *url.URL, req types.RegisterChallengeRequest) (types.RegisterResponse, error) {
	var registered types.RegisterResponse
	var challenge types.RegisterChallengeResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegisterChallenge, req, nil, &challenge); err != nil {
		return registered, err
	}
	signature, err := identity.NewLocalAuthority(req.Identity).SignEthereumPersonalMessage(challenge.SIWEMessage)
	if err != nil {
		return registered, err
	}
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{ChallengeID: challenge.ChallengeID, SIWEMessage: challenge.SIWEMessage, SIWESignature: signature}, nil, &registered); err != nil {
		return registered, err
	}
	return registered, nil
}

func dialReverseWithCapability(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, capability string) error {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+types.PathSDKConnect, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(types.HeaderReverseCapability, capability)
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

func TestManualReleaseInvalidatesLease(t *testing.T) {
	ctx, base, client := startPolicyRelay(t, t.TempDir(), "--approval-mode", "manual")
	id := generatePolicyIdentities(t, "approval-capability")[0]
	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: id.Key(), IsApproved: ptr(true)})
	registered := registerRawLease(t, ctx, client, base, id)
	if err := dialReverseWithCapability(t, ctx, client, base, registered.ReverseEndpoint.Capability); err != nil {
		t.Fatal(err)
	}
	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: id.Key(), IsApproved: ptr(false)})
	if err := dialReverseWithCapability(t, ctx, client, base, registered.ReverseEndpoint.Capability); err == nil {
		t.Fatal("revoked capability accepted")
	}
	err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRenew, types.RenewRequest{AccessToken: registered.AccessToken}, nil, new(types.RenewResponse))
	if !errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseNotFound}) {
		t.Fatalf("renew after eviction: %v", err)
	}
}

func TestAutoRefusesDeniedPublishersBeforeAllocatingResources(t *testing.T) {
	port := strconv.Itoa(harnessPort(t, "127.0.0.1"))
	ctx, base, client := startPolicyRelay(t, t.TempDir(), "--approval-mode=auto", "--tcp-enabled=true", "--min-port="+port, "--max-port="+port)
	ids := generatePolicyIdentities(t, "admission", "admission", "admission")
	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: ids[0].Key(), IsDenied: ptr(true)})
	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: ids[1].Key(), IsBanned: ptr(true)})
	for _, id := range ids[:2] {
		registered, err := tryRegisterLease(ctx, client, base, types.RegisterChallengeRequest{Identity: id, TCPEnabled: true})
		if !errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseDenied}) {
			t.Fatalf("denied publisher registration: %+v, %v", registered, err)
		}
		if registered.AccessToken != "" || registered.TCPAddr != "" {
			t.Fatal("denied publisher received a token or endpoint")
		}
	}
	var state types.PolicyStateResponse
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodGet, types.PathPolicyState, nil, headers, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Leases) != 0 || len(state.Pending) != 0 {
		t.Fatalf("denied publishers retained leases or approval requests: %+v", state)
	}
	registered, err := tryRegisterLease(ctx, client, base, types.RegisterChallengeRequest{Identity: ids[2], TCPEnabled: true})
	if err != nil || registered.Hostname != "admission.localhost" || registered.TCPAddr == "" {
		t.Fatalf("denied publishers consumed the alias or only port: %+v, %v", registered, err)
	}
}

func TestAutoBlockingReleasesRegisteredResources(t *testing.T) {
	for _, action := range []string{"ban", "deny"} {
		t.Run(action, func(t *testing.T) {
			port := strconv.Itoa(harnessPort(t, "127.0.0.1"))
			ctx, base, client := startPolicyRelay(t, t.TempDir(), "--approval-mode=auto", "--tcp-enabled=true", "--min-port="+port, "--max-port="+port)
			ids := generatePolicyIdentities(t, "reclaimed", "reclaimed")
			registered, err := tryRegisterLease(ctx, client, base, types.RegisterChallengeRequest{Identity: ids[0], TCPEnabled: true})
			if err != nil {
				t.Fatal(err)
			}
			setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: ids[0].Key(), IsApproved: ptr(true)})
			setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: ids[0].Key(), IsApproved: ptr(false)})
			if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRenew, types.RenewRequest{AccessToken: registered.AccessToken}, nil, new(types.RenewResponse)); err != nil {
				t.Fatal("revoking approval in auto mode removed a routable lease:", err)
			}
			update := types.LeasePolicyUpdate{IdentityKey: ids[0].Key()}
			if action == "ban" {
				update.IsBanned = ptr(true)
			} else {
				update.IsDenied = ptr(true)
			}
			setLeasePolicy(t, ctx, client, base, update)
			if err := dialReverseWithCapability(t, ctx, client, base, registered.ReverseEndpoint.Capability); err == nil {
				t.Fatal("blocked publisher retained a usable capability")
			}
			err = utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRenew, types.RenewRequest{AccessToken: registered.AccessToken}, nil, new(types.RenewResponse))
			if !errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseNotFound}) {
				t.Fatalf("renew after blocking: %v", err)
			}
			replacement, err := tryRegisterLease(ctx, client, base, types.RegisterChallengeRequest{Identity: ids[1], TCPEnabled: true})
			if err != nil || replacement.Hostname != "reclaimed.localhost" || replacement.TCPAddr == "" || replacement.TCPAddr != registered.TCPAddr {
				t.Fatalf("blocked publisher retained alias or port: old=%+v new=%+v err=%v", registered, replacement, err)
			}
		})
	}
}

func waitRelayStatus(t *testing.T, exposure *sdk.Exposure, name string, match func(sdk.RelayStatus) bool) sdk.RelayStatus {
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

func waitRelayApproval(t *testing.T, exposure *sdk.Exposure, want sdk.RelayApproval) {
	t.Helper()
	status := waitRelayStatus(t, exposure, string(want), func(status sdk.RelayStatus) bool { return status.Approval == want })
	if status.State != sdk.RelayConnecting || status.PublicURL != "" || status.Active() {
		t.Fatalf("%s status = %+v, want no usable endpoint", want, status)
	}
}

func waitRelayReadyURL(t *testing.T, exposure *sdk.Exposure) string {
	t.Helper()
	status := waitRelayStatus(t, exposure, "ready", func(status sdk.RelayStatus) bool { return status.State == sdk.RelayReady })
	if status.Approval != "" {
		t.Fatalf("ready status = %+v", status)
	}
	return status.PublicURL
}

func startManualApprovalExposure(t *testing.T, ctx context.Context, base *url.URL, client *http.Client) (*sdk.Exposure, string) {
	t.Helper()
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
	waitRelayApproval(t, exposure, sdk.RelayApprovalPending)
	return exposure, leaseIdentity.Key()
}

func assertApprovedTenantServed(t *testing.T, tenantClient *http.Client, publicURL string) {
	t.Helper()
	response, err := tenantClient.Get(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "approved tenant" {
		t.Fatalf("approved lease answered %d %q", response.StatusCode, body)
	}
}

func TestManualRelayApprovalLifecycle(t *testing.T) {
	ctx, base, client := startPolicyRelay(t, t.TempDir(), "--approval-mode", "manual")
	exposure, key := startManualApprovalExposure(t, ctx, base, client)

	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsApproved: ptr(true)})
	publicURL := waitRelayReadyURL(t, exposure)
	tenantClient := relayTenantClient(t, client, base)
	assertApprovedTenantServed(t, tenantClient, publicURL)

	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsApproved: ptr(false)})
	waitRelayApproval(t, exposure, sdk.RelayApprovalPending)
	waitPendingApproval(t, ctx, client, base)

	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsApproved: ptr(true)})
	waitRelayReadyURL(t, exposure)

	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsDenied: ptr(true)})
	status := waitRelayStatus(t, exposure, "terminal denial", func(s sdk.RelayStatus) bool { return s.State == sdk.RelayFailed })
	if !errors.Is(status.Err, &types.APIRequestError{Code: types.APIErrorCodeLeaseDenied}) || status.Approval != sdk.RelayApprovalRefused {
		t.Fatalf("denied publisher: %+v", status)
	}
}

func populatePolicyCache(ctx context.Context, t *testing.T, tenantClient *http.Client, publicURL string) {
	t.Helper()
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
		case <-ctx.Done():
			t.Fatal("cache did not populate")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func assertOfflineCacheServed(t *testing.T, exposure *sdk.Exposure, tenantClient *http.Client, publicURL string) {
	t.Helper()
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
}

func switchPolicyToManual(t *testing.T, ctx context.Context, client *http.Client, base *url.URL) {
	t.Helper()
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	var settings types.PolicySettings
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathPolicy, types.PolicySettings{ApprovalMode: "manual"}, headers, &settings); err != nil {
		t.Fatal(err)
	}
}

func assertOfflineCacheRevoked(t *testing.T, tenantClient *http.Client, publicURL string) {
	t.Helper()
	response, err := tenantClient.Get(publicURL)
	if err != nil {
		return
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode == http.StatusOK && string(body) == "cached policy site" {
		t.Fatal("manual mode left an unapproved offline cache routable")
	}
}

func exposeCachedPolicySite(t *testing.T, ctx context.Context, relayPort, siteDir string, leaseIdentity types.Identity) *sdk.Exposure {
	t.Helper()
	exposure, err := sdk.Expose(ctx, leaseIdentity, []string{"https://localhost:" + relayPort}, sdk.WithStaticRelayCache(siteDir, 30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	static := staticsite.NewHandler("/", siteDir, "index.html")
	go func() { _ = sdk.RunHTTP(ctx, exposure, static, "") }()
	return exposure
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
	exposure := exposeCachedPolicySite(t, ctx, base.Port(), siteDir, leaseIdentity)
	readyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ready, err := exposure.WaitReady(readyCtx)
	if err != nil || len(ready) != 1 {
		t.Fatalf("ready: %v, %v", ready, err)
	}
	tenantClient := relayTenantClient(t, client, base)
	publicURL := ready[0].PublicURL
	populatePolicyCache(readyCtx, t, tenantClient, publicURL)
	assertOfflineCacheServed(t, exposure, tenantClient, publicURL)
	switchPolicyToManual(t, ctx, client, base)
	assertOfflineCacheRevoked(t, tenantClient, publicURL)
}

func readEffectiveApprovalMode(t *testing.T, ctx context.Context, base *url.URL, client *http.Client) string {
	t.Helper()
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	var settings types.PolicySettings
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodGet, types.PathPolicy, nil, headers, &settings); err != nil {
		t.Fatal(err)
	}
	return settings.ApprovalMode
}

func exposeUnapprovedManualLease(t *testing.T, ctx context.Context, base *url.URL, client *http.Client) (*sdk.Exposure, types.Identity) {
	t.Helper()
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
	waitPendingApproval(t, ctx, client, base)
	return exposure, leaseIdentity
}

func assertUnapprovedLeaseBlocked(t *testing.T, ctx context.Context, exposure *sdk.Exposure, tenantClient *http.Client, publicURL string) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if ready, err := exposure.WaitReady(waitCtx); err == nil {
		t.Fatalf("unapproved lease became ready: %+v", ready)
	}
	if response, err := tenantClient.Get(publicURL); err == nil {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if string(body) == "approved tenant" {
			t.Fatal("an unapproved lease received a visitor request")
		}
	}
}

func approveManualLease(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, exposure *sdk.Exposure, leaseIdentity types.Identity) {
	t.Helper()
	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: leaseIdentity.Key(), IsApproved: ptr(true)})
	readyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, err := exposure.WaitReady(readyCtx); err != nil {
		t.Fatalf("approved lease never became ready: %v", err)
	}
}

func checkManualLeaseNeedsApproval(t *testing.T) {
	t.Helper()
	ctx, base, client := startPolicyRelay(t, t.TempDir(), "--approval-mode", "manual")
	exposure, leaseIdentity := exposeUnapprovedManualLease(t, ctx, base, client)
	tenantClient := relayTenantClient(t, client, base)
	publicURL := "https://" + net.JoinHostPort(leaseIdentity.Name+".localhost", base.Port())
	assertUnapprovedLeaseBlocked(t, ctx, exposure, tenantClient, publicURL)
	approveManualLease(t, ctx, client, base, exposure, leaseIdentity)
	assertApprovedTenantServed(t, tenantClient, publicURL)
}

func checkSavedApprovalMode(t *testing.T, saved, flag, want string) {
	t.Helper()
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, types.RelayPolicyFilename), []byte(saved), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, base, client := startPolicyRelay(t, stateDir, "--approval-mode", flag)
	if got := readEffectiveApprovalMode(t, ctx, base, client); got != want {
		t.Fatalf("effective mode = %q, want %q", got, want)
	}
}

func assertInvalidApprovalModeRejected(t *testing.T, bin, value string) {
	t.Helper()
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

func TestRelayInitialApprovalMode(t *testing.T) {
	t.Run("manual routes nothing before an admin call", func(t *testing.T) {
		checkManualLeaseNeedsApproval(t)
	})

	for _, tc := range []struct {
		name, saved, flag, want string
	}{
		{"saved auto wins over a manual flag", `{"approval_mode":"auto"}`, "manual", "auto"},
		{"saved manual wins over an auto flag", `{"approval_mode":"manual"}`, "auto", "manual"},
		{"a saved policy without a mode keeps the flag", `{}`, "manual", "manual"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			checkSavedApprovalMode(t, tc.saved, tc.flag, tc.want)
		})
	}

	t.Run("invalid value stops startup", func(t *testing.T) {
		bin := buildRelayBinary(t)
		for _, value := range []string{"off", "Manual", ""} {
			assertInvalidApprovalModeRejected(t, bin, value)
		}
	})
}

func TestManualProtocol10Compatibility(t *testing.T) {
	oldCLI, oldRelay := os.Getenv("PORTAL_V10_BASE_CLI"), os.Getenv("PORTAL_V10_BASE_RELAY")
	if oldCLI == "" || oldRelay == "" {
		t.Skip("set PORTAL_V10_BASE_CLI and PORTAL_V10_BASE_RELAY to baseline binaries")
	}
	for _, tc := range []struct {
		name, cli, relay string
		legacyRelay      bool
	}{
		{"previous client", oldCLI, buildRelayBinary(t), false},
		{"previous relay", buildPortalTunnelBinary(t), oldRelay, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, base, client := startPolicyRelayBinary(t, t.TempDir(), tc.relay, "--approval-mode=manual")
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "approved tenant") }))
			defer target.Close()
			relayURL := "https://localhost:" + base.Port()
			records := launchJSONExpose(t, tc.cli, relayURL, filepath.Join(t.TempDir(), "identity.json"), target.Listener.Addr().String())
			var key string
			if tc.legacyRelay {
				assertApprovalWaiting(t, records)
				var state types.PolicyStateResponse
				err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodGet, types.PathPolicyState, nil, http.Header{"Authorization": {"Bearer admin-test"}}, &state)
				if err != nil || len(state.Leases) != 1 {
					t.Fatalf("legacy pending lease: %v, %v", state.Leases, err)
				}
				key = state.Leases[0].IdentityKey
			} else {
				key = waitPendingApproval(t, ctx, client, base).IdentityKey
			}
			setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsApproved: ptr(true)})
			publicURL := assertExposeReady(t, records, relayURL)
			assertApprovedTenantServed(t, relayTenantClient(t, client, base), publicURL)
		})
	}
}

func TestManualModeSwitchReleasesOnlyUnapprovedResources(t *testing.T) {
	port := strconv.Itoa(harnessPort(t, "127.0.0.1"))
	ctx, base, client := startPolicyRelay(t, t.TempDir(), "--tcp-enabled=true", "--min-port="+port, "--max-port="+port)
	ids := generatePolicyIdentities(t, "keeper", "same-alias", "same-alias")
	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: ids[0].Key(), IsApproved: ptr(true)})
	keeper := registerRawLease(t, ctx, client, base, ids[0])
	req := types.RegisterChallengeRequest{Identity: ids[1], TCPEnabled: true}
	evicted, err := tryRegisterLease(ctx, client, base, req)
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	settings := types.PolicySettings{ApprovalMode: "manual", TCPPort: types.PolicyPortSettings{Enabled: true}}
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathPolicy, settings, headers, nil); err != nil {
		t.Fatal(err)
	}
	if err := dialReverseWithCapability(t, ctx, client, base, keeper.ReverseEndpoint.Capability); err != nil {
		t.Fatalf("pre-approved lease lost: %v", err)
	}
	if err := dialReverseWithCapability(t, ctx, client, base, evicted.ReverseEndpoint.Capability); err == nil {
		t.Fatal("auto-approved lease survived switch")
	}
	attempts := make(chan error, 4)
	for range cap(attempts) {
		go func() { _, err := tryRegisterLease(ctx, client, base, req); attempts <- err }()
	}
	for range cap(attempts) {
		if err := <-attempts; !errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseRejected}) {
			t.Fatalf("registration: %v", err)
		}
	}
	var state types.PolicyStateResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodGet, types.PathPolicyState, nil, headers, &state); err != nil || len(state.Pending) != 1 || len(state.Leases) != 1 {
		t.Fatalf("duplicate requests affected capacity: %v, %v", state, err)
	}
	settings.ApprovalMode = "auto"
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathPolicy, settings, headers, nil); err != nil {
		t.Fatal(err)
	}
	req.Identity = ids[2]
	replacement, err := tryRegisterLease(ctx, client, base, req)
	if err != nil || replacement.TCPAddr != evicted.TCPAddr || replacement.Hostname != evicted.Hostname {
		t.Fatalf("alias/port unavailable to new owner: %+v, %v", replacement, err)
	}
}
