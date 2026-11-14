package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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
	return registered
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

func TestReverseCapabilitySurvivesApproval(t *testing.T) {
	ctx, base, client := startPolicyRelay(t, t.TempDir(), "--approval-mode", "manual")
	leaseIdentity, err := identity.Generate("approval-capability")
	if err != nil {
		t.Fatal(err)
	}
	registered := registerRawLease(t, ctx, client, base, leaseIdentity)
	key := leaseIdentity.Key()

	if err := dialReverseWithCapability(t, ctx, client, base, registered.ReverseEndpoint.Capability); !errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseRejected}) {
		t.Fatalf("waiting connect = %v", err)
	}
	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsApproved: ptr(true)})
	if err := dialReverseWithCapability(t, ctx, client, base, registered.ReverseEndpoint.Capability); err != nil {
		t.Fatalf("approved connect = %v", err)
	}
	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsDenied: ptr(true)})
	if err := dialReverseWithCapability(t, ctx, client, base, registered.ReverseEndpoint.Capability); !errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseDenied}) {
		t.Fatalf("denied connect = %v", err)
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
	if lease := waitPolicyLease(t, ctx, client, base); lease.Ready != 0 {
		t.Fatalf("a revoked lease kept %d idle streams", lease.Ready)
	}

	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsApproved: ptr(true)})
	waitRelayReadyURL(t, exposure)

	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsDenied: ptr(true)})
	waitRelayApproval(t, exposure, sdk.RelayApprovalRefused)

	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsDenied: ptr(false), IsApproved: ptr(true)})
	waitRelayReadyURL(t, exposure)

	setLeasePolicy(t, ctx, client, base, types.LeasePolicyUpdate{IdentityKey: key, IsBanned: ptr(true)})
	waitRelayApproval(t, exposure, sdk.RelayApprovalRefused)
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

func exposeUnapprovedManualLease(t *testing.T, ctx context.Context, base *url.URL, client *http.Client) (*sdk.Exposure, types.Identity, types.PolicyLease) {
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
	pending := waitPolicyLease(t, ctx, client, base)
	if pending.IsApproved {
		t.Fatalf("manual relay approved a lease on its own: %+v", pending)
	}
	return exposure, leaseIdentity, pending
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
	exposure, leaseIdentity, pending := exposeUnapprovedManualLease(t, ctx, base, client)
	tenantClient := relayTenantClient(t, client, base)
	publicURL := "https://" + pending.CanonicalHostname + ":" + base.Port()
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
