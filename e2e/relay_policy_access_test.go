package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func writeInitialPolicyDenying(t *testing.T, leaseIdentity types.Identity) (string, string) {
	t.Helper()
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
	return stateDir, policyPath
}

func postPolicyLeases(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, body string, status int) {
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

func assertIdentityBlocked(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, leaseIdentity types.Identity, capability string) {
	t.Helper()
	if _, err := tryRegisterLease(ctx, client, base, types.RegisterChallengeRequest{Identity: leaseIdentity}); !errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseDenied}) {
		t.Fatalf("blocked identity registration: %v", err)
	}
	if err := dialReverseWithCapability(t, ctx, client, base, capability); err == nil {
		t.Fatal("blocked identity retained a usable capability")
	}
}

func updateGlobalPolicyLimits(t *testing.T, ctx context.Context, client *http.Client, base *url.URL) http.Header {
	t.Helper()
	headers := http.Header{"Authorization": {"Bearer admin-test"}}
	var settings types.PolicySettings
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodGet, types.PathPolicy, nil, headers, &settings); err != nil {
		t.Fatal(err)
	}
	settings.UDP.MaxLeases, settings.TCPPort.MaxLeases = 1, 2
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathPolicy, settings, headers, nil); err != nil {
		t.Fatal(err)
	}
	var afterSettings types.PolicyStateResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodGet, types.PathPolicyState, nil, headers, &afterSettings); err != nil {
		t.Fatal(err)
	}
	if afterSettings.Policy.UDP.MaxLeases != 1 || afterSettings.Policy.TCPPort.MaxLeases != 2 ||
		len(afterSettings.Leases) != 0 {
		t.Fatalf("global policy update lost identity decisions or limits: %+v", afterSettings)
	}
	return headers
}

func breakPolicyPersistence(t *testing.T, policyPath string) {
	t.Helper()
	if err := os.Rename(policyPath, policyPath+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(policyPath, 0o700); err != nil {
		t.Fatal(err)
	}
}

func assertFailedSavePreserved(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, headers http.Header) {
	t.Helper()
	var state types.PolicyStateResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodGet, types.PathPolicyState, nil, headers, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Leases) != 0 {
		t.Fatalf("failed save changed committed policy: %+v", state.Leases)
	}
	proposed := state.Policy
	proposed.ApprovalMode = "manual"
	proposed.UDP.MaxLeases = 4
	proposed.TCPPort.MaxLeases = 5
	err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathPolicy, proposed, headers, nil)
	var apiErr *types.APIRequestError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("policy save failure: %v", err)
	}
	var unchanged types.PolicySettings
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodGet, types.PathPolicy, nil, headers, &unchanged); err != nil {
		t.Fatal(err)
	}
	if unchanged != state.Policy {
		t.Fatalf("failed save changed transport policy: got %+v, want %+v", unchanged, state.Policy)
	}
}

func TestRelayAccessPolicyTransaction(t *testing.T) {
	leaseIdentity, err := identity.Generate("policy-transaction")
	if err != nil {
		t.Fatal(err)
	}
	stateDir, policyPath := writeInitialPolicyDenying(t, leaseIdentity)
	ctx, base, client := startPolicyRelay(t, stateDir, "--cache-enabled=false")
	if _, err := tryRegisterLease(ctx, client, base, types.RegisterChallengeRequest{Identity: leaseIdentity}); !errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseDenied}) {
		t.Fatalf("persisted ban did not reject registration: %v", err)
	}
	postPolicyLeases(t, ctx, client, base, `{"identity_key":"`+leaseIdentity.Key()+`","is_banned":false}`, http.StatusOK)
	registered := registerRawLease(t, ctx, client, base, leaseIdentity)
	postPolicyLeases(t, ctx, client, base, `{"identity_key":"`+leaseIdentity.Key()+`","is_banned":true}`, http.StatusOK)

	assertIdentityBlocked(t, ctx, client, base, leaseIdentity, registered.ReverseEndpoint.Capability)
	postPolicyLeases(t, ctx, client, base, `{"identity_key":"`+leaseIdentity.Key()+`","is_banned":false,"is_denied":true,"bps":10000}`, http.StatusOK)
	assertIdentityBlocked(t, ctx, client, base, leaseIdentity, registered.ReverseEndpoint.Capability)
	headers := updateGlobalPolicyLimits(t, ctx, client, base)
	assertIdentityBlocked(t, ctx, client, base, leaseIdentity, registered.ReverseEndpoint.Capability)

	breakPolicyPersistence(t, policyPath)
	postPolicyLeases(t, ctx, client, base, `{"identity_key":"`+leaseIdentity.Key()+`","is_denied":false,"bps":20000}`, http.StatusInternalServerError)
	assertIdentityBlocked(t, ctx, client, base, leaseIdentity, registered.ReverseEndpoint.Capability)
	assertFailedSavePreserved(t, ctx, client, base, headers)
	if err := os.Remove(policyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(policyPath+".saved", policyPath); err != nil {
		t.Fatal(err)
	}
	postPolicyLeases(t, ctx, client, base, `{"identity_key":"`+leaseIdentity.Key()+`","is_denied":false}`, http.StatusOK)
	registerRawLease(t, ctx, client, base, leaseIdentity)
	var restored types.PolicyStateResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodGet, types.PathPolicyState, nil, headers, &restored); err != nil {
		t.Fatal(err)
	}
	if len(restored.Leases) != 1 || restored.Leases[0].BPS != 10000 || restored.Leases[0].IsBanned || restored.Leases[0].IsDenied {
		t.Fatalf("identity policy was lost while no lease existed: %+v", restored.Leases)
	}
}
