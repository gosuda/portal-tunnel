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

func registerBannedLease(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, leaseIdentity types.Identity) types.RegisterResponse {
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

func assertReverseBlocked(t *testing.T, ctx context.Context, client *http.Client, base *url.URL, leaseIdentity types.Identity, capability string) {
	t.Helper()
	var challenge types.RegisterChallengeResponse
	if err := utils.HTTPDoAPIPath(ctx, client, base, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{Identity: leaseIdentity}, nil, &challenge); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+types.PathSDKConnect, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(types.HeaderReverseCapability, capability)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("connect status = %d, want forbidden", response.StatusCode)
	}
}

func updateGlobalPolicyLimits(t *testing.T, ctx context.Context, client *http.Client, base *url.URL) (http.Header, types.PolicyStateResponse) {
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
		len(afterSettings.Leases) != 1 || !afterSettings.Leases[0].IsDenied || afterSettings.Leases[0].BPS != 10000 {
		t.Fatalf("global policy update lost identity decisions or limits: %+v", afterSettings)
	}
	return headers, afterSettings
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
	if len(state.Leases) != 1 || state.Leases[0].IsBanned || !state.Leases[0].IsDenied || state.Leases[0].BPS != 10000 {
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
	registered := registerBannedLease(t, ctx, client, base, leaseIdentity)

	assertReverseBlocked(t, ctx, client, base, leaseIdentity, registered.ReverseEndpoint.Capability)
	postPolicyLeases(t, ctx, client, base, `{"identity_key":"`+leaseIdentity.Key()+`","is_banned":false,"is_denied":true,"bps":10000}`, http.StatusOK)
	assertReverseBlocked(t, ctx, client, base, leaseIdentity, registered.ReverseEndpoint.Capability)
	headers, _ := updateGlobalPolicyLimits(t, ctx, client, base)
	assertReverseBlocked(t, ctx, client, base, leaseIdentity, registered.ReverseEndpoint.Capability)

	breakPolicyPersistence(t, policyPath)
	postPolicyLeases(t, ctx, client, base, `{"identity_key":"`+leaseIdentity.Key()+`","is_denied":false,"bps":20000}`, http.StatusInternalServerError)
	assertReverseBlocked(t, ctx, client, base, leaseIdentity, registered.ReverseEndpoint.Capability)
	assertFailedSavePreserved(t, ctx, client, base, headers)
}
