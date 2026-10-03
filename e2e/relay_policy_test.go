package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Exercise admin persistence and registration through the real relay binary.
// A failed allow-side policy write must leave the existing denial effective.
func TestRelayAccessPolicyTransaction(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "relay-server.exe")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./cmd/relay-server")
	build.Dir = ".."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build relay: %v\n%s", err, output)
	}
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
	frontend := t.TempDir()
	if err := os.WriteFile(filepath.Join(frontend, "index.html"), []byte("portal"), 0o600); err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(harnessPort(t))
	base, err := url.Parse("https://127.0.0.1:" + port)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	command := exec.CommandContext(ctx, bin,
		"--portal-url", "https://localhost:"+port,
		"--identity-path", stateDir,
		"--frontend-dir", frontend,
		"--admin-token", "admin-test",
		"--cache-enabled=false",
	)
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
