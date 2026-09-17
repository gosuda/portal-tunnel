package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// TestExposureReRegistersAfterAuthorityRotation verifies that a relay restart
// that rotates the lease signing authority while keeping the TLS relay identity
// causes a previously valid access token to be rejected as "unauthorized" once
// the relay is back up.  The test registers a short-lived token before the
// restart, restarts the relay with a fresh identity file under the same StateDir
// (so TLS material on disk is untouched), immediately POSTs that token to
// /sdk/renew, and asserts the HTTP 403 "unauthorized" response.  The recovery
// half then confirms the exposure re-registers automatically (issue #471).
//
// The key distinction: after a same-authority restart the relay still holds the
// original identity, so a token's signature verifies but the in-memory lease
// record is gone → /sdk/renew returns HTTP 404 "lease_not_found"
// (recordForVerifiedLease in lease.go reports the missing record).
// After an authority rotation the signature itself fails to verify against the
// new public key → /sdk/renew returns HTTP 403 "unauthorized"
// (VerifyLeaseAccessToken in lease.go).  The same-authority case is covered
// in restart_recovery_test.go.
func TestExposureReRegistersAfterAuthorityRotation(t *testing.T) {
	h := newHarness(t)
	publicURL := h.waitForPublicURL()
	if got := h.get(publicURL); got != marker {
		t.Fatalf("tenant response before rotation = %q, want %q", got, marker)
	}

	// Obtain a valid access token before the restart using a temporary client
	// identity.  The token is signed by the relay's current (pre-restart) lease
	// authority; which client identity was used is irrelevant — any token signed
	// by the old authority must be rejected after the rotation.
	preRestartToken, err := registerShortLivedToken(h.apiPort)
	if err != nil {
		t.Fatalf("register pre-restart token: %v", err)
	}

	// Shut down the relay.  The exposure stays alive, still holding its reverse
	// sessions and the pinned public URL.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.server.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown relay: %v", err)
	}
	if err := h.server.Wait(); err != nil {
		t.Fatalf("wait for relay shutdown: %v", err)
	}

	// Rotate the lease signing authority by replacing the relay's identity.json
	// file with a freshly generated one under the same StateDir.  The file lives
	// at <StateDir>/identity.json (types.RelayIdentityFilename) and is loaded
	// by identity.LoadOrCreateRelayIdentity at server startup; the lease
	// authority is derived from the identity's private key via
	// identity.NewLocalAuthority in server.go.  The ACME TLS material
	// (fullchain.pem, privkey.pem under StateDir) is untouched, so the
	// restarted relay keeps its existing certificate and the exposure's pinned
	// public URL continues to resolve to the same SNI listener.
	identityPath := filepath.Join(h.stateDir, types.RelayIdentityFilename)
	rotatedIdentity, err := identity.LoadOrCreateRelayIdentity(
		filepath.Join(t.TempDir(), types.RelayIdentityFilename),
		"rotated-"+h.sniAddr,
	)
	if err != nil {
		t.Fatalf("create rotated identity: %v", err)
	}
	rotatedBytes, err := identity.Marshal(rotatedIdentity.Identity)
	if err != nil {
		t.Fatalf("marshal rotated identity: %v", err)
	}
	if err := os.WriteFile(identityPath, rotatedBytes, 0o600); err != nil {
		t.Fatalf("replace relay identity file: %v", err)
	}

	// Restart the relay with the same ServerConfig as the original.
	restarted, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     "https://127.0.0.1:" + strconv.Itoa(h.sniPort),
		StateDir:      h.stateDir,
		APIListenAddr: "127.0.0.1:" + strconv.Itoa(h.apiPort),
		SNIListenAddr: "127.0.0.1:" + strconv.Itoa(h.sniPort),
		SNIPort:       h.sniPort,
	})
	if err != nil {
		t.Fatalf("create restarted relay: %v", err)
	}
	serverCtx, serverCancel := context.WithCancel(context.Background())
	t.Cleanup(serverCancel)
	if err := restarted.Start(serverCtx, nil); err != nil {
		t.Fatalf("start restarted relay: %v", err)
	}
	h.server = restarted

	// The pre-restart token was signed by the previous relay identity's private
	// key.  The restarted relay holds the rotated identity, whose public key does
	// not match the token's signature, so VerifyLeaseAccessToken in lease.go
	// returns an error and the /sdk/renew handler writes HTTP 403 "unauthorized".
	// By contrast, a same-authority restart (same identity file, fresh registry)
	// yields HTTP 404 "lease_not_found" because the signature verifies but the
	// in-memory lease record no longer exists (recordForVerifiedLease).
	assertUnauthorizedForOldToken(t, h.apiPort, preRestartToken)

	// The exposure must recover without being recreated: the SDK detects the
	// 403/401 from the relay, treats it as a lost lease, performs a fresh
	// registration with the new authority, establishes reverse sessions, and
	// tenant traffic routes again.
	deadline := time.Now().Add(45 * time.Second)
	for {
		if got, ok := h.tryGet(publicURL); ok && got == marker {
			return
		}
		if !time.Now().Before(deadline) {
			break
		}
		<-time.After(250 * time.Millisecond)
	}
	t.Fatal("exposure did not route again after authority rotation")
}

// registerShortLivedToken performs a complete register challenge + sign +
// register round trip against the relay's API listener and returns the
// resulting access token. The token is signed by the relay's current
// (pre-restart) lease authority. TLS verification is skipped: the loopback
// relay serves a self-signed certificate.
func registerShortLivedToken(apiPort int) (string, error) {
	baseURL, err := url.Parse("https://127.0.0.1:" + strconv.Itoa(apiPort))
	if err != nil {
		return "", err
	}
	// No ServerName: the relay binds a connection to the tenant path when SNI
	// differs from the relay identity name, so an IP-literal dial must send no
	// SNI to reach the control-plane register endpoints.
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	// Generate a temporary client identity so we can sign the challenge.
	tmpIdentity, err := identity.Generate("e2e-rotation-token")
	if err != nil {
		return "", err
	}

	// Step 1: request a registration challenge, using the temporary identity.
	var challenge types.RegisterChallengeResponse
	if err := utils.HTTPDoAPIPath(context.Background(), client, baseURL, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{
		Identity: tmpIdentity,
		Metadata: types.LeaseMetadata{},
	}, nil, &challenge); err != nil {
		return "", err
	}

	// Step 2: sign the SIWE challenge message with the temporary identity.
	sig, err := identity.NewLocalAuthority(tmpIdentity).SignEthereumPersonalMessage(challenge.SIWEMessage)
	if err != nil {
		return "", err
	}

	// Step 3: submit the signed register request.
	var resp types.RegisterResponse
	if err := utils.HTTPDoAPIPath(context.Background(), client, baseURL, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{
		ChallengeID:   challenge.ChallengeID,
		SIWEMessage:   challenge.SIWEMessage,
		SIWESignature: sig,
	}, nil, &resp); err != nil {
		return "", err
	}
	return resp.AccessToken, nil
}

// assertUnauthorizedForOldToken POSTs the given access token to /sdk/renew on
// the relay's API listener and asserts the response is HTTP 403 with error
// code "unauthorized". The token was signed by the pre-restart authority;
// the restarted relay holds a different public key, so VerifyLeaseAccessToken
// in lease.go returns an error and the handler writes HTTP 403 via
// errUnauthorized in api_server.go.
func assertUnauthorizedForOldToken(t *testing.T, apiPort int, accessToken string) {
	t.Helper()
	baseURL := "https://127.0.0.1:" + strconv.Itoa(apiPort) + types.PathSDKRenew
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	body, _ := json.Marshal(types.RenewRequest{AccessToken: accessToken, Metadata: types.LeaseMetadata{}})
	resp, err := client.Post(baseURL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /sdk/renew: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("renew with old token status = %d, want 403 (unauthorized); "+
			"the relay may still hold the pre-rotation identity", resp.StatusCode)
	}

	var apiErr struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiErr); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if apiErr.Error.Code != types.APIErrorCodeUnauthorized {
		t.Fatalf("renew with old token error code = %q, want %q", apiErr.Error.Code, types.APIErrorCodeUnauthorized)
	}
}
