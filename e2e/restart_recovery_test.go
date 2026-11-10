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

func TestExposureReRegistersAfterRelayRestart(t *testing.T) {
	h := newHarness(t)
	publicURL := h.waitForPublicURL()
	if got := h.get(publicURL); got != marker {
		t.Fatalf("tenant response before restart = %q, want %q", got, marker)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.server.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown relay: %v", err)
	}
	if err := h.server.Wait(); err != nil {
		t.Fatalf("wait for relay shutdown: %v", err)
	}

	restarted, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     "https://127.0.0.1:" + strconv.Itoa(h.sniPort),
		StateDir:      h.stateDir,
		SNIListenAddr: "127.0.0.1:" + strconv.Itoa(h.sniPort),
		SNIPort:       h.sniPort,
	})
	if err != nil {
		t.Fatalf("create restarted relay: %v", err)
	}
	serverCtx, serverCancel := context.WithCancel(context.Background())
	t.Cleanup(serverCancel)
	if err := restarted.Start(serverCtx, relayHandler(restarted, nil)); err != nil {
		t.Fatalf("start restarted relay: %v", err)
	}
	h.server = restarted

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
	t.Fatal("exposure did not route again after relay restart")
}

func TestExposureReRegistersAfterAuthorityRotation(t *testing.T) {
	h := newHarness(t)
	publicURL := h.waitForPublicURL()
	if got := h.get(publicURL); got != marker {
		t.Fatalf("tenant response before rotation = %q, want %q", got, marker)
	}

	preRestartToken, err := registerShortLivedToken(h.sniPort)
	if err != nil {
		t.Fatalf("register pre-restart token: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.server.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown relay: %v", err)
	}
	if err := h.server.Wait(); err != nil {
		t.Fatalf("wait for relay shutdown: %v", err)
	}

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

	restarted, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     "https://127.0.0.1:" + strconv.Itoa(h.sniPort),
		StateDir:      h.stateDir,
		SNIListenAddr: "127.0.0.1:" + strconv.Itoa(h.sniPort),
		SNIPort:       h.sniPort,
	})
	if err != nil {
		t.Fatalf("create restarted relay: %v", err)
	}
	serverCtx, serverCancel := context.WithCancel(context.Background())
	t.Cleanup(serverCancel)
	if err := restarted.Start(serverCtx, relayHandler(restarted, nil)); err != nil {
		t.Fatalf("start restarted relay: %v", err)
	}
	h.server = restarted

	assertUnauthorizedForOldToken(t, h.sniPort, preRestartToken)

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

func registerShortLivedToken(sniPort int) (string, error) {
	baseURL, err := url.Parse("https://127.0.0.1:" + strconv.Itoa(sniPort))
	if err != nil {
		return "", err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	tmpIdentity, err := identity.Generate("e2e-rotation-token")
	if err != nil {
		return "", err
	}

	var challenge types.RegisterChallengeResponse
	if err := utils.HTTPDoAPIPath(context.Background(), client, baseURL, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{
		Identity: tmpIdentity,
		Metadata: types.LeaseMetadata{},
	}, nil, &challenge); err != nil {
		return "", err
	}

	sig, err := identity.NewLocalAuthority(tmpIdentity).SignEthereumPersonalMessage(challenge.SIWEMessage)
	if err != nil {
		return "", err
	}

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

func assertUnauthorizedForOldToken(t *testing.T, sniPort int, accessToken string) {
	t.Helper()
	baseURL := "https://127.0.0.1:" + strconv.Itoa(sniPort) + types.PathSDKRenew
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	body, _ := json.Marshal(types.RenewRequest{AccessToken: accessToken, Metadata: types.LeaseMetadata{}})
	resp, err := client.Post(baseURL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /sdk/renew: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("renew with old token status = %d, want 403 (unauthorized)", resp.StatusCode)
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
