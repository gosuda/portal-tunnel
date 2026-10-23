package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// unreachableRelay keeps started tunnels off the network: they come up with
// one relay that never connects.
const unreachableRelay = "https://127.0.0.1:1"

func testTunnel(id string) TunnelConfig {
	discovery := false
	return TunnelConfig{ID: id, TargetAddr: "127.0.0.1:3000", RelayURLs: []string{unreachableRelay}, Discovery: &discovery}
}

// testManager builds a manager from a config file written and loaded the way
// the agent does, so it starts from normalized settings.
func testManager(t *testing.T, tunnels ...TunnelConfig) (*manager, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	cfg := Config{Agent: AgentConfig{StateDir: dir}, Tunnels: tunnels}
	if err := writeConfigDocument(path, 0o600, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return newManager(loaded, DefaultControlAddr), path
}

func startManager(t *testing.T, m *manager) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	t.Cleanup(func() {
		cancel()
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		_ = m.Stop(stopCtx)
	})
}

func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(10 * time.Second)
	for !condition() {
		select {
		case <-ticker.C:
		case <-timeout:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func tunnelStatus(t *testing.T, m *manager, id string) AgentTunnelStatus {
	t.Helper()
	for _, status := range m.Snapshot().Tunnels {
		if status.ID == id {
			return status
		}
	}
	t.Fatalf("tunnel %q not in status", id)
	return AgentTunnelStatus{}
}

// newTestOIDCIssuer serves a minimal OIDC provider. Requests wait for release
// to be closed, so a test decides when the provider answers, and the returned
// channel is closed when the first request arrives.
func newTestOIDCIssuer(t *testing.T, release <-chan struct{}) (*httptest.Server, <-chan struct{}) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "ES256", Use: "sig"}}}
	requested := make(chan struct{})
	var once sync.Once
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(requested) })
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 issuer.URL,
				"authorization_endpoint": issuer.URL + "/authorize",
				"token_endpoint":         issuer.URL + "/token",
				"jwks_uri":               issuer.URL + "/jwks",
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(issuer.Close)
	return issuer, requested
}

func oidcTunnel(id, issuer, secret string) TunnelConfig {
	cfg := testTunnel(id)
	cfg.Auth = "oidc"
	cfg.AuthAllowedWallets = []string{"alice@example.com"}
	cfg.AuthOIDCIssuer = issuer
	cfg.AuthOIDCClientID = "client-123"
	cfg.AuthOIDCClientSecret = secret
	return cfg
}

func TestTunnelStatusAuthSettings(t *testing.T) {
	const secret = "s3cret-client-secret"
	credential := testTunnel("credential")
	credential.Auth = "credential"
	m, _ := testManager(t,
		oidcTunnel("oidc", "https://accounts.example.com", secret),
		credential,
		testTunnel("plain"),
	)
	data, err := json.Marshal(m.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("status exposes the client secret: %s", data)
	}

	var wire struct {
		Tunnels []map[string]any `json:"tunnels"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]map[string]any, len(wire.Tunnels))
	for _, tunnel := range wire.Tunnels {
		byID[tunnel["id"].(string)] = tunnel
	}
	if got := byID["oidc"]["auth_allowed_wallets"]; !slices.Equal(toStrings(got), []string{"alice@example.com"}) {
		t.Fatalf("oidc auth_allowed_wallets = %v", got)
	}
	if byID["oidc"]["auth_oidc_client_secret_set"] != true {
		t.Fatalf("oidc auth_oidc_client_secret_set = %v, want true", byID["oidc"]["auth_oidc_client_secret_set"])
	}
	for _, key := range []string{"auth_allowed_wallets", "auth_oidc_client_secret_set", "auth_oidc_provider_checked", "auth_oidc_provider_error"} {
		for _, id := range []string{"credential", "plain"} {
			if _, ok := byID[id][key]; ok {
				t.Fatalf("tunnel %q reports %s without it being configured", id, key)
			}
		}
	}
	// A tunnel that is not running has not checked its provider.
	if _, ok := byID["oidc"]["auth_oidc_provider_checked"]; ok {
		t.Fatal("stopped oidc tunnel reports a provider check")
	}
}

func toStrings(value any) []string {
	items, _ := value.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.(string))
	}
	return out
}

func TestTunnelStatusOIDCProviderHealth(t *testing.T) {
	release := make(chan struct{})
	slow, requested := newTestOIDCIssuer(t, release)
	m, _ := testManager(t,
		oidcTunnel("pending", slow.URL, ""),
		oidcTunnel("down", "http://127.0.0.1:1", ""),
		func() TunnelConfig { cfg := testTunnel("siwe"); cfg.Auth = "siwe"; return cfg }(),
	)
	startManager(t, m)

	eventually(t, "the unreachable provider to be checked", func() bool {
		return tunnelStatus(t, m, "down").AuthOIDCProviderChecked
	})
	if got := tunnelStatus(t, m, "down"); got.AuthOIDCProviderError == "" {
		t.Fatal("unreachable provider reports no error")
	}

	eventually(t, "the tunnels to run and the slow provider to be asked", func() bool {
		select {
		case <-requested:
		default:
			return false
		}
		return tunnelStatus(t, m, "pending").State == "running" && tunnelStatus(t, m, "siwe").State == "running"
	})
	if got := tunnelStatus(t, m, "pending"); got.AuthOIDCProviderChecked || got.AuthOIDCProviderError != "" {
		t.Fatalf("provider that has not answered reports %+v", got)
	}
	if got := tunnelStatus(t, m, "siwe"); got.AuthOIDCProviderChecked || got.AuthOIDCProviderError != "" {
		t.Fatalf("siwe tunnel reports an oidc provider check: %+v", got)
	}

	close(release)
	eventually(t, "the usable provider to be checked", func() bool {
		return tunnelStatus(t, m, "pending").AuthOIDCProviderChecked
	})
	if got := tunnelStatus(t, m, "pending"); got.AuthOIDCProviderError != "" {
		t.Fatalf("usable provider reports error %q", got.AuthOIDCProviderError)
	}
}
