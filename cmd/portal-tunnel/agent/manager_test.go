package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gosuda/portal-tunnel/v2/types"
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

// unreachableIssuer is a loopback OIDC issuer nothing listens on: a started
// tunnel's provider check fails at once, and nothing leaves the machine.
const unreachableIssuer = "http://127.0.0.1:1"

func patchTunnel(t *testing.T, m *manager, id, body string) (int, string) {
	t.Helper()
	handler := &controlHandler{manager: m, token: "test-token", authority: "127.0.0.1:4018", localhostAuthority: "localhost:4018"}
	req := httptest.NewRequest(http.MethodPatch, types.PathAgentTunnelsPrefix+id, strings.NewReader(body))
	req.Host = "127.0.0.1:4018"
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func savedTunnel(t *testing.T, path, id string) TunnelConfig {
	t.Helper()
	cfg, err := LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tunnel := range cfg.Tunnels {
		if tunnel.ID == id {
			return tunnel
		}
	}
	t.Fatalf("tunnel %q not saved", id)
	return TunnelConfig{}
}

func TestUpdateTunnelAuthChangesOnlyWhatIsSent(t *testing.T) {
	const oldSecret, newSecret = "old-client-secret", "new-client-secret"
	m, path := testManager(t, oidcTunnel("app", unreachableIssuer, oldSecret))
	startManager(t, m)

	for _, step := range []struct {
		name  string
		body  string
		check func(t *testing.T, saved TunnelConfig, status AgentTunnelStatus)
	}{
		{
			name: "metadata leaves sign-in alone",
			body: `{"metadata":{"description":"hello"}}`,
			check: func(t *testing.T, saved TunnelConfig, status AgentTunnelStatus) {
				if saved.Description != "hello" || saved.Auth != "oidc" || saved.AuthOIDCClientSecret != oldSecret ||
					!slices.Equal(saved.AuthAllowedWallets, []string{"alice@example.com"}) {
					t.Fatalf("saved = %+v", saved)
				}
			},
		},
		{
			name: "allowlist replaces only the allowlist",
			body: `{"auth_allowed_wallets":["Bob@Example.com","sub:42"]}`,
			check: func(t *testing.T, saved TunnelConfig, status AgentTunnelStatus) {
				if !slices.Equal(saved.AuthAllowedWallets, []string{"bob@example.com", "sub:42"}) ||
					!slices.Equal(status.AuthAllowedWallets, saved.AuthAllowedWallets) ||
					saved.AuthOIDCIssuer != unreachableIssuer || saved.AuthOIDCClientID != "client-123" || saved.AuthOIDCClientSecret != oldSecret {
					t.Fatalf("saved = %+v, status allowlist = %v", saved, status.AuthAllowedWallets)
				}
			},
		},
		{
			name: "secret is replaced and never echoed",
			body: `{"auth_oidc_client_secret":"` + newSecret + `"}`,
			check: func(t *testing.T, saved TunnelConfig, status AgentTunnelStatus) {
				if saved.AuthOIDCClientSecret != newSecret || !status.AuthOIDCClientSecretSet {
					t.Fatalf("saved secret = %q, secret set = %v", saved.AuthOIDCClientSecret, status.AuthOIDCClientSecretSet)
				}
				if data, _ := json.Marshal(status); strings.Contains(string(data), newSecret) {
					t.Fatalf("status exposes the client secret: %s", data)
				}
			},
		},
		{
			name: "empty secret clears it",
			body: `{"auth_oidc_client_secret":""}`,
			check: func(t *testing.T, saved TunnelConfig, status AgentTunnelStatus) {
				if saved.AuthOIDCClientSecret != "" || status.AuthOIDCClientSecretSet || saved.Auth != "oidc" {
					t.Fatalf("saved = %+v, secret set = %v", saved, status.AuthOIDCClientSecretSet)
				}
			},
		},
	} {
		t.Run(step.name, func(t *testing.T) {
			code, body := patchTunnel(t, m, "app", step.body)
			if code != http.StatusAccepted {
				t.Fatalf("status = %d, body = %s", code, body)
			}
			if strings.Contains(body, newSecret) {
				t.Fatalf("response echoes the client secret: %s", body)
			}
			step.check(t, savedTunnel(t, path, "app"), tunnelStatus(t, m, "app"))
		})
	}
}

func TestUpdateTunnelEmptyAuthTurnsSignInOff(t *testing.T) {
	cfg := oidcTunnel("app", unreachableIssuer, "client-secret")
	cfg.AuthIdentityHeaders = true
	m, path := testManager(t, cfg)
	startManager(t, m)

	if code, body := patchTunnel(t, m, "app", `{"auth":""}`); code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", code, body)
	}
	saved := savedTunnel(t, path, "app")
	status := tunnelStatus(t, m, "app")
	if !reflect.DeepEqual(saved.applicationAuth(), TunnelConfig{}.applicationAuth()) {
		t.Fatalf("saved auth = %+v", saved.applicationAuth())
	}
	// Every sign-in field is omitted from the status when it is empty.
	if data, _ := json.Marshal(status); strings.Contains(string(data), `"auth`) {
		t.Fatalf("status still reports sign-in: %s", data)
	}
}

func TestUpdateTunnelAuthRejectionChangesNothing(t *testing.T) {
	const secret = "rejected-client-secret"
	wallet := "0x0000000000000000000000000000000000000001"
	signedIn := testTunnel("signedin")
	signedIn.Auth = "siwe"
	signedIn.AuthAllowedWallets = []string{wallet}
	tcp := testTunnel("tcp")
	tcp.TCPEnabled = true
	udp := testTunnel("udp")
	udp.UDPEnabled = true
	m, path := testManager(t, testTunnel("plain"), signedIn, tcp, udp)

	for _, tc := range []struct {
		name, id, body, want string
	}{
		{name: "oidc without allowlist", id: "plain", want: "oidc requires at least one",
			body: `{"auth":"oidc","auth_oidc_issuer":"https://accounts.example.com","auth_oidc_client_id":"client-123","auth_oidc_client_secret":"` + secret + `"}`},
		{name: "oidc without issuer", id: "plain", want: "issuer",
			body: `{"auth":"oidc","auth_allowed_wallets":["alice@example.com"],"auth_oidc_client_id":"client-123","auth_oidc_client_secret":"` + secret + `"}`},
		{name: "oidc settings under siwe", id: "signedin", want: "oidc settings require",
			body: `{"auth_oidc_issuer":"https://accounts.example.com","auth_oidc_client_secret":"` + secret + `"}`},
		{name: "invalid wallet", id: "signedin", want: "address must start with 0x", body: `{"auth_allowed_wallets":["alice"]}`},
		{name: "unknown provider", id: "plain", want: "unsupported application auth provider", body: `{"auth":"magic"}`},
		{name: "allowlist without provider", id: "plain", want: "unsupported application auth provider", body: `{"auth_allowed_wallets":["` + wallet + `"]}`},
		{name: "tcp", id: "tcp", want: "cannot be combined with TCP or UDP", body: `{"auth":"siwe"}`},
		{name: "udp", id: "udp", want: "cannot be combined with TCP or UDP", body: `{"auth":"credential"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fileBefore, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			statusBefore := tunnelStatus(t, m, tc.id)

			code, body := patchTunnel(t, m, tc.id, tc.body)
			if code != http.StatusBadRequest || !strings.Contains(body, tc.want) {
				t.Fatalf("status = %d, body = %s; want 400 mentioning %q", code, body, tc.want)
			}
			if strings.Contains(body, secret) {
				t.Fatalf("error echoes the client secret: %s", body)
			}
			fileAfter, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(fileBefore, fileAfter) {
				t.Fatalf("rejected update changed the config file:\n%s", fileAfter)
			}
			if statusAfter := tunnelStatus(t, m, tc.id); !reflect.DeepEqual(statusBefore, statusAfter) {
				t.Fatalf("rejected update changed the tunnel: %+v -> %+v", statusBefore, statusAfter)
			}
		})
	}
}

func TestUpdateTunnelAuthRebuildsRunningTunnel(t *testing.T) {
	release := make(chan struct{})
	close(release)
	issuer, _ := newTestOIDCIssuer(t, release)
	usable := issuer.URL
	m, _ := testManager(t, oidcTunnel("app", unreachableIssuer, ""))
	startManager(t, m)
	eventually(t, "the unreachable provider to be checked", func() bool {
		return tunnelStatus(t, m, "app").AuthOIDCProviderChecked
	})

	// The gate is built when the tunnel starts: the new issuer only counts once
	// the running tunnel has been rebuilt.
	if code, body := patchTunnel(t, m, "app", `{"auth_oidc_issuer":"`+usable+`"}`); code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", code, body)
	}
	eventually(t, "the rebuilt tunnel to find its provider usable", func() bool {
		status := tunnelStatus(t, m, "app")
		return status.AuthOIDCProviderChecked && status.AuthOIDCProviderError == ""
	})

	// Metadata, even sent next to unchanged sign-in settings, updates the
	// running tunnel in place.
	body := `{"metadata":{"description":"in place"},"auth":"oidc","auth_oidc_issuer":"` + usable + `"}`
	if code, resp := patchTunnel(t, m, "app", body); code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", code, resp)
	}
	if status := tunnelStatus(t, m, "app"); status.State != "running" || !status.AuthOIDCProviderChecked || status.Metadata.Description != "in place" {
		t.Fatalf("tunnel was rebuilt for a metadata change: %+v", status)
	}
}
