package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// unreachableRelay keeps started tunnels off the network: they come up with
// one relay that never connects.
const unreachableRelay = "https://127.0.0.1:1"

// unreachableIssuer is a loopback OIDC issuer nothing listens on: a started
// tunnel's provider check fails at once, and nothing leaves the machine.
const unreachableIssuer = "http://127.0.0.1:1"

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
	// writeConfigDocument secures an existing file before it rewrites it, and
	// on Windows a file that is not there yet cannot be secured.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
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

// TestRuntimeAuthProviderCheck covers the provider states; the status reports
// the check for a running OIDC tunnel and for no other tunnel.
func TestTunnelStatusOIDCProviderCheck(t *testing.T) {
	siwe := testTunnel("siwe")
	siwe.Auth = "siwe"
	m, _ := testManager(t, oidcTunnel("oidc", unreachableIssuer, ""), siwe)
	startManager(t, m)

	eventually(t, "the oidc provider to be checked and the siwe tunnel to run", func() bool {
		return tunnelStatus(t, m, "oidc").AuthOIDCProviderChecked && tunnelStatus(t, m, "siwe").State == "running"
	})
	if got := tunnelStatus(t, m, "oidc"); got.AuthOIDCProviderError == "" {
		t.Fatal("unreachable provider reports no error")
	}
	if got := tunnelStatus(t, m, "siwe"); got.AuthOIDCProviderChecked || got.AuthOIDCProviderError != "" {
		t.Fatalf("siwe tunnel reports an oidc provider check: %+v", got)
	}
}

func callControl(t *testing.T, m *manager, method, path, body string) (int, string) {
	t.Helper()
	handler := &controlHandler{manager: m, token: "test-token", authority: "127.0.0.1:4018", localhostAuthority: "localhost:4018"}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
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
			code, body := callControl(t, m, http.MethodPatch, types.PathAgentTunnelsPrefix+"app", step.body)
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

	if code, body := callControl(t, m, http.MethodPatch, types.PathAgentTunnelsPrefix+"app", `{"auth":""}`); code != http.StatusAccepted {
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
		{name: "settings together with sign-in turned off", id: "signedin", want: "leave out the other auth fields",
			body: `{"auth":"","auth_oidc_issuer":"https://accounts.example.com"}`},
		{name: "tcp", id: "tcp", want: "cannot be combined with TCP or UDP", body: `{"auth":"siwe"}`},
		{name: "udp", id: "udp", want: "cannot be combined with TCP or UDP", body: `{"auth":"credential"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fileBefore, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			statusBefore := tunnelStatus(t, m, tc.id)

			code, body := callControl(t, m, http.MethodPatch, types.PathAgentTunnelsPrefix+tc.id, tc.body)
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

// The sign-in gate is built when a tunnel starts, so a changed gate restarts
// the edited tunnel. The other tunnels keep running untouched, with the relays
// connected to them at runtime, and metadata updates the running tunnel in
// place.
func TestUpdateTunnelAuthRestartsOnlyThatTunnel(t *testing.T) {
	addedRelay, err := utils.NormalizeRelayURL("https://127.0.0.1:2")
	if err != nil {
		t.Fatal(err)
	}
	edited := testTunnel("a")
	edited.Auth = "credential"
	m, _ := testManager(t, edited, testTunnel("b"))
	startManager(t, m)
	eventually(t, "both tunnels to run", func() bool {
		return tunnelStatus(t, m, "a").State == "running" && tunnelStatus(t, m, "b").State == "running"
	})
	if code, body := callControl(t, m, http.MethodPost, types.PathAgentTunnelsPrefix+"b/relays", `{"relay_url":"`+addedRelay+`"}`); code != http.StatusAccepted {
		t.Fatalf("connect relay: status = %d, body = %s", code, body)
	}
	hasAddedRelay := func(status AgentTunnelStatus) bool {
		return slices.ContainsFunc(status.Relays, func(relay AgentRelayStatus) bool { return relay.RelayURL == addedRelay })
	}
	if b := tunnelStatus(t, m, "b"); !hasAddedRelay(b) {
		t.Fatalf("relay was not connected to b: %+v", b.Relays)
	}

	// The credential provider check passes at once, so only a runtime rebuilt
	// with the new gate reports that the OIDC provider is unreachable.
	body := `{"auth":"oidc","auth_allowed_wallets":["alice@example.com"],"auth_oidc_issuer":"` + unreachableIssuer + `","auth_oidc_client_id":"client-123"}`
	if code, resp := callControl(t, m, http.MethodPatch, types.PathAgentTunnelsPrefix+"a", body); code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", code, resp)
	}
	if b := tunnelStatus(t, m, "b"); b.State != "running" || !hasAddedRelay(b) {
		t.Fatalf("sign-in change on a restarted b: %+v", b)
	}
	eventually(t, "a to run with the oidc gate", func() bool {
		return tunnelStatus(t, m, "a").AuthOIDCProviderError != ""
	})

	// Metadata, even sent next to unchanged sign-in settings, updates the
	// running tunnel in place: a relay connected at runtime would not survive
	// a restart.
	if code, resp := callControl(t, m, http.MethodPost, types.PathAgentTunnelsPrefix+"a/relays", `{"relay_url":"`+addedRelay+`"}`); code != http.StatusAccepted {
		t.Fatalf("connect relay: status = %d, body = %s", code, resp)
	}
	body = `{"metadata":{"description":"in place"},"auth":"oidc","auth_oidc_issuer":"` + unreachableIssuer + `"}`
	if code, resp := callControl(t, m, http.MethodPatch, types.PathAgentTunnelsPrefix+"a", body); code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", code, resp)
	}
	if status := tunnelStatus(t, m, "a"); status.State != "running" || !hasAddedRelay(status) || status.Metadata.Description != "in place" {
		t.Fatalf("tunnel was rebuilt for a metadata change: %+v", status)
	}
}

func TestAddTunnelWithAuth(t *testing.T) {
	const secret = "created-client-secret"
	wallet := "0x0000000000000000000000000000000000000001"
	common := `"discovery":false,"relays":["` + unreachableRelay + `"]`

	t.Run("accepted", func(t *testing.T) {
		m, path := testManager(t)
		startManager(t, m)
		for _, body := range []string{
			`{"id":"siwe","target_addr":"127.0.0.1:3000","auth":" SIWE ","auth_allowed_wallets":["` + wallet + `"],"auth_identity_headers":true,` + common + `}`,
			`{"id":"oidc","target_addr":"127.0.0.1:3000","auth":"oidc","auth_allowed_wallets":["alice@example.com"],"auth_oidc_issuer":"` + unreachableIssuer + `","auth_oidc_client_id":"client-123","auth_oidc_client_secret":"` + secret + `",` + common + `}`,
		} {
			code, resp := callControl(t, m, http.MethodPost, types.PathAgentTunnels, body)
			if code != http.StatusAccepted || strings.Contains(resp, secret) {
				t.Fatalf("status = %d, body = %s", code, resp)
			}
		}

		siwe := savedTunnel(t, path, "siwe")
		if siwe.Auth != "siwe" || !slices.Equal(siwe.AuthAllowedWallets, []string{wallet}) || !siwe.AuthIdentityHeaders {
			t.Fatalf("saved siwe tunnel = %+v", siwe)
		}
		if oidc := savedTunnel(t, path, "oidc"); oidc.Auth != "oidc" || oidc.AuthOIDCClientID != "client-123" || oidc.AuthOIDCClientSecret != secret {
			t.Fatalf("saved oidc tunnel = %+v", oidc)
		}
		if got := tunnelStatus(t, m, "oidc"); !got.AuthOIDCClientSecretSet || got.AuthOIDCClientID != "client-123" {
			t.Fatalf("oidc tunnel status = %+v", got)
		}
	})

	t.Run("rejected", func(t *testing.T) {
		m, path := testManager(t, testTunnel("existing"))
		for _, tc := range []struct{ name, body, want string }{
			{name: "oidc without allowlist", want: "oidc requires at least one",
				body: `{"id":"app","auth":"oidc","auth_oidc_issuer":"` + unreachableIssuer + `","auth_oidc_client_id":"client-123","auth_oidc_client_secret":"` + secret + `",` + common + `}`},
			{name: "invalid wallet", want: "address must start with 0x",
				body: `{"id":"app","auth":"siwe","auth_allowed_wallets":["alice"],` + common + `}`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				fileBefore, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				code, resp := callControl(t, m, http.MethodPost, types.PathAgentTunnels, tc.body)
				if code != http.StatusBadRequest || !strings.Contains(resp, tc.want) || strings.Contains(resp, secret) {
					t.Fatalf("status = %d, body = %s; want 400 mentioning %q", code, resp, tc.want)
				}
				if fileAfter, err := os.ReadFile(path); err != nil || !bytes.Equal(fileBefore, fileAfter) {
					t.Fatalf("rejected tunnel changed the config file (err %v):\n%s", err, fileAfter)
				}
				if got := len(m.Snapshot().Tunnels); got != 1 {
					t.Fatalf("tunnels = %d, want only the existing one", got)
				}
			})
		}
	})
}

func TestAddTunnelStaticSite(t *testing.T) {
	site := t.TempDir()
	if err := os.WriteFile(filepath.Join(site, "index.html"), []byte("<h1>hi</h1>"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A Windows path has backslashes, so the site path is JSON-encoded.
	siteJSON, err := json.Marshal(site)
	if err != nil {
		t.Fatal(err)
	}
	common := `"discovery":false,"relays":["` + unreachableRelay + `"]`

	t.Run("accepted", func(t *testing.T) {
		m, path := testManager(t)
		startManager(t, m)
		if code, resp := callControl(t, m, http.MethodPost, types.PathAgentTunnels, `{"id":"site","serve":`+string(siteJSON)+`,`+common+`}`); code != http.StatusAccepted {
			t.Fatalf("status = %d, body = %s", code, resp)
		}
		// A static site gets no default target.
		if saved := savedTunnel(t, path, "site"); saved.Serve != site || saved.TargetAddr != "" {
			t.Fatalf("saved static tunnel = %+v", saved)
		}
		if status := tunnelStatus(t, m, "site"); status.Serve != site || status.TargetAddr != "" {
			t.Fatalf("static tunnel status = %+v", status)
		}
	})

	t.Run("rejected", func(t *testing.T) {
		m, path := testManager(t, testTunnel("existing"))
		for _, tc := range []struct{ name, body string }{
			{name: "with target", body: `{"id":"site","serve":` + string(siteJSON) + `,"target_addr":"127.0.0.1:3000",` + common + `}`},
			{name: "with routes", body: `{"id":"site","serve":` + string(siteJSON) + `,"http_routes":[{"prefix":"/","upstream":"http://127.0.0.1:3000"}],` + common + `}`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				fileBefore, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				code, resp := callControl(t, m, http.MethodPost, types.PathAgentTunnels, tc.body)
				if code != http.StatusBadRequest || !strings.Contains(resp, "static serving cannot be combined") {
					t.Fatalf("status = %d, body = %s; want 400 refusing the combination", code, resp)
				}
				if fileAfter, err := os.ReadFile(path); err != nil || !bytes.Equal(fileBefore, fileAfter) {
					t.Fatalf("rejected tunnel changed the config file (err %v):\n%s", err, fileAfter)
				}
				if got := len(m.Snapshot().Tunnels); got != 1 {
					t.Fatalf("tunnels = %d, want only the existing one", got)
				}
			})
		}
	})
}
