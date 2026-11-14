package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
)

const unreachableRelay = "https://127.0.0.1:1"

const unreachableIssuer = "http://127.0.0.1:1"

func testTunnel(id string) TunnelConfig {
	discovery := false
	return TunnelConfig{ID: id, Config: tunnel.Config{TargetAddr: "127.0.0.1:3000", RelayURLs: []string{unreachableRelay}, Discovery: &discovery}}
}

func testManager(t *testing.T, tunnels ...TunnelConfig) (*manager, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	cfg := Config{Agent: AgentConfig{StateDir: dir}, Tunnels: tunnels}
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
	cfg.Provider = "oidc"
	cfg.Allow = []string{"alice@example.com"}
	cfg.OIDCIssuerURL = issuer
	cfg.OIDCClientID = "client-123"
	cfg.OIDCClientSecret = secret
	return cfg
}

func TestTunnelStatusAuthSettings(t *testing.T) {
	const secret = "s3cret-client-secret"
	const smtpPassword = "s3cret-smtp-password"
	credential := testTunnel("credential")
	credential.Provider = "credential"
	email := testTunnel("email")
	email.Provider = "email"
	email.EmailList = []string{"alice@example.com"}
	email.SMTPAddr = "smtp.example.com:587"
	email.SMTPUsername = "portal"
	email.SMTPPassword = smtpPassword
	email.SMTPFrom = "login@example.com"
	m, _ := testManager(t,
		oidcTunnel("oidc", "https://accounts.example.com", secret),
		credential,
		email,
		testTunnel("plain"),
	)
	data := marshalTunnelStatus(t, m)
	if strings.Contains(string(data), secret) || strings.Contains(string(data), smtpPassword) {
		t.Fatalf("status exposes a secret: %s", data)
	}

	byID := tunnelStatusByID(t, data)
	if got := byID["oidc"]["auth_allowed_wallets"]; !slices.Equal(toStrings(got), []string{"alice@example.com"}) {
		t.Fatalf("oidc auth_allowed_wallets = %v", got)
	}
	if byID["oidc"]["auth_oidc_client_secret_set"] != true {
		t.Fatalf("oidc auth_oidc_client_secret_set = %v, want true", byID["oidc"]["auth_oidc_client_secret_set"])
	}
	if byID["email"]["auth_smtp_password_set"] != true || byID["email"]["auth_smtp_addr"] != "smtp.example.com:587" {
		t.Fatalf("email status = %v, want the SMTP server and auth_smtp_password_set", byID["email"])
	}
	for _, key := range []string{"auth_allowed_wallets", "auth_oidc_client_secret_set", "auth_smtp_password_set", "auth_provider_checked", "auth_provider_error"} {
		for _, id := range []string{"credential", "plain"} {
			if _, ok := byID[id][key]; ok {
				t.Fatalf("tunnel %q reports %s without it being configured", id, key)
			}
		}
	}
	if _, ok := byID["oidc"]["auth_provider_checked"]; ok {
		t.Fatal("stopped oidc tunnel reports a provider check")
	}
}

func marshalTunnelStatus(t *testing.T, m *manager) []byte {
	t.Helper()
	data, err := json.Marshal(m.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func tunnelStatusByID(t *testing.T, data []byte) map[string]map[string]any {
	t.Helper()
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
	return byID
}

func toStrings(value any) []string {
	items, _ := value.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.(string))
	}
	return out
}

func TestTunnelStatusOIDCProviderCheck(t *testing.T) {
	siwe := testTunnel("siwe")
	siwe.Provider = "siwe"
	m, _ := testManager(t, oidcTunnel("oidc", unreachableIssuer, ""), siwe)
	startManager(t, m)

	eventually(t, "the oidc provider to be checked and the siwe tunnel to run", func() bool {
		return tunnelStatus(t, m, "oidc").AuthProviderChecked && tunnelStatus(t, m, "siwe").State == "running"
	})
	if got := tunnelStatus(t, m, "oidc"); got.AuthProviderError == "" {
		t.Fatal("unreachable provider reports no error")
	}
	if got := tunnelStatus(t, m, "siwe"); got.AuthProviderChecked || got.AuthProviderError != "" {
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

func TestAddTunnelWithAuth(t *testing.T) {
	const secret = "created-client-secret"
	wallet := "0x0000000000000000000000000000000000000001"
	common := `"discovery":false,"relays":["` + unreachableRelay + `"]`

	t.Run("accepted", func(t *testing.T) {
		checkAddTunnelWithAuthAccepted(t, secret, wallet, common)
	})

	t.Run("rejected", func(t *testing.T) {
		checkAddTunnelWithAuthRejected(t, secret, common)
	})
}

func checkAddTunnelWithAuthAccepted(t *testing.T, secret, wallet, common string) {
	t.Helper()
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
	if siwe.Provider != "siwe" || !slices.Equal(siwe.Allow, []string{wallet}) || !siwe.IdentityHeaders {
		t.Fatalf("saved siwe tunnel = %+v", siwe)
	}
	if oidc := savedTunnel(t, path, "oidc"); oidc.Provider != "oidc" || oidc.OIDCClientID != "client-123" || oidc.OIDCClientSecret != secret {
		t.Fatalf("saved oidc tunnel = %+v", oidc)
	}
	if got := tunnelStatus(t, m, "oidc"); !got.AuthOIDCClientSecretSet || got.OIDCClientID != "client-123" {
		t.Fatalf("oidc tunnel status = %+v", got)
	}
}

func checkAddTunnelWithAuthRejected(t *testing.T, secret, common string) {
	t.Helper()
	m, path := testManager(t, testTunnel("existing"))
	for _, tc := range []addTunnelRejection{
		{name: "oidc without allowlist", want: "oidc requires at least one",
			body: `{"id":"app","auth":"oidc","auth_oidc_issuer":"` + unreachableIssuer + `","auth_oidc_client_id":"client-123","auth_oidc_client_secret":"` + secret + `",` + common + `}`},
		{name: "invalid wallet", want: "address must start with 0x",
			body: `{"id":"app","auth":"siwe","auth_allowed_wallets":["alice"],` + common + `}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkAddTunnelRejection(t, m, path, secret, tc)
		})
	}
}

type addTunnelRejection struct {
	name string
	body string
	want string
}

func checkAddTunnelRejection(t *testing.T, m *manager, path, secret string, tc addTunnelRejection) {
	t.Helper()
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
}

func TestAddTunnelStaticSite(t *testing.T) {
	site := t.TempDir()
	if err := os.WriteFile(filepath.Join(site, "index.html"), []byte("<h1>hi</h1>"), 0o600); err != nil {
		t.Fatal(err)
	}
	siteJSON, err := json.Marshal(site)
	if err != nil {
		t.Fatal(err)
	}
	common := `"discovery":false,"relays":["` + unreachableRelay + `"]`

	t.Run("accepted", func(t *testing.T) {
		checkStaticSiteAccepted(t, site, siteJSON, common)
	})

	t.Run("with target", func(t *testing.T) {
		checkStaticSiteWithTargetRejected(t, siteJSON, common)
	})
}

func checkStaticSiteAccepted(t *testing.T, site string, siteJSON []byte, common string) {
	t.Helper()
	m, path := testManager(t)
	startManager(t, m)
	if code, resp := callControl(t, m, http.MethodPost, types.PathAgentTunnels, `{"id":"site","serve":`+string(siteJSON)+`,`+common+`}`); code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", code, resp)
	}
	if saved := savedTunnel(t, path, "site"); saved.Serve != site || saved.TargetAddr != "" {
		t.Fatalf("saved static tunnel = %+v", saved)
	}
}

func checkStaticSiteWithTargetRejected(t *testing.T, siteJSON []byte, common string) {
	t.Helper()
	m, path := testManager(t, testTunnel("existing"))
	fileBefore, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"id":"site","serve":` + string(siteJSON) + `,"target_addr":"127.0.0.1:3000",` + common + `}`
	if code, resp := callControl(t, m, http.MethodPost, types.PathAgentTunnels, body); code != http.StatusBadRequest || !strings.Contains(resp, "static serving cannot be combined") {
		t.Fatalf("status = %d, body = %s; want 400 refusing the combination", code, resp)
	}
	if fileAfter, err := os.ReadFile(path); err != nil || !bytes.Equal(fileBefore, fileAfter) {
		t.Fatalf("refused tunnel changed the config file (err %v):\n%s", err, fileAfter)
	}
}

func TestAddTunnelSavesOnlyWhatWasSent(t *testing.T) {
	m, path := testManager(t)
	startManager(t, m)
	body := `{"id":"web","discovery":false,"relays":["` + unreachableRelay + `"]}`
	if code, resp := callControl(t, m, http.MethodPost, types.PathAgentTunnels, body); code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", code, resp)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(saved), "max_active_relays") || !strings.Contains(string(saved), "discovery = false") {
		t.Fatalf("saved config:\n%s", saved)
	}
	if status := tunnelStatus(t, m, "web"); status.Discovery || status.MaxActiveRelays != discovery.DefaultMaxActiveRelays {
		t.Fatalf("status = %+v", status)
	}
}
