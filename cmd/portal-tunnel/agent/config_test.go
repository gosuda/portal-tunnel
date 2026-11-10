package agent

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
)

func TestStaticServeConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	for _, input := range []string{"./dist", "./dist/main.html", filepath.Join(dir, "absolute-site")} {
		t.Run(input, func(t *testing.T) {
			path := filepath.Join(dir, "config.toml")
			data := fmt.Sprintf("[[tunnels]]\nid = \"site\"\nserve = %q\n", " "+input+" ")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadExistingConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			want := input
			if !filepath.IsAbs(want) {
				want = filepath.Join(dir, want)
			}
			if got := cfg.Tunnels[0].Serve; got != want {
				t.Fatalf("serve = %q, want %q", got, want)
			}
			cfg.Tunnels[0].Description = "updated metadata"
			if err := writeConfigDocument(path, 0o600, cfg); err != nil {
				t.Fatal(err)
			}
			reloaded, err := LoadExistingConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := reloaded.Tunnels[0].Serve; got != want {
				t.Fatalf("saved serve = %q, want %q", got, want)
			}
		})
	}
}

const tunnelsDocument = `
[[tunnels]]
id = "web"
name = "web-name"
target = "127.0.0.1:3000"
strip_request_headers = ["X-Strip"]
relays = ["https://relay.example.com"]
discovery = false
overlay = true
identity_path = "/absolute/identity.json"
tls_cert = "cert.pem"
tls_key = "key.pem"
ban_mitm = true
max_active_relays = 5
description = "described"
tags = ["tag"]
owner = "owner"
thumbnail = "https://example.com/thumb.png"
hide = true
auth = "oidc"
auth_allowed_wallets = ["alice@example.com"]
auth_identity_headers = true
auth_oidc_issuer = "https://accounts.google.com"
auth_oidc_client_id = "client-id"
auth_oidc_client_secret = "client-secret"

[[tunnels]]
id = "sso"
tls_auto = true
tls_state_dir = "certs"
tls_require_local = true
target = "localhost:3001"
auth = "saml"
auth_allowed_wallets = ["@example.com"]
auth_saml_metadata_url = "https://idp.example/metadata"
auth_saml_entity_id = "urn:portal:sso"
auth_saml_subject_attribute = "email"

[[tunnels]]
id = "sso-file"
target = "localhost:3002"
auth = "saml"
auth_allowed_wallets = ["sub:G-7f3a"]
auth_saml_metadata_file = "/absolute/idp.xml"

[[tunnels]]
id = "mail"
target = "localhost:3003"
auth = "email"
auth_email_list = ["alice@example.com", "@example.com"]
auth_smtp_addr = "smtp.example.com:587"
auth_smtp_username = "portal@example.com"
auth_smtp_password = "smtp-password"
auth_smtp_from = "Portal <portal@example.com>"

[[tunnels]]
id = "site"
serve = "./site"
identity_json = "{}"

[[tunnels]]
id = "paid"
x402_pay_to = "0x1234567890abcdef1234567890abcdef12345678"
x402_testnet = true
x402_network = "base"
x402_asset = "usdc"
x402_endpoints = ["/paid"]
x402_facilitator_token = "facilitator-token"

[[tunnels.http_routes]]
prefix = "/api"
upstream = "127.0.0.1:3001"
methods = ["GET"]
amount = "0.01"

[[tunnels]]
id = "tcp"
target = "127.0.0.1:25565"
tcp = true

[[tunnels]]
id = "udp"
target = "127.0.0.1:19132"
udp = true
udp_addr = "127.0.0.1:19133"
`

func TestSavedConfigKeepsEveryTunnelKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(tunnelsDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	keys := tunnelConfigKeys(reflect.TypeOf(TunnelConfig{}))
	for _, key := range keys {
		if !strings.Contains(tunnelsDocument, "\n"+key+" =") && !strings.Contains(tunnelsDocument, "\n[[tunnels."+key+"]]") {
			t.Errorf("tunnelsDocument does not set %q", key)
		}
	}

	if err := writeConfigDocument(path, 0o600, loaded); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if !strings.Contains(string(saved), "\n"+key+" =") && !strings.Contains(string(saved), "\n[[tunnels."+key+"]]") {
			t.Errorf("saved config does not keep %q:\n%s", key, saved)
		}
	}
	reloaded, err := LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Tunnels) != len(loaded.Tunnels) {
		t.Fatalf("saved %d tunnels, reloaded %d", len(loaded.Tunnels), len(reloaded.Tunnels))
	}
	for i := range loaded.Tunnels {
		if !reflect.DeepEqual(loaded.Tunnels[i], reloaded.Tunnels[i]) {
			t.Errorf("tunnel %q changed by a save:\n before: %+v\n after:  %+v", loaded.Tunnels[i].ID, loaded.Tunnels[i], reloaded.Tunnels[i])
		}
	}
	if err := writeConfigDocument(path, 0o600, reloaded); err != nil {
		t.Fatal(err)
	}
	if again, err := os.ReadFile(path); err != nil || !bytes.Equal(again, saved) {
		t.Fatalf("a second save wrote another document (err %v):\n%s", err, again)
	}
}

func TestExistingConfigKeysFillComponents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(tunnelsDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	specs := make(map[string]tunnel.Spec, len(cfg.Tunnels))
	for _, tunnelCfg := range cfg.Tunnels {
		if specs[tunnelCfg.ID], err = tunnelCfg.Spec(); err != nil {
			t.Fatal(err)
		}
	}
	oidc := appauth.Config{
		Provider:        appauth.ProviderOIDC,
		Allow:           []string{"alice@example.com"},
		IdentityHeaders: true,
		OIDCConfig:      appauth.OIDCConfig{OIDCIssuerURL: "https://accounts.google.com", OIDCClientID: "client-id", OIDCClientSecret: "client-secret"},
	}
	saml := appauth.Config{
		Provider:   appauth.ProviderSAML,
		Allow:      []string{"@example.com"},
		SAMLConfig: appauth.SAMLConfig{SAMLMetadataURL: "https://idp.example/metadata", SAMLEntityID: "urn:portal:sso", SAMLSubjectAttribute: "email"},
	}
	payment := gateway.X402Config{
		Testnet: true, Network: "base", Asset: "usdc", PayTo: "0x1234567890abcdef1234567890abcdef12345678",
		Endpoints: []string{"/paid"}, FacilitatorToken: "facilitator-token",
	}
	if got := *specs["web"].HTTP.Auth; !reflect.DeepEqual(got, oidc) {
		t.Errorf("web auth = %+v, want %+v", got, oidc)
	}
	if got := *specs["sso"].HTTP.Auth; !reflect.DeepEqual(got, saml) {
		t.Errorf("sso auth = %+v, want %+v", got, saml)
	}
	if got := specs["paid"].HTTP.Payment; !reflect.DeepEqual(got, payment) {
		t.Errorf("paid payment = %+v, want %+v", got, payment)
	}
	if got := specs["web"].Relays; got.Discovery || !got.BanMITM || got.MaxActive != 5 || !got.Overlay {
		t.Errorf("web relays = %+v", got)
	}
}

func TestSavedConfigKeepsOnlyWhatWasSet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	document := `
[agent]
state_dir = "state"

[[tunnels]]
name = "web"
target = "127.0.0.1:3000"

[[tunnels]]
id = "explicit"
target = "127.0.0.1:3001"
discovery = true
ban_mitm = false
max_active_relays = 3
`
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeConfigDocument(path, 0o600, cfg); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	web, explicit, ok := strings.Cut(string(saved), "id = 'explicit'")
	if !ok {
		t.Fatalf("saved config:\n%s", saved)
	}
	for _, key := range []string{"discovery", "ban_mitm", "max_active_relays"} {
		if strings.Contains(web, key) {
			t.Errorf("saved web tunnel repeats the default %s:\n%s", key, saved)
		}
	}
	for _, line := range []string{"discovery = true", "ban_mitm = false", "max_active_relays = 3"} {
		if !strings.Contains(explicit, line) {
			t.Errorf("saved explicit tunnel lost %q:\n%s", line, saved)
		}
	}
	for _, line := range []string{
		"id = 'web'",
		"identity_path = '" + filepath.Join(dir, "state", "web", defaultIdentityFilename) + "'",
		"identity_path = '" + filepath.Join(dir, "state", "explicit", defaultIdentityFilename) + "'",
	} {
		if !strings.Contains(string(saved), line) {
			t.Errorf("saved config lost %q:\n%s", line, saved)
		}
	}
}

func TestSavedConfigHoldingASecretIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows restricts the file with an ACL instead of a mode")
	}

	plain := TunnelConfig{ID: "web", Config: tunnel.Config{TargetAddr: "127.0.0.1:3000"}}
	for _, tt := range []struct {
		name   string
		before os.FileMode
		tunnel TunnelConfig
		want   os.FileMode
	}{
		{"OIDC client secret in a world-readable file", 0o644, TunnelConfig{ID: "web", Config: tunnel.Config{AuthConfig: appauth.Config{Provider: "oidc", OIDCConfig: appauth.OIDCConfig{OIDCClientSecret: "fake-secret"}}}}, 0o600},
		{"identity with a private key in a group-readable file", 0o640, TunnelConfig{ID: "web", Config: tunnel.Config{IdentityJSON: `{"private_key":"fake"}`}}, 0o600},
		{"x402 facilitator token in a group-writable file", 0o660, TunnelConfig{ID: "web", Config: tunnel.Config{X402Config: gateway.X402Config{FacilitatorToken: "fake-token"}}}, 0o600},
		{"a secret in a file that is already private", 0o600, TunnelConfig{ID: "web", Config: tunnel.Config{AuthConfig: appauth.Config{OIDCConfig: appauth.OIDCConfig{OIDCClientSecret: "fake-secret"}}}}, 0o600},
		{"the owner's other bits are kept", 0o755, TunnelConfig{ID: "web", Config: tunnel.Config{AuthConfig: appauth.Config{OIDCConfig: appauth.OIDCConfig{OIDCClientSecret: "fake-secret"}}}}, 0o700},
		{"a blank secret is not one", 0o644, TunnelConfig{ID: "web", Config: tunnel.Config{AuthConfig: appauth.Config{OIDCConfig: appauth.OIDCConfig{OIDCClientSecret: "  "}}}}, 0o644},
		{"no secret", 0o644, plain, 0o644},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tt.before); err != nil {
				t.Fatal(err)
			}
			if err := writeConfigDocument(path, tt.before, Config{Tunnels: []TunnelConfig{plain, tt.tunnel}}); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != tt.want {
				t.Fatalf("mode after the save = %o; want %o", got, tt.want)
			}
		})
	}
}

func TestHoldsSecretCoversEveryCredentialKey(t *testing.T) {
	var found int
	for _, field := range reflect.VisibleFields(reflect.TypeOf(TunnelConfig{})) {
		key, _, _ := strings.Cut(field.Tag.Get("toml"), ",")
		credential := key == "identity_json" || slices.ContainsFunc([]string{"secret", "token", "key", "password"}, func(word string) bool {
			return strings.Contains(key, word)
		})
		// tls_key stores a file path, not private key bytes.
		if !field.IsExported() || key == "" || key == "-" || key == "tls_key" || !credential {
			continue
		}
		found++
		if field.Type.Kind() != reflect.String {
			t.Errorf("%s is not a string; teach this test and holdsSecret how to read it", key)
			continue
		}
		var tunnel TunnelConfig
		reflect.ValueOf(&tunnel).Elem().FieldByIndex(field.Index).SetString("fake")
		if !tunnel.holdsSecret() {
			t.Errorf("%s reads like a credential, but a config that stores it is not made private: add it to holdsSecret", key)
		}
	}
	if found < 3 {
		t.Errorf("found %d credential keys in TunnelConfig; want at least 3", found)
	}
}

func tunnelConfigKeys(typ reflect.Type) []string {
	var keys []string
	for field := range typ.Fields() {
		key, _, _ := strings.Cut(field.Tag.Get("toml"), ",")
		switch {
		case field.Anonymous:
			keys = append(keys, tunnelConfigKeys(field.Type)...)
		case key != "" && key != "-":
			keys = append(keys, key)
		}
	}
	return keys
}

func TestLocalTLSCertificateConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := "[[tunnels]]\nid = \"web\"\ntarget = \"3000\"\ntls_cert = \"certs/tenant.pem\"\ntls_key = \"certs/tenant.key\"\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeConfigDocument(path, 0o600, cfg); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := reloaded.Tunnels[0].Spec()
	if err != nil {
		t.Fatal(err)
	}
	if spec.TLSCert != filepath.Join(dir, "certs", "tenant.pem") || spec.TLSKey != filepath.Join(dir, "certs", "tenant.key") {
		t.Fatalf("certificate paths after restart = %q, %q", spec.TLSCert, spec.TLSKey)
	}
}

func TestAutomaticTLSConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.toml")
	data := "[[tunnels]]\nid = \"web\"\ntarget = \"3000\"\nidentity_path = \"identity.json\"\ntls_auto = true\ntls_require_local = true\ntls_state_dir = \"certs\"\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeConfigDocument(path, 0600, cfg); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := cfg.Tunnels[0].Spec()
	if err != nil {
		t.Fatal(err)
	}
	if !spec.TLSAuto || !spec.TLSRequireLocal || spec.TLSStateDir != filepath.Join(dir, "certs") {
		t.Fatalf("persisted automatic TLS options = %+v", spec)
	}
	cfg.Tunnels[0].TLSStateDir = ""
	spec, err = cfg.Tunnels[0].Spec()
	if err != nil {
		t.Fatal(err)
	}
	if spec.TLSStateDir != filepath.Join(dir, "identity.json")+".tls" {
		t.Fatalf("identity-scoped default = %q", spec.TLSStateDir)
	}
}
