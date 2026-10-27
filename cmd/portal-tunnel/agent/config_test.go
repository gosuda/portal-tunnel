package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
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
			// Saving unrelated settings must preserve the static site source.
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

func TestStaticServeConfigModes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cfg   TunnelConfig
		valid bool
	}{
		{name: "static", cfg: TunnelConfig{Serve: "./dist"}, valid: true},
		{name: "missing source", cfg: TunnelConfig{}},
		{name: "target", cfg: TunnelConfig{Serve: "./dist", TargetAddr: "localhost:3000"}},
		{name: "routes", cfg: TunnelConfig{Serve: "./dist", HTTPRoutes: []tunnel.HTTPRoute{{Prefix: "/", Upstream: "http://localhost:3000"}}}},
		{name: "tcp", cfg: TunnelConfig{Serve: "./dist", TCPEnabled: true}},
		{name: "udp", cfg: TunnelConfig{Serve: "./dist", UDPEnabled: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.ID = "site"
			if err := tc.cfg.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate() = %v, want valid=%v", err, tc.valid)
			}
		})
	}
}

func TestHTTPRoutesConfigModes(t *testing.T) {
	routes := []tunnel.HTTPRoute{{Prefix: "/", Upstream: "http://localhost:3000"}}
	for _, tc := range []struct {
		name  string
		cfg   TunnelConfig
		valid bool
	}{
		{name: "routes", cfg: TunnelConfig{HTTPRoutes: routes}, valid: true},
		{name: "tcp", cfg: TunnelConfig{HTTPRoutes: routes, TCPEnabled: true}},
		{name: "udp", cfg: TunnelConfig{HTTPRoutes: routes, UDPEnabled: true}},
		{name: "strip request headers", cfg: TunnelConfig{HTTPRoutes: routes, StripRequestHeaders: []string{"X-Tenant-User"}}, valid: true},
		{name: "strip request headers on static", cfg: TunnelConfig{Serve: "./dist", StripRequestHeaders: []string{"X-Tenant-User"}}},
		{name: "strip request header without upstream", cfg: TunnelConfig{Auth: "siwe", TargetAddr: "", StripRequestHeaders: []string{"X-Tenant-User"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.ID = "routed"
			if err := tc.cfg.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate() = %v, want valid=%v", err, tc.valid)
			}
		})
	}
}

func TestApplicationAuthConfig(t *testing.T) {
	validWallet := "0x0000000000000000000000000000000000000001"
	for _, tc := range []struct {
		name  string
		cfg   TunnelConfig
		valid bool
	}{
		{name: "target", cfg: TunnelConfig{TargetAddr: "localhost:3000", Auth: "siwe"}, valid: true},
		{name: "credential", cfg: TunnelConfig{TargetAddr: "localhost:3000", Auth: "credential"}, valid: true},
		{name: "unknown provider", cfg: TunnelConfig{TargetAddr: "localhost:3000", Auth: "unknown"}},
		{name: "credential allowlist", cfg: TunnelConfig{TargetAddr: "localhost:3000", Auth: "credential", AuthAllowedWallets: []string{"alice"}}, valid: true},
		{name: "credential invalid allowlist", cfg: TunnelConfig{TargetAddr: "localhost:3000", Auth: "credential", AuthAllowedWallets: []string{""}}},
		{name: "siwe invalid allowlist", cfg: TunnelConfig{TargetAddr: "localhost:3000", Auth: "siwe", AuthAllowedWallets: []string{"alice"}}},
		{name: "oidc", cfg: TunnelConfig{TargetAddr: "localhost:3000", Auth: "oidc", AuthOIDCIssuer: "https://accounts.google.com", AuthOIDCClientID: "client-123", AuthAllowedWallets: []string{"alice@example.com"}}, valid: true},
		{name: "oidc missing issuer", cfg: TunnelConfig{TargetAddr: "localhost:3000", Auth: "oidc", AuthOIDCClientID: "client-123"}},
		{name: "oidc fields without oidc provider", cfg: TunnelConfig{TargetAddr: "localhost:3000", Auth: "siwe", AuthOIDCIssuer: "https://accounts.google.com"}},
		{name: "static", cfg: TunnelConfig{Serve: "./dist", Auth: "siwe", AuthAllowedWallets: []string{validWallet}}, valid: true},
		{name: "allowlist without auth", cfg: TunnelConfig{TargetAddr: "localhost:3000", AuthAllowedWallets: []string{validWallet}}},
		{name: "headers without auth", cfg: TunnelConfig{TargetAddr: "localhost:3000", AuthIdentityHeaders: true}},
		{name: "tcp", cfg: TunnelConfig{TargetAddr: "localhost:3000", Auth: "siwe", TCPEnabled: true}},
		{name: "udp", cfg: TunnelConfig{TargetAddr: "localhost:3000", Auth: "siwe", UDPEnabled: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.ID = "authenticated"
			if err := tc.cfg.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate() = %v, want valid=%v", err, tc.valid)
			}
		})
	}
}

// tunnelsDocument sets every tunnel key, each to a value that differs from its
// default, so a key the writer drops shows up as a difference after a save. The
// keys are spread over several tunnels because loading validates each one and
// some keys exclude each other (HTTP routes and TCP, a static site and a target).
// The check below finds a key as a line that starts with it and has one space
// before `=`, so keep the keys unindented in that form. A key inside a nested
// struct such as an HTTP route is not walked and has to be set here by hand.
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

// Saving the config after any dashboard action rewrites the whole file, so
// every key the loader reads must come back out of the writer.
func TestSavedConfigKeepsEveryTunnelKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(tunnelsDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	// A key added to TunnelConfig must be added to the document above too, or
	// this test would not notice the writer forgetting it.
	for _, key := range tunnelConfigKeys(reflect.TypeOf(TunnelConfig{})) {
		if !strings.Contains(tunnelsDocument, "\n"+key+" =") && !strings.Contains(tunnelsDocument, "\n[[tunnels."+key+"]]") {
			t.Errorf("tunnelsDocument does not set %q", key)
		}
	}

	if err := writeConfigDocument(path, 0o600, loaded); err != nil {
		t.Fatal(err)
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
}

// Linux and macOS keep the mode a file already has, so the agent restricts a
// config before it writes a credential into it; a config without one is left as
// the user set it.
func TestSavedConfigHoldingASecretIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows restricts the file with an ACL instead of a mode")
	}

	plain := TunnelConfig{ID: "web", TargetAddr: "127.0.0.1:3000"}
	for _, tt := range []struct {
		name   string
		before os.FileMode
		tunnel TunnelConfig
		want   os.FileMode
	}{
		{"OIDC client secret in a world-readable file", 0o644, TunnelConfig{ID: "web", Auth: "oidc", AuthOIDCClientSecret: "fake-secret"}, 0o600},
		{"identity with a private key in a group-readable file", 0o640, TunnelConfig{ID: "web", IdentityJSON: `{"private_key":"fake"}`}, 0o600},
		{"x402 facilitator token in a group-writable file", 0o660, TunnelConfig{ID: "web", FacilitatorToken: "fake-token"}, 0o600},
		{"a secret in a file that is already private", 0o600, TunnelConfig{ID: "web", AuthOIDCClientSecret: "fake-secret"}, 0o600},
		{"the owner's other bits are kept", 0o755, TunnelConfig{ID: "web", AuthOIDCClientSecret: "fake-secret"}, 0o700},
		{"a blank secret is not one", 0o644, TunnelConfig{ID: "web", AuthOIDCClientSecret: "  "}, 0o644},
		{"no secret", 0o644, plain, 0o644},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tt.before); err != nil { // not subject to the umask
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

// holdsSecret lists the credential fields by hand, as the document writer lists
// the keys it saves. A credential field added to TunnelConfig and missing from
// holdsSecret would be saved into a world-readable file with no test to notice, so
// every field whose key reads like a credential must count.
func TestHoldsSecretCoversEveryCredentialKey(t *testing.T) {
	var found int
	for _, field := range reflect.VisibleFields(reflect.TypeOf(TunnelConfig{})) {
		key, _, _ := strings.Cut(field.Tag.Get("koanf"), ",")
		credential := key == "identity_json" || slices.ContainsFunc([]string{"secret", "token", "key", "password"}, func(word string) bool {
			return strings.Contains(key, word)
		})
		if !field.IsExported() || key == "" || !credential {
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
	// Three keys are known today; fewer means the match above stopped finding them.
	if found < 3 {
		t.Errorf("found %d credential keys in TunnelConfig; want at least 3", found)
	}
}

func tunnelConfigKeys(typ reflect.Type) []string {
	var keys []string
	for field := range typ.Fields() {
		tag := field.Tag.Get("koanf")
		switch {
		case strings.HasSuffix(tag, ",squash"):
			keys = append(keys, tunnelConfigKeys(field.Type)...)
		case tag != "":
			keys = append(keys, tag)
		}
	}
	return keys
}
