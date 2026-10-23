package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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

func TestApplicationAuthConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	want := TunnelConfig{
		ID: "app", TargetAddr: "localhost:3000",
		Auth: "oidc", AuthAllowedWallets: []string{"alice@example.com", "sub:42"}, AuthIdentityHeaders: true,
		AuthOIDCIssuer: "https://accounts.example.com", AuthOIDCClientID: "client-123", AuthOIDCClientSecret: "client-secret",
	}
	if err := writeConfigDocument(path, 0o600, Config{Tunnels: []TunnelConfig{want}}); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Tunnels[0].applicationAuth(); !reflect.DeepEqual(got, want.applicationAuth()) {
		t.Fatalf("saved auth = %+v, want %+v", got, want.applicationAuth())
	}
}
