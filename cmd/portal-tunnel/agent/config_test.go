package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
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
		{name: "routes", cfg: TunnelConfig{Serve: "./dist", HTTPRoutes: []HTTPRouteConfig{{Prefix: "/", Upstream: "http://localhost:3000"}}}},
		{name: "tcp", cfg: TunnelConfig{Serve: "./dist", TCPEnabled: true}},
		{name: "udp", cfg: TunnelConfig{Serve: "./dist", UDPEnabled: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate() = %v, want valid=%v", err, tc.valid)
			}
		})
	}
}

func TestHTTPRoutesConfigModes(t *testing.T) {
	routes := []HTTPRouteConfig{{Prefix: "/", Upstream: "http://localhost:3000"}}
	for _, tc := range []struct {
		name  string
		cfg   TunnelConfig
		valid bool
	}{
		{name: "routes", cfg: TunnelConfig{HTTPRoutes: routes}, valid: true},
		{name: "tcp", cfg: TunnelConfig{HTTPRoutes: routes, TCPEnabled: true}},
		{name: "udp", cfg: TunnelConfig{HTTPRoutes: routes, UDPEnabled: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate() = %v, want valid=%v", err, tc.valid)
			}
		})
	}
}

func TestManagedConfigCompatibility(t *testing.T) {
	for _, source := range []string{
		"http_routes = [{prefix = 'api', upstream = 'localhost:3000'}]",
		"serve = './dist'\n- = 1",
		"serve = './dist'\ncache = true\ncache_ttl = '1m'",
	} {
		t.Run(source, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			data := "[[tunnels]]\nid = 'existing'\n" + source + "\n[[tunnels]]\nid = 'healthy'\ntarget = '3000'\n"
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadExistingConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.Tunnels) != 2 || cfg.Tunnels[1].TargetAddr != "3000" {
				t.Fatal("an invalid route must not prevent other managed tunnels from loading")
			}
			if cfg.Tunnels[0].Cache || cfg.Tunnels[0].CacheTTL != 0 {
				t.Fatal("managed config must not enable CLI-only relay caching")
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
		{name: "blank provider", cfg: TunnelConfig{TargetAddr: "localhost:3000", Auth: " "}},
		{name: "unknown provider", cfg: TunnelConfig{TargetAddr: "localhost:3000", Auth: "unknown"}},
		{name: "credential allowlist", cfg: TunnelConfig{TargetAddr: "localhost:3000", Auth: "credential", AuthAllowedWallets: []string{validWallet}}},
		{name: "static", cfg: TunnelConfig{Serve: "./dist", Auth: "siwe", AuthAllowedWallets: []string{validWallet}}, valid: true},
		{name: "allowlist without auth", cfg: TunnelConfig{TargetAddr: "localhost:3000", AuthAllowedWallets: []string{validWallet}}},
		{name: "headers without auth", cfg: TunnelConfig{TargetAddr: "localhost:3000", AuthIdentityHeaders: true}},
		{name: "tcp", cfg: TunnelConfig{TargetAddr: "localhost:3000", Auth: "siwe", TCPEnabled: true}},
		{name: "udp", cfg: TunnelConfig{TargetAddr: "localhost:3000", Auth: "siwe", UDPEnabled: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate() = %v, want valid=%v", err, tc.valid)
			}
		})
	}
}

func TestTunnelHTTPFeatureValidation(t *testing.T) {
	protectedCache := TunnelConfig{Serve: "./dist", Cache: true, BanMITM: new(bool)}
	*protectedCache.BanMITM = true
	for _, tc := range []struct {
		name  string
		cfg   TunnelConfig
		valid bool
	}{
		{name: "raw TCP", cfg: TunnelConfig{TargetAddr: "3000", TCPEnabled: true}, valid: true},
		{name: "UDP", cfg: TunnelConfig{TargetAddr: "3000", UDPEnabled: true}, valid: true},
		{name: "static cache", cfg: TunnelConfig{Serve: "./dist", Cache: true}, valid: true},
		{name: "cache target", cfg: TunnelConfig{TargetAddr: "3000", Cache: true}},
		{name: "cache TTL without cache", cfg: TunnelConfig{Serve: "./dist", CacheTTL: time.Minute}},
		{name: "cache with auth", cfg: TunnelConfig{Serve: "./dist", Cache: true, Auth: "siwe"}},
		{name: "cache with MITM ban", cfg: protectedCache},
		{name: "payment recipient", cfg: TunnelConfig{HTTPRoutes: []HTTPRouteConfig{
			{Prefix: "/paid", Upstream: "3000", Amount: "1"},
		}}},
		{name: "paid route", cfg: TunnelConfig{X402PayTo: "recipient", HTTPRoutes: []HTTPRouteConfig{
			{Prefix: "/paid", Upstream: "3000", Methods: []string{"GET"}, Amount: "1"},
		}}, valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate() = %v, want valid=%v", err, tc.valid)
			}
		})
	}
}

func TestManagedTunnelRequiresValidID(t *testing.T) {
	for _, id := range []string{"", "..", "a/b", "web"} {
		cfg := Config{Agent: AgentConfig{
			StateDir: t.TempDir(), ControlAddr: DefaultControlAddr, ServiceName: DefaultServiceName,
		}, Tunnels: []TunnelConfig{{ID: id, TargetAddr: "3000"}}}
		if err := cfg.Validate(); (err == nil) != (id == "web") {
			t.Fatalf("id %q: Validate() = %v", id, err)
		}
	}
}
