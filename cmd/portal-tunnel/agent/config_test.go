package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
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
			tc.cfg.ID = "site"
			if err := tc.cfg.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate() = %v, want valid=%v", err, tc.valid)
			}
		})
	}
}
