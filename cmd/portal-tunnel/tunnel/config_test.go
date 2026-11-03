package tunnel

import (
	"reflect"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
)

func TestConfigSpecModes(t *testing.T) {
	const wallet = "0x0000000000000000000000000000000000000001"
	routes := []HTTPRoute{{Prefix: "/", Upstream: "http://localhost:3000"}}
	for _, tc := range []struct {
		name  string
		edit  func(*Config)
		valid bool
	}{
		{name: "target", edit: func(c *Config) { c.TargetAddr = "localhost:3000" }, valid: true},
		{name: "missing source", edit: func(c *Config) {}},
		{name: "static", edit: func(c *Config) { c.Serve = "./dist" }, valid: true},
		{name: "static and target", edit: func(c *Config) { c.Serve, c.TargetAddr = "./dist", "localhost:3000" }},
		{name: "static and routes", edit: func(c *Config) { c.Serve, c.HTTPRoutes = "./dist", routes }},
		{name: "static and tcp", edit: func(c *Config) { c.Serve, c.TCPEnabled = "./dist", true }},
		{name: "static and udp", edit: func(c *Config) { c.Serve, c.UDPEnabled = "./dist", true }},
		{name: "routes", edit: func(c *Config) { c.HTTPRoutes = routes }, valid: true},
		{name: "routes and tcp", edit: func(c *Config) { c.HTTPRoutes, c.TCPEnabled = routes, true }},
		{name: "routes and udp", edit: func(c *Config) { c.HTTPRoutes, c.UDPEnabled = routes, true }},
		{name: "strip request headers", edit: func(c *Config) { c.HTTPRoutes, c.StripRequestHeaders = routes, []string{"X-Tenant-User"} }, valid: true},
		{name: "strip request headers on static", edit: func(c *Config) { c.Serve, c.StripRequestHeaders = "./dist", []string{"X-Tenant-User"} }},
		{name: "strip request headers without upstream", edit: func(c *Config) { c.Provider, c.StripRequestHeaders = "siwe", []string{"X-Tenant-User"} }},
		{name: "siwe", edit: func(c *Config) { c.TargetAddr, c.Provider = "localhost:3000", "siwe" }, valid: true},
		{name: "credential", edit: func(c *Config) { c.TargetAddr, c.Provider = "localhost:3000", "credential" }, valid: true},
		{name: "unknown provider", edit: func(c *Config) { c.TargetAddr, c.Provider = "localhost:3000", "unknown" }},
		{name: "credential allowlist", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.AllowedWallets = "localhost:3000", "credential", []string{"alice"}
		}, valid: true},
		{name: "credential invalid allowlist", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.AllowedWallets = "localhost:3000", "credential", []string{""}
		}},
		{name: "siwe invalid allowlist", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.AllowedWallets = "localhost:3000", "siwe", []string{"alice"}
		}},
		{name: "static siwe", edit: func(c *Config) { c.Serve, c.Provider, c.AllowedWallets = "./dist", "siwe", []string{wallet} }, valid: true},
		{name: "allowlist without provider", edit: func(c *Config) { c.TargetAddr, c.AllowedWallets = "localhost:3000", []string{wallet} }},
		{name: "headers without provider", edit: func(c *Config) { c.TargetAddr, c.IdentityHeaders = "localhost:3000", true }},
		{name: "auth and tcp", edit: func(c *Config) { c.TargetAddr, c.Provider, c.TCPEnabled = "localhost:3000", "siwe", true }},
		{name: "auth and udp", edit: func(c *Config) { c.TargetAddr, c.Provider, c.UDPEnabled = "localhost:3000", "siwe", true }},
		{name: "oidc", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.AllowedWallets = "localhost:3000", "oidc", []string{"alice@example.com"}
			c.OIDCIssuerURL, c.OIDCClientID = "https://accounts.google.com", "client-123"
		}, valid: true},
		{name: "oidc without issuer", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.AllowedWallets, c.OIDCClientID = "localhost:3000", "oidc", []string{"alice@example.com"}, "client-123"
		}},
		{name: "saml", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.AllowedWallets = "localhost:3000", "saml", []string{"@example.com"}
			c.SAMLMetadataURL = "https://idp.example/metadata"
		}, valid: true},
		{name: "saml with both metadata sources", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.AllowedWallets = "localhost:3000", "saml", []string{"@example.com"}
			c.SAMLMetadataURL, c.SAMLMetadataFile = "https://idp.example/metadata", "/idp.xml"
		}},
		// The settings of a provider that is not the active one are refused, so
		// they cannot change what the active one does.
		{name: "oidc settings under siwe", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.OIDCIssuerURL = "localhost:3000", "siwe", "https://accounts.google.com"
		}},
		{name: "saml settings under oidc", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.AllowedWallets = "localhost:3000", "oidc", []string{"alice@example.com"}
			c.OIDCIssuerURL, c.OIDCClientID, c.SAMLEntityID = "https://accounts.google.com", "client-123", "urn:portal"
		}},
		{name: "casper payment without asset", edit: func(c *Config) {
			c.HTTPRoutes, c.PayTo, c.Network = routes, "account-hash-1", "casper:casper-test"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			tc.edit(&cfg)
			if _, err := cfg.Spec(); (err == nil) != tc.valid {
				t.Fatalf("Spec() = %v, want valid=%v", err, tc.valid)
			}
		})
	}
}

// A Config keeps nil and zero for what was not set, so Spec owns the defaults,
// and an explicit value, false and zero included, wins over them.
func TestConfigSpecDefaults(t *testing.T) {
	off, on := false, true
	for _, tc := range []struct {
		name               string
		cfg                Config
		discovery, banMITM bool
		maxActive          int
	}{
		{name: "omitted", cfg: Config{TargetAddr: "localhost:3000"}, discovery: true, maxActive: discovery.DefaultMaxActiveRelays},
		{name: "explicit", cfg: Config{TargetAddr: "localhost:3000", Discovery: &off, BanMITM: &on, MaxActiveRelays: 5}, banMITM: true, maxActive: 5},
		{name: "explicit default values", cfg: Config{TargetAddr: "localhost:3000", Discovery: &on, BanMITM: &off}, discovery: true, maxActive: discovery.DefaultMaxActiveRelays},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := tc.cfg.Spec()
			if err != nil {
				t.Fatal(err)
			}
			if got := spec.Relays; got.Discovery != tc.discovery || got.BanMITM != tc.banMITM || got.MaxActive != tc.maxActive {
				t.Fatalf("relays = %+v, want discovery=%v ban_mitm=%v max_active=%d", got, tc.discovery, tc.banMITM, tc.maxActive)
			}
		})
	}
}

// Any auth setting makes an HTTP tunnel with the sign-in gate, so an incomplete
// auth config is refused instead of leaving the application open. Payment
// settings alone change nothing: only a paid route uses them.
func TestConfigSpecHTTPMode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		edit     func(*Config)
		http     bool
		auth     bool
		hasError bool
	}{
		{name: "target", edit: func(c *Config) {}},
		{name: "payment settings", edit: func(c *Config) { c.PayTo = "0x1" }},
		{name: "provider", edit: func(c *Config) { c.Provider = "credential" }, http: true, auth: true},
		{name: "identity headers alone", edit: func(c *Config) { c.IdentityHeaders = true }, http: true, auth: true, hasError: true},
		{name: "saml setting alone", edit: func(c *Config) { c.SAMLEntityID = "urn:portal" }, http: true, auth: true, hasError: true},
		{name: "strip request headers", edit: func(c *Config) { c.StripRequestHeaders = []string{"X-Tenant-User"} }, http: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{TargetAddr: "localhost:3000"}
			tc.edit(&cfg)
			spec, err := cfg.Spec()
			if (err != nil) != tc.hasError {
				t.Fatalf("Spec() error = %v, want error=%v", err, tc.hasError)
			}
			if (spec.HTTP != nil) != tc.http || (spec.HTTP != nil && spec.HTTP.Auth != nil) != tc.auth {
				t.Fatalf("HTTP = %+v, want http=%v auth=%v", spec.HTTP, tc.http, tc.auth)
			}
		})
	}
}

// Representative OIDC, SAML and x402 configs, written the way a user may type
// them, reach the runtime normalized by the owners of the components, and the
// Config the caller holds is left as it was.
func TestConfigSpecResolvesComponents(t *testing.T) {
	t.Setenv("CSPR_CLOUD_API_KEY", "")
	for _, tc := range []struct {
		name  string
		input func() Config
		check func(t *testing.T, spec Spec)
	}{
		{
			name: "oidc",
			input: func() Config {
				cfg := Config{TargetAddr: " localhost:3000 "}
				cfg.Provider, cfg.AllowedWallets = " OIDC ", []string{"Bob@Example.com", "bob@example.com"}
				cfg.OIDCIssuerURL, cfg.OIDCClientID, cfg.OIDCClientSecret = " https://accounts.google.com ", " client-123 ", " secret "
				return cfg
			},
			check: func(t *testing.T, spec Spec) {
				want := gateway.ApplicationAuthConfig{
					Provider:       gateway.ApplicationAuthProviderOIDC,
					AllowedWallets: []string{"bob@example.com"},
					OIDCConfig:     gateway.OIDCConfig{OIDCIssuerURL: "https://accounts.google.com", OIDCClientID: "client-123", OIDCClientSecret: "secret"},
				}
				if spec.Transport.Target != "localhost:3000" || !reflect.DeepEqual(*spec.HTTP.Auth, want) {
					t.Fatalf("target = %q, auth = %+v", spec.Transport.Target, *spec.HTTP.Auth)
				}
			},
		},
		{
			name: "saml",
			input: func() Config {
				cfg := Config{TargetAddr: "localhost:3000"}
				cfg.Provider, cfg.AllowedWallets, cfg.IdentityHeaders = "saml", []string{"@example.com", "sub:G-7f3a"}, true
				cfg.SAMLMetadataURL, cfg.SAMLSubjectAttribute = " https://idp.example/metadata ", " email "
				return cfg
			},
			check: func(t *testing.T, spec Spec) {
				want := gateway.ApplicationAuthConfig{
					Provider:        gateway.ApplicationAuthProviderSAML,
					AllowedWallets:  []string{"@example.com", "sub:G-7f3a"},
					IdentityHeaders: true,
					SAMLConfig:      gateway.SAMLConfig{SAMLMetadataURL: "https://idp.example/metadata", SAMLSubjectAttribute: "email"},
				}
				if !reflect.DeepEqual(*spec.HTTP.Auth, want) {
					t.Fatalf("auth = %+v", *spec.HTTP.Auth)
				}
			},
		},
		{
			name: "x402",
			input: func() Config {
				cfg := Config{HTTPRoutes: []HTTPRoute{{Prefix: " /paid ", Upstream: "127.0.0.1:3001", Methods: []string{"get", "GET", " post "}, Amount: " 0.01 "}}}
				cfg.PayTo, cfg.Network, cfg.Endpoints = " 0x1234 ", " SUI:TESTNET ", []string{" https://rpc.example ", ""}
				cfg.FacilitatorToken = " token "
				return cfg
			},
			check: func(t *testing.T, spec Spec) {
				wantRoutes := []HTTPRoute{{Prefix: "/paid", Upstream: "127.0.0.1:3001", Methods: []string{"GET", "POST"}, Amount: "0.01"}}
				wantPayment := gateway.X402Config{PayTo: "0x1234", Network: "sui:testnet", Endpoints: []string{"https://rpc.example"}, FacilitatorToken: "token"}
				if !reflect.DeepEqual(spec.HTTP.Routes, wantRoutes) || !reflect.DeepEqual(spec.HTTP.Payment.X402Config, wantPayment) || spec.HTTP.Auth != nil {
					t.Fatalf("routes = %+v, payment = %+v, auth = %+v", spec.HTTP.Routes, spec.HTTP.Payment.X402Config, spec.HTTP.Auth)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.input()
			spec, err := cfg.Spec()
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, spec)
			if !reflect.DeepEqual(cfg, tc.input()) {
				t.Fatalf("Spec changed the config it resolved: %+v", cfg)
			}
		})
	}
}

// The facilitator token falls back to CSPR_CLOUD_API_KEY, the variable
// portal expose reads for --x402-facilitator-token; a token in the config wins.
func TestConfigSpecFacilitatorTokenFromEnvironment(t *testing.T) {
	t.Setenv("CSPR_CLOUD_API_KEY", " env-token ")
	cfg := Config{HTTPRoutes: []HTTPRoute{{Prefix: "/", Upstream: "127.0.0.1:3001"}}}
	spec, err := cfg.Spec()
	if err != nil {
		t.Fatal(err)
	}
	if got := spec.HTTP.Payment.FacilitatorToken; got != "env-token" {
		t.Fatalf("token = %q, want the environment one", got)
	}
	cfg.FacilitatorToken = "config-token"
	if spec, _ = cfg.Spec(); spec.HTTP.Payment.FacilitatorToken != "config-token" {
		t.Fatalf("token = %q, want the config one", spec.HTTP.Payment.FacilitatorToken)
	}
}

// The identity proof is compared byte for byte upstream, and a path is resolved
// by the frontend that knows its base, so Normalize leaves both alone.
func TestConfigNormalizeKeepsProofAndPaths(t *testing.T) {
	cfg := Config{IdentityPath: "relative/identity.json"}
	cfg.IdentityProof = " proof-with-spaces-kept "
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.IdentityPath != "relative/identity.json" || cfg.IdentityProof != " proof-with-spaces-kept " {
		t.Fatalf("normalized = %+v", cfg)
	}
}
