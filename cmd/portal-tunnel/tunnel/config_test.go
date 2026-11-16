package tunnel

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
)

func TestParseHTTPRoute(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  HTTPRoute
	}{
		{input: "/api=3000", want: HTTPRoute{Prefix: "/api", Upstream: "3000"}},
		{input: " /api/ = http://localhost:3000/base?q=1 ", want: HTTPRoute{Prefix: "/api", Upstream: "http://localhost:3000/base?q=1"}},
		{input: "/paid=3000 0.01", want: HTTPRoute{Prefix: "/paid", Upstream: "3000", Amount: "0.01"}},
		{input: "/paid=3000 post,GET,POST:0.01", want: HTTPRoute{Prefix: "/paid", Upstream: "3000", Amount: "0.01", Methods: []string{"GET", "POST"}}},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseHTTPRoute(tc.input)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParseHTTPRoute() = %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
	for _, input := range []string{"", "/api", "=3000", "api=3000", "/api=", "/api=3000 GET:", "/api=3000 :0.01", "/api=3000 GET,:0.01", "/api=3000 0.01 extra"} {
		t.Run("invalid "+input, func(t *testing.T) {
			if _, err := ParseHTTPRoute(input); err == nil {
				t.Fatal("ParseHTTPRoute() accepted invalid syntax")
			}
		})
	}
}

func TestConfigSpecRejectsBlankPaymentMethods(t *testing.T) {
	for _, methods := range [][]string{{""}, {" "}, {"GET", " "}} {
		cfg := Config{HTTPRoutes: []HTTPRoute{{
			Prefix: "/paid", Upstream: "127.0.0.1:3000", Amount: "0.01", Methods: methods,
		}}}
		cfg.PayTo = "recipient"
		if _, err := cfg.Spec(); err == nil || !strings.Contains(err.Error(), "payment method is required") {
			t.Errorf("methods %q: Spec() error = %v, want a blank-method error", methods, err)
		}
	}
}

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
			c.TargetAddr, c.Provider, c.Allow = "localhost:3000", "credential", []string{"alice"}
		}, valid: true},
		{name: "credential invalid allowlist", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.Allow = "localhost:3000", "credential", []string{""}
		}},
		{name: "siwe invalid allowlist", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.Allow = "localhost:3000", "siwe", []string{"alice"}
		}},
		{name: "static siwe", edit: func(c *Config) { c.Serve, c.Provider, c.Allow = "./dist", "siwe", []string{wallet} }, valid: true},
		{name: "allowlist without provider", edit: func(c *Config) { c.TargetAddr, c.Allow = "localhost:3000", []string{wallet} }},
		{name: "headers without provider", edit: func(c *Config) { c.TargetAddr, c.IdentityHeaders = "localhost:3000", true }},
		{name: "auth and tcp", edit: func(c *Config) { c.TargetAddr, c.Provider, c.TCPEnabled = "localhost:3000", "siwe", true }},
		{name: "auth and udp", edit: func(c *Config) { c.TargetAddr, c.Provider, c.UDPEnabled = "localhost:3000", "siwe", true }},
		{name: "oidc", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.Allow = "localhost:3000", "oidc", []string{"alice@example.com"}
			c.OIDCIssuerURL, c.OIDCClientID = "https://accounts.google.com", "client-123"
		}, valid: true},
		{name: "oidc without issuer", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.Allow, c.OIDCClientID = "localhost:3000", "oidc", []string{"alice@example.com"}, "client-123"
		}},
		{name: "saml", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.Allow = "localhost:3000", "saml", []string{"@example.com"}
			c.SAMLMetadataURL = "https://idp.example/metadata"
		}, valid: true},
		{name: "saml with both metadata sources", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.Allow = "localhost:3000", "saml", []string{"@example.com"}
			c.SAMLMetadataURL, c.SAMLMetadataFile = "https://idp.example/metadata", "/idp.xml"
		}},
		{name: "oidc settings under siwe", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.OIDCIssuerURL = "localhost:3000", "siwe", "https://accounts.google.com"
		}},
		{name: "saml settings under oidc", edit: func(c *Config) {
			c.TargetAddr, c.Provider, c.Allow = "localhost:3000", "oidc", []string{"alice@example.com"}
			c.OIDCIssuerURL, c.OIDCClientID, c.SAMLEntityID = "https://accounts.google.com", "client-123", "urn:portal"
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

func TestReplicaConfigResolvesHTTPAndRejectsUnsupportedModes(t *testing.T) {
	cfg := Config{Replica: true, TargetAddr: "localhost:3000"}
	spec, err := cfg.Spec()
	if err != nil || spec.HTTP == nil || !spec.Transport.Replica {
		t.Fatalf("replica did not resolve to HTTP: %+v, %v", spec, err)
	}
	for _, invalid := range []Config{
		{Replica: true, TargetAddr: "localhost:3000", Overlay: true},
		{Replica: true, TargetAddr: "localhost:3000", TCPEnabled: true},
		{Replica: true, TargetAddr: "localhost:3000", UDPEnabled: true},
		{Replica: true, Serve: ".", Cache: &CacheConfig{}},
	} {
		if _, err := invalid.Spec(); err == nil {
			t.Fatalf("unsupported replica mode accepted: %+v", invalid)
		}
	}
}

func TestReplicaAuthCompatibility(t *testing.T) {
	for _, auth := range []appauth.Config{
		{Provider: appauth.ProviderSIWE},
		{Provider: appauth.ProviderCredential},
		{Provider: appauth.ProviderOIDC, Allow: []string{"alice@example.com"}, OIDCConfig: appauth.OIDCConfig{OIDCIssuerURL: "https://idp.example", OIDCClientID: "client"}},
		{Provider: appauth.ProviderSAML, Allow: []string{"alice@example.com"}, SAMLConfig: appauth.SAMLConfig{SAMLMetadataURL: "https://idp.example/metadata"}},
		{Provider: appauth.ProviderEmail, EmailList: []string{"alice@example.com"}, EmailConfig: appauth.EmailConfig{SMTPAddr: "smtp.example.com:465", SMTPFrom: "signin@example.com"}},
	} {
		t.Run(auth.Provider, func(t *testing.T) {
			cfg := Config{TargetAddr: "localhost:3000", AuthConfig: auth}
			if _, err := cfg.Spec(); err != nil {
				t.Fatalf("exclusive auth config rejected: %v", err)
			}
			cfg.Replica = true
			_, err := cfg.Spec()
			reject := auth.Provider == appauth.ProviderEmail || auth.Provider == appauth.ProviderSAML
			if reject {
				if !errors.Is(err, errReplicaApplicationAuth) {
					t.Fatalf("replica %s config: got %v, want %v", auth.Provider, err, errReplicaApplicationAuth)
				}
			} else if err != nil {
				t.Fatalf("replica %s config: unexpected error: %v", auth.Provider, err)
			}
		})
	}
}

func TestReplicaRejectsPaidNanoRoutes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network string
		replica bool
		amount  string
		reject  bool
	}{
		{name: "Nano replica", network: "nano:mainnet", replica: true, amount: "0.01", reject: true},
		{name: "normalized Nano replica", network: " NANO:MAINNET ", replica: true, amount: "0.01", reject: true},
		{name: "exclusive Nano", network: "nano:mainnet", amount: "0.01"},
		{name: "unpaid replica", network: "nano:mainnet", replica: true},
		{name: "Sui replica", network: "sui:mainnet", replica: true, amount: "0.01"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Replica:    tc.replica,
				HTTPRoutes: []HTTPRoute{{Prefix: "/", Upstream: "localhost:3000", Amount: tc.amount}},
				X402Config: gateway.X402Config{Network: tc.network, PayTo: "recipient"},
			}
			_, err := cfg.Spec()
			if tc.reject {
				if !errors.Is(err, errReplicaNanoPayments) {
					t.Fatalf("got %v, want incompatible-Nano error", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

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

func TestConfigSpecResolvesOIDC(t *testing.T) {
	t.Setenv("CSPR_CLOUD_API_KEY", "")
	cfg := Config{TargetAddr: " localhost:3000 "}
	cfg.Provider, cfg.Allow = " OIDC ", []string{"Bob@Example.com", "bob@example.com"}
	cfg.OIDCIssuerURL, cfg.OIDCClientID, cfg.OIDCClientSecret = " https://accounts.google.com ", " client-123 ", " secret "
	spec, err := cfg.Spec()
	if err != nil {
		t.Fatal(err)
	}
	want := appauth.Config{
		Provider:   appauth.ProviderOIDC,
		Allow:      []string{"bob@example.com"},
		OIDCConfig: appauth.OIDCConfig{OIDCIssuerURL: "https://accounts.google.com", OIDCClientID: "client-123", OIDCClientSecret: "secret"},
	}
	if spec.Transport.Target != "localhost:3000" || !reflect.DeepEqual(*spec.HTTP.Auth, want) {
		t.Fatalf("target = %q, auth = %+v", spec.Transport.Target, *spec.HTTP.Auth)
	}
	fresh := Config{TargetAddr: " localhost:3000 "}
	fresh.Provider, fresh.Allow = " OIDC ", []string{"Bob@Example.com", "bob@example.com"}
	fresh.OIDCIssuerURL, fresh.OIDCClientID, fresh.OIDCClientSecret = " https://accounts.google.com ", " client-123 ", " secret "
	if !reflect.DeepEqual(cfg, fresh) {
		t.Fatalf("Spec changed the config it resolved: %+v", cfg)
	}
}

func TestConfigSpecResolvesSAML(t *testing.T) {
	t.Setenv("CSPR_CLOUD_API_KEY", "")
	cfg := Config{TargetAddr: "localhost:3000"}
	cfg.Provider, cfg.Allow, cfg.IdentityHeaders = "saml", []string{"@example.com", "sub:G-7f3a"}, true
	cfg.SAMLMetadataURL, cfg.SAMLSubjectAttribute = " https://idp.example/metadata ", " email "
	spec, err := cfg.Spec()
	if err != nil {
		t.Fatal(err)
	}
	want := appauth.Config{
		Provider:        appauth.ProviderSAML,
		Allow:           []string{"@example.com", "sub:G-7f3a"},
		IdentityHeaders: true,
		SAMLConfig:      appauth.SAMLConfig{SAMLMetadataURL: "https://idp.example/metadata", SAMLSubjectAttribute: "email"},
	}
	if !reflect.DeepEqual(*spec.HTTP.Auth, want) {
		t.Fatalf("auth = %+v", *spec.HTTP.Auth)
	}
	fresh := Config{TargetAddr: "localhost:3000"}
	fresh.Provider, fresh.Allow, fresh.IdentityHeaders = "saml", []string{"@example.com", "sub:G-7f3a"}, true
	fresh.SAMLMetadataURL, fresh.SAMLSubjectAttribute = " https://idp.example/metadata ", " email "
	if !reflect.DeepEqual(cfg, fresh) {
		t.Fatalf("Spec changed the config it resolved: %+v", cfg)
	}
}

func TestConfigSpecResolvesX402(t *testing.T) {
	t.Setenv("CSPR_CLOUD_API_KEY", "")
	cfg := Config{HTTPRoutes: []HTTPRoute{{Prefix: " /paid ", Upstream: "127.0.0.1:3001", Methods: []string{"get", "GET", " post "}, Amount: " 0.01 "}}}
	cfg.PayTo, cfg.Network, cfg.Endpoints = " 0x1234 ", " SUI:TESTNET ", []string{" https://rpc.example ", ""}
	cfg.FacilitatorToken = " token "
	spec, err := cfg.Spec()
	if err != nil {
		t.Fatal(err)
	}
	wantRoutes := []HTTPRoute{{Prefix: "/paid", Upstream: "127.0.0.1:3001", Methods: []string{"GET", "POST"}, Amount: "0.01"}}
	wantPayment := gateway.X402Config{PayTo: "0x1234", Network: "sui:testnet", Endpoints: []string{"https://rpc.example"}, FacilitatorToken: "token"}
	if !reflect.DeepEqual(spec.HTTP.Routes, wantRoutes) || !reflect.DeepEqual(spec.HTTP.Payment, wantPayment) || spec.HTTP.Auth != nil {
		t.Fatalf("routes = %+v, payment = %+v, auth = %+v", spec.HTTP.Routes, spec.HTTP.Payment, spec.HTTP.Auth)
	}
	fresh := Config{HTTPRoutes: []HTTPRoute{{Prefix: " /paid ", Upstream: "127.0.0.1:3001", Methods: []string{"get", "GET", " post "}, Amount: " 0.01 "}}}
	fresh.PayTo, fresh.Network, fresh.Endpoints = " 0x1234 ", " SUI:TESTNET ", []string{" https://rpc.example ", ""}
	fresh.FacilitatorToken = " token "
	if !reflect.DeepEqual(cfg, fresh) {
		t.Fatalf("Spec changed the config it resolved: %+v", cfg)
	}
}

func TestConfigSpecDoesNotReadEnvironment(t *testing.T) {
	t.Setenv("CSPR_CLOUD_API_KEY", " env-token ")
	cfg := Config{HTTPRoutes: []HTTPRoute{{Prefix: "/", Upstream: "127.0.0.1:3001"}}}
	spec, err := cfg.Spec()
	if err != nil {
		t.Fatal(err)
	}
	if got := spec.HTTP.Payment.FacilitatorToken; got != "" {
		t.Fatalf("token = %q, want empty explicit input", got)
	}
	cfg.FacilitatorToken = "config-token"
	if spec, _ = cfg.Spec(); spec.HTTP.Payment.FacilitatorToken != "config-token" {
		t.Fatalf("token = %q, want the config one", spec.HTTP.Payment.FacilitatorToken)
	}
}

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

func TestLocalTLSCertificateConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name      string
		config    Config
		wantError bool
	}{
		{"paired", Config{TargetAddr: "3000", TLSCert: " cert.pem ", TLSKey: " key.pem "}, false},
		{"certificate only", Config{TargetAddr: "3000", TLSCert: "cert.pem"}, true},
		{"key only", Config{TargetAddr: "3000", TLSKey: "key.pem"}, true},
		{"raw TCP", Config{TargetAddr: "3000", TLSCert: "cert.pem", TLSKey: "key.pem", TCPEnabled: true}, true},
		{"relay cache", Config{Serve: "site", TLSCert: "cert.pem", TLSKey: "key.pem", Cache: &CacheConfig{}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := tc.config.Spec()
			if (err != nil) != tc.wantError {
				t.Fatalf("Spec() error = %v, want error %v", err, tc.wantError)
			}
			if !tc.wantError && (spec.TLSCert != tc.config.TLSCert || spec.TLSKey != tc.config.TLSKey) {
				t.Fatalf("certificate paths = %q, %q", spec.TLSCert, spec.TLSKey)
			}
		})
	}
}

func TestLocalTLSPathsAreNotNormalizedAway(t *testing.T) {
	cfg := Config{TargetAddr: "3000", TLSCert: " ", TLSKey: " "}
	spec, err := cfg.Spec()
	if err != nil {
		t.Fatal(err)
	}
	if spec.TLSCert != " " || spec.TLSKey != " " {
		t.Fatal("configured local TLS file paths were silently removed")
	}
}

func TestAutomaticTLSConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name      string
		config    Config
		wantDir   string
		wantError bool
	}{
		{"identity default", Config{TargetAddr: "3000", IdentityPath: "identity.json", TLSAuto: true}, "identity.json.tls", false},
		{"explicit", Config{TargetAddr: "3000", IdentityJSON: "{}", TLSAuto: true, TLSStateDir: " certs ", TLSRequireLocal: true}, " certs ", false},
		{"memory identity requires directory", Config{TargetAddr: "3000", IdentityJSON: "{}", IdentityPath: "unused.json", TLSAuto: true}, "", true},
		{"missing identity and directory", Config{TargetAddr: "3000", TLSAuto: true}, "", true},
		{"directory does not enable automatic", Config{TargetAddr: "3000", TLSStateDir: "certs"}, "", true},
		{"policy needs a mode", Config{TargetAddr: "3000", TLSRequireLocal: true}, "", true},
		{"manual policy", Config{TargetAddr: "3000", TLSCert: "cert.pem", TLSKey: "key.pem", TLSRequireLocal: true}, "", false},
		{"manual automatic conflict", Config{TargetAddr: "3000", TLSAuto: true, TLSStateDir: "certs", TLSCert: "cert.pem", TLSKey: "key.pem"}, "", true},
		{"raw TCP", Config{TargetAddr: "3000", TLSAuto: true, TLSStateDir: "certs", TCPEnabled: true}, "", true},
		{"cache", Config{Serve: "site", TLSAuto: true, TLSStateDir: "certs", Cache: &CacheConfig{}}, "certs", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := tc.config.Spec()
			if (err != nil) != tc.wantError {
				t.Fatalf("Spec() = %v, want error %v", err, tc.wantError)
			}
			if !tc.wantError && spec.TLSStateDir != tc.wantDir {
				t.Fatalf("state directory = %q, want %q", spec.TLSStateDir, tc.wantDir)
			}
			if spec.TLSRequireLocal != tc.config.TLSRequireLocal {
				t.Fatal("require-local policy was lost")
			}
		})
	}
}

func TestCertificateMonitoringConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name      string
		config    Config
		wantError bool
	}{
		{"disabled by default", Config{TargetAddr: "3000"}, false},
		{"keyless", Config{TargetAddr: "3000", TLSMonitorStateDir: "evidence"}, false},
		{"manual", Config{TargetAddr: "3000", TLSCert: "cert.pem", TLSKey: "key.pem", TLSMonitorStateDir: "evidence"}, false},
		{"automatic", Config{TargetAddr: "3000", TLSAuto: true, TLSStateDir: "certs", TLSMonitorStateDir: "evidence"}, false},
		{"explicit baseline and resolver", Config{TargetAddr: "3000", TLSMonitorStateDir: " evidence ", TLSMonitorBaseline: " baseline.json ", TLSMonitorDNSResolver: "[2606:4700:4700::1111]:53"}, false},
		{"baseline alone", Config{TargetAddr: "3000", TLSMonitorBaseline: "baseline.json"}, true},
		{"resolver alone", Config{TargetAddr: "3000", TLSMonitorDNSResolver: "9.9.9.9:53"}, true},
		{"invalid resolver", Config{TargetAddr: "3000", TLSMonitorStateDir: "evidence", TLSMonitorDNSResolver: "resolver.example:53"}, true},
		{"raw TCP", Config{TargetAddr: "3000", TLSMonitorStateDir: "evidence", TCPEnabled: true}, true},
		{"relay cache", Config{Serve: "site", TLSMonitorStateDir: "evidence", Cache: &CacheConfig{}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := tc.config.Spec()
			if (err != nil) != tc.wantError {
				t.Fatalf("Spec() error = %v, want error %v", err, tc.wantError)
			}
			if tc.wantError {
				return
			}
			monitor := spec.CertificateMonitor
			if tc.config.TLSMonitorStateDir == "" {
				if monitor != nil {
					t.Fatal("monitoring enabled without an explicit request")
				}
				return
			}
			if monitor == nil || monitor.StateDir != tc.config.TLSMonitorStateDir || monitor.BaselineFile != tc.config.TLSMonitorBaseline || monitor.DNSResolver != tc.config.TLSMonitorDNSResolver {
				t.Fatalf("monitoring configuration was changed: %+v", monitor)
			}
			if spec.TLSAuto != tc.config.TLSAuto || spec.TLSRequireLocal != tc.config.TLSRequireLocal {
				t.Fatal("monitoring changed certificate provisioning policy")
			}
		})
	}
}

func TestLocalTLSSelectsHTTPHandler(t *testing.T) {
	for _, config := range []Config{
		{TargetAddr: "3000", TLSAuto: true, TLSStateDir: "certs"},
		{TargetAddr: "3000", TLSCert: "cert.pem", TLSKey: "key.pem"},
		{
			TargetAddr:     "3000",
			IdentityPath:   "identity.json",
			PGNSZone:       "portal.example",
			PGNSSequencers: []string{"https://seq.portal.example"},
			PGNSWitnesses:  []string{"w1=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"},
		},
	} {
		spec, err := config.Spec()
		if err != nil {
			t.Fatal(err)
		}
		if spec.HTTP == nil {
			t.Fatal("Local TLS targets need HTTP handling for h2 translation")
		}
	}
}

func TestPGNSConfigurationValidation(t *testing.T) {
	const witnessHex = "w1=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	// Compressed secp256k1 generator G
	const validRecoveryPub = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	basePGNS := func() Config {
		return Config{
			TargetAddr:     "3000",
			IdentityPath:   "identity.json",
			PGNSZone:       "portal.example",
			PGNSSequencers: []string{"https://seq.portal.example"},
			PGNSWitnesses:  []string{witnessHex},
		}
	}

	t.Run("identity default state dir and immutability", func(t *testing.T) {
		cfg := Config{
			TargetAddr:         " 3000 ",
			IdentityPath:       "identity.json",
			PGNSZone:           " portal.example ",
			PGNSAlias:          " myapp ",
			PGNSSiteLabel:      " prod ",
			PGNSSequencers:     []string{" https://seq.portal.example ", ""},
			PGNSWitnesses:      []string{" " + witnessHex + " "},
			PGNSRecoveryPubKey: " " + validRecoveryPub + " ",
			PGNSRelayEndpoints: []string{" https://r1.portal.example=93.184.216.34:443 "},
		}
		snapshot := Config{
			TargetAddr:         cfg.TargetAddr,
			IdentityPath:       cfg.IdentityPath,
			PGNSZone:           cfg.PGNSZone,
			PGNSAlias:          cfg.PGNSAlias,
			PGNSSiteLabel:      cfg.PGNSSiteLabel,
			PGNSSequencers:     []string{" https://seq.portal.example ", ""},
			PGNSWitnesses:      []string{" " + witnessHex + " "},
			PGNSRecoveryPubKey: cfg.PGNSRecoveryPubKey,
			PGNSRelayEndpoints: []string{" https://r1.portal.example=93.184.216.34:443 "},
		}
		spec, err := cfg.Spec()
		if err != nil {
			t.Fatalf("Spec(): %v", err)
		}
		if spec.PGNS == nil || spec.PGNS.StateDir != "identity.json.pgns" {
			t.Fatalf("StateDir = %+v, want identity.json.pgns", spec.PGNS)
		}
		if !reflect.DeepEqual(cfg, snapshot) {
			t.Fatalf("Spec mutated input Config: %+v", cfg)
		}
	})

	for _, tc := range []struct {
		name      string
		mutate    func(*Config)
		wantError bool
	}{
		{"valid id mode", func(c *Config) {}, false},
		{"in-memory identity requires pgns_state_dir", func(c *Config) { c.IdentityJSON = "{}"; c.IdentityPath = "" }, true},
		{"in-memory identity with pgns_state_dir", func(c *Config) { c.IdentityJSON = "{}"; c.IdentityPath = ""; c.PGNSStateDir = "pgns-state" }, false},
		{"missing zone", func(c *Config) { c.PGNSZone = "" }, true},
		{"missing sequencers", func(c *Config) { c.PGNSSequencers = nil }, true},
		{"missing witnesses", func(c *Config) { c.PGNSWitnesses = nil }, true},
		{"recovery key forbidden on id mode", func(c *Config) { c.PGNSRecoveryPubKey = validRecoveryPub }, true},
		{"recovery key allowed on app mode", func(c *Config) { c.PGNSAlias = "myapp"; c.PGNSRecoveryPubKey = validRecoveryPub }, false},
		{"persist01 requires caa issuer", func(c *Config) { c.PGNSPersist01 = true }, true},
		{"persist01 with caa issuer", func(c *Config) { c.PGNSPersist01 = true; c.PGNSACMECAIssuer = "pki.goog" }, false},
		{"conflict with relay cache", func(c *Config) { c.TargetAddr = ""; c.Serve = "dist"; c.Cache = &CacheConfig{} }, true},
		{"conflict with tls-auto", func(c *Config) { c.TLSAuto = true; c.TLSStateDir = "certs" }, true},
		{"conflict with tls-cert", func(c *Config) { c.TLSCert = "cert.pem"; c.TLSKey = "key.pem" }, true},
		{"conflict with raw tcp", func(c *Config) { c.TCPEnabled = true }, true},
		{"non-public relay endpoint rejected", func(c *Config) { c.PGNSRelayEndpoints = []string{"https://r1.portal.example=127.0.0.1:443"} }, true},
		{"doc IP relay endpoint rejected", func(c *Config) { c.PGNSRelayEndpoints = []string{"https://r1.portal.example=198.51.100.1:443"} }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := basePGNS()
			tc.mutate(&cfg)
			_, err := cfg.Spec()
			if (err != nil) != tc.wantError {
				t.Fatalf("Spec() error = %v, wantError = %v", err, tc.wantError)
			}
		})
	}
}
