package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// writeEnvFile writes lines to a temporary env file and returns its path.
func writeEnvFile(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.env")
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	return path
}

// resolveWithEnvFile runs the same isolation the config subcommand performs and
// returns the resulting configuration.
func resolveWithEnvFile(t *testing.T, path string) appConfig {
	t.Helper()
	entries, err := loadEnvFile(path)
	if err != nil {
		t.Fatalf("load env file: %v", err)
	}
	restore, err := applyEnvFileInIsolation(entries)
	if err != nil {
		t.Fatalf("isolate env file: %v", err)
	}
	defer restore()

	cfg, err := resolveAppConfig(nil)
	if err != nil {
		t.Fatalf("resolve config: %v", err)
	}
	return cfg
}

func TestHTTPRedirectEnvironment(t *testing.T) {
	cfg := resolveWithEnvFile(t, writeEnvFile(t,
		types.HTTPRedirectEnabledEnv+"=true", "HTTP_REDIRECT_ADDR=127.0.0.1:18080", "HTTP_REDIRECT_HSTS=true"))
	if !cfg.Relay.HTTPRedirect.Enabled || cfg.Relay.HTTPRedirect.Addr != "127.0.0.1:18080" || !cfg.Relay.HTTPRedirect.HSTS {
		t.Fatalf("redirect environment not resolved: %+v", cfg)
	}
	f := featureByName(t, cfg, types.HTTPRedirectFeatureName)
	if f.State != types.FeatureEnabled || !strings.Contains(f.Detail, "browsers ignore") {
		t.Fatalf("redirect capability report=%+v", f)
	}
	cfg = resolveWithEnvFile(t, writeEnvFile(t))
	if cfg.Relay.HTTPRedirect.Enabled || cfg.Relay.HTTPRedirect.HSTS || cfg.Relay.HTTPRedirect.Addr != types.DefaultHTTPRedirectAddr {
		t.Fatalf("unexpected redirect defaults: %+v", cfg)
	}
}

func TestHTTPRedirectReportDoesNotBind(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	cfg := resolveWithEnvFile(t, writeEnvFile(t,
		"PORTAL_URL=https://localhost:4017", types.HTTPRedirectEnabledEnv+"=true",
		"HTTP_REDIRECT_ADDR="+occupied.Addr().String()))
	f := featureByName(t, cfg, types.HTTPRedirectFeatureName)
	if f.State != types.FeatureEnabled || f.Missing != "" {
		t.Fatalf("occupied address must not block configuration reporting: %+v", f)
	}
	_, err = portal.NewServer(portal.ServerConfig{
		PortalURL: cfg.Relay.PortalURL, StateDir: t.TempDir(), HTTPRedirect: cfg.Relay.HTTPRedirect,
	})
	if err != nil {
		t.Fatalf("NewServer must defer binding until Start: %v", err)
	}
}

func featureByName(t *testing.T, cfg appConfig, name string) types.FeatureDiagnostic {
	t.Helper()
	for _, f := range evaluateFeatures(cfg) {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("feature %q not reported", name)
	return types.FeatureDiagnostic{}
}

// A variable absent from the env file must not leak in from the surrounding
// shell: Compose passes only the file, so a report that saw the shell would be
// describing a different deployment.
func TestEnvFileIsolationIgnoresInheritedValue(t *testing.T) {
	t.Setenv("DISCOVERY", "true")

	cfg := resolveWithEnvFile(t, writeEnvFile(t, "PORTAL_URL=https://relay.example.com"))

	if cfg.Relay.DiscoveryEnabled {
		t.Fatal("DISCOVERY was inherited from the process environment; the file did not set it")
	}
}

// A higher-priority alias in the shell must not beat a value the file supplies
// through a lower-priority name.
func TestEnvFileIsolationBeatsHigherPriorityAlias(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")

	cfg := resolveWithEnvFile(t, writeEnvFile(t, "AWS_DEFAULT_REGION=ap-northeast-2"))

	if cfg.Relay.ACME.AWSRegion != "ap-northeast-2" {
		t.Fatalf("AWS region = %q, want the file value ap-northeast-2", cfg.Relay.ACME.AWSRegion)
	}
}

func TestEnvFileIsolationRestoresEnvironment(t *testing.T) {
	t.Setenv("DISCOVERY", "true")
	if err := os.Unsetenv("BOOTSTRAPS"); err != nil {
		t.Fatalf("unset BOOTSTRAPS: %v", err)
	}

	entries, err := loadEnvFile(writeEnvFile(t, "BOOTSTRAPS=https://seed.example.com"))
	if err != nil {
		t.Fatalf("load env file: %v", err)
	}
	restore, err := applyEnvFileInIsolation(entries)
	if err != nil {
		t.Fatalf("isolate env file: %v", err)
	}
	restore()

	if got := os.Getenv("DISCOVERY"); got != "true" {
		t.Fatalf("DISCOVERY = %q after restore, want true", got)
	}
	if _, set := os.LookupEnv("BOOTSTRAPS"); set {
		t.Fatal("BOOTSTRAPS is set after restore; it was unset before")
	}
}

// acme.NewManager returns before building a DNS provider for a local-only base
// domain, so a configured provider still yields no managed issuance.
func TestACMEFeatureBlockedForLocalHost(t *testing.T) {
	for _, provider := range []string{"", "embedded", "cloudflare"} {
		t.Run(provider, func(t *testing.T) {
			cfg := appConfig{
				Relay: portal.ServerConfig{
					PortalURL: "https://localhost",
					ACME:      acme.Config{DNSProvider: provider, CloudflareToken: "token"},
				},
			}

			f := featureByName(t, cfg, "acme")
			if f.State != types.FeatureBlocked {
				t.Fatalf("acme state = %q, want %q", f.State, types.FeatureBlocked)
			}
			if !strings.Contains(f.Missing, "local-only") {
				t.Fatalf("acme missing = %q, want it to name the local-only host", f.Missing)
			}
		})
	}
}

// ens-gasless drives the same provider, so it must inherit the blocked state
// rather than repeating half of the check.
func TestENSGaslessFollowsBlockedACME(t *testing.T) {
	for _, provider := range []string{"", "embedded", "cloudflare"} {
		t.Run(provider, func(t *testing.T) {
			cfg := appConfig{
				Relay: portal.ServerConfig{
					PortalURL: "https://localhost",
					ACME:      acme.Config{DNSProvider: provider, CloudflareToken: "token", ENSGaslessEnabled: true},
				},
			}

			f := featureByName(t, cfg, "ens-gasless")
			if f.State != types.FeatureBlocked {
				t.Fatalf("ens-gasless state = %q, want %q", f.State, types.FeatureBlocked)
			}
			if !strings.Contains(f.Missing, "local-only") {
				t.Fatalf("ens-gasless missing = %q, want the ACME reason propagated", f.Missing)
			}
		})
	}
}

func TestENSGaslessBlockedForUnsupportedDNSSECProvider(t *testing.T) {
	for _, provider := range []string{"hetzner", "njalla"} {
		t.Run(provider, func(t *testing.T) {
			cfg := appConfig{
				Relay: portal.ServerConfig{
					PortalURL: "https://relay.example.com",
					ACME:      acme.Config{DNSProvider: provider, ENSGaslessEnabled: true},
				},
			}
			if provider == "hetzner" {
				cfg.Relay.ACME.HetznerAPIToken = "token"
			} else {
				cfg.Relay.ACME.NjallaToken = "token"
			}
			if f := featureByName(t, cfg, "acme"); f.State != types.FeatureEnabled {
				t.Fatalf("acme state = %q, want managed DNS to remain enabled", f.State)
			}
			f := featureByName(t, cfg, "ens-gasless")
			if f.State != types.FeatureBlocked || !strings.Contains(f.Missing, "DNSSEC") {
				t.Fatalf("ens-gasless = %+v, want blocked for missing DNSSEC support", f)
			}
			cfg.Relay.ACME.ENSGaslessEnabled = false
			if f := featureByName(t, cfg, "ens-gasless"); f.State != types.FeatureDisabled {
				t.Fatalf("ens-gasless state = %q, want disabled when not requested", f.State)
			}
		})
	}
}

func TestACMEFeatureEnabledForPublicHost(t *testing.T) {
	cfg := appConfig{
		Relay: portal.ServerConfig{
			PortalURL: "https://relay.example.com",
			ACME:      acme.Config{DNSProvider: "cloudflare", CloudflareToken: "token"},
		},
	}

	f := featureByName(t, cfg, "acme")
	if f.State != types.FeatureEnabled {
		t.Fatalf("acme state = %q, want %q (missing: %s)", f.State, types.FeatureEnabled, f.Missing)
	}
}

func TestACMEFeatureBlockedWithoutCredential(t *testing.T) {
	cfg := appConfig{
		Relay: portal.ServerConfig{
			PortalURL: "https://relay.example.com",
			ACME:      acme.Config{DNSProvider: "cloudflare"},
		},
	}

	f := featureByName(t, cfg, "acme")
	if f.State != types.FeatureBlocked {
		t.Fatalf("acme state = %q, want %q", f.State, types.FeatureBlocked)
	}
	if !strings.Contains(f.Missing, "CLOUDFLARE_TOKEN") {
		t.Fatalf("acme missing = %q, want it to name the credential", f.Missing)
	}
}

// A line that is neither blank, a comment, nor an assignment is a typo, and
// dropping it would recreate the silent misconfiguration this command exists to
// expose: the feature would report its default with nothing to explain why.
func TestLoadEnvFileRejectsMalformedLines(t *testing.T) {
	for name, line := range map[string]string{
		"missing separator": "DISCOVERY true",
		"empty name":        "=true",
	} {
		t.Run(name, func(t *testing.T) {
			path := writeEnvFile(t, "PORTAL_URL=https://relay.example.com", line)

			_, err := loadEnvFile(path)
			if err == nil {
				t.Fatalf("%q was accepted", line)
			}
			if !strings.Contains(err.Error(), ":2:") {
				t.Fatalf("error does not point at the line: %v", err)
			}
		})
	}
}

func TestLoadEnvFileKeepsCommentsAndBlanks(t *testing.T) {
	path := writeEnvFile(t, "# a comment", "", "  ", "export PORTAL_URL=https://relay.example.com")

	entries, err := loadEnvFile(path)
	if err != nil {
		t.Fatalf("load env file: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "PORTAL_URL" {
		t.Fatalf("entries = %v, want only PORTAL_URL", entries)
	}
}

// The report must not claim a feature works when the server will reject the
// same value moments later. portal.NewServer normalizes PORTAL_URL through
// utils.NormalizeRelayURL, which requires https.
func TestDiscoveryBlockedForNonHTTPSPortalURL(t *testing.T) {
	path := writeEnvFile(t, "DISCOVERY=true", "PORTAL_URL=http://relay.example.com")
	cfg := resolveWithEnvFile(t, path)

	f := featureByName(t, cfg, "discovery")
	if f.State != types.FeatureBlocked {
		t.Fatalf("discovery state = %q, want blocked for a non-https PORTAL_URL", f.State)
	}
	if !strings.Contains(f.Missing, "https") {
		t.Fatalf("missing = %q, want it to name the https requirement", f.Missing)
	}
}

func TestDiscoveryBlockedForUnusableBootstraps(t *testing.T) {
	path := writeEnvFile(t,
		"DISCOVERY=true",
		"PORTAL_URL=https://relay.example.com",
		"BOOTSTRAPS=http://peer.example.com")
	cfg := resolveWithEnvFile(t, path)

	f := featureByName(t, cfg, "discovery")
	if f.State != types.FeatureBlocked {
		t.Fatalf("discovery state = %q, want blocked for an unusable BOOTSTRAPS", f.State)
	}
}

func TestDiscoveryEnabledCountsNormalizedBootstraps(t *testing.T) {
	path := writeEnvFile(t,
		"DISCOVERY=true",
		"PORTAL_URL=https://relay.example.com",
		"BOOTSTRAPS=https://a.example.com,https://b.example.com")
	cfg := resolveWithEnvFile(t, path)

	f := featureByName(t, cfg, "discovery")
	if f.State != types.FeatureEnabled {
		t.Fatalf("discovery state = %q, want enabled", f.State)
	}
	if !strings.Contains(f.Detail, "bootstraps=2") {
		t.Fatalf("detail = %q, want bootstraps=2", f.Detail)
	}
}

func TestProxyHeaderFeatureBlockedForInvalidCIDR(t *testing.T) {
	cfg := resolveWithEnvFile(t, writeEnvFile(t,
		"TRUST_PROXY_HEADERS=true",
		"TRUSTED_PROXY_CIDRS=not-a-cidr"))

	f := featureByName(t, cfg, "proxy-headers")
	if f.State != types.FeatureBlocked {
		t.Fatalf("proxy header state = %q, want blocked", f.State)
	}
	if !strings.Contains(f.Missing, "invalid cidr") {
		t.Fatalf("proxy header missing = %q, want CIDR validation error", f.Missing)
	}
}

// An unset ACME_DNS_PROVIDER selects the embedded authoritative server, not
// "no automation". Reporting it as disabled would describe a relay that is in
// fact serving its own zone.
func TestACMEFeatureReportsEmbeddedWhenUnset(t *testing.T) {
	path := writeEnvFile(t, "PORTAL_URL=https://relay.example.com")
	cfg := resolveWithEnvFile(t, path)

	f := featureByName(t, cfg, "acme")
	if f.State != types.FeatureEnabled {
		t.Fatalf("acme state = %q, want enabled for the embedded default", f.State)
	}
	if !strings.Contains(f.By, "embedded") {
		t.Fatalf("by = %q, want it to name the embedded provider", f.By)
	}
}

// Embedded DNS signs the ENS TXT records; publishing its DS remains an
// explicit parent-zone operation rather than an API-credential requirement.
func TestENSGaslessEnabledOnEmbeddedProvider(t *testing.T) {
	path := writeEnvFile(t,
		"PORTAL_URL=https://relay.example.com",
		"ENS_GASLESS_ENABLED=true")
	cfg := resolveWithEnvFile(t, path)

	f := featureByName(t, cfg, "ens-gasless")
	if f.State != types.FeatureEnabled {
		t.Fatalf("ens-gasless state = %q, want enabled on the embedded provider", f.State)
	}
	if !strings.Contains(f.Detail, "embedded") {
		t.Fatalf("detail = %q, want it to name the embedded provider", f.Detail)
	}
}

func TestENSGaslessEnabledOnManagedProvider(t *testing.T) {
	for _, provider := range []string{"cloudflare", "gcloud", "route53", "vultr"} {
		t.Run(provider, func(t *testing.T) {
			values := []string{
				"PORTAL_URL=https://relay.example.com",
				"ACME_DNS_PROVIDER=" + provider,
				"ENS_GASLESS_ENABLED=true",
			}
			switch provider {
			case "cloudflare":
				values = append(values, "CLOUDFLARE_TOKEN=token")
			case "vultr":
				values = append(values, "VULTR_API_KEY=token")
			}
			path := writeEnvFile(t, values...)
			cfg := resolveWithEnvFile(t, path)

			if f := featureByName(t, cfg, "ens-gasless"); f.State != types.FeatureEnabled {
				t.Fatalf("ens-gasless state = %q (%s), want enabled", f.State, f.Missing)
			}
		})
	}
}
