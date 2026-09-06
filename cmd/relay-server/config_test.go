package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal"
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
func resolveWithEnvFile(t *testing.T, path string) relayServerConfig {
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

	cfg, err := resolveRelayServerConfig(nil)
	if err != nil {
		t.Fatalf("resolve config: %v", err)
	}
	return cfg
}

func TestHTTPRedirectEnvironment(t *testing.T) {
	cfg := resolveWithEnvFile(t, writeEnvFile(t,
		types.HTTPRedirectEnabledEnv+"=true", "HTTP_REDIRECT_ADDR=127.0.0.1:18080", "HTTP_REDIRECT_HSTS=true"))
	if !cfg.HTTPRedirect.Enabled || cfg.HTTPRedirect.Addr != "127.0.0.1:18080" || !cfg.HTTPRedirect.HSTS {
		t.Fatalf("redirect environment not resolved: %+v", cfg)
	}
	f := featureByName(t, cfg, types.HTTPRedirectFeatureName)
	if f.State != stateEnabled || !strings.Contains(f.Detail, "browsers ignore") {
		t.Fatalf("redirect capability report=%+v", f)
	}
	cfg = resolveWithEnvFile(t, writeEnvFile(t))
	if cfg.HTTPRedirect.Enabled || cfg.HTTPRedirect.HSTS || cfg.HTTPRedirect.Addr != types.DefaultHTTPRedirectAddr {
		t.Fatalf("unexpected redirect defaults: %+v", cfg)
	}
}

func TestHTTPRedirectReportMatchesServerValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		target  string
		addr    string
		enabled bool
		blocked bool
	}{
		{name: "HTTPS", target: "HTTPS://localhost:4017/base/?q=discarded#fragment", addr: "127.0.0.1:0", enabled: true},
		{name: "mixed case", target: "hTtPs://localhost:4017", addr: "[::1]:0", enabled: true},
		{name: "default address", target: "https://localhost:4017", enabled: true},
		{name: "trimmed address", target: " https://localhost:4017/ ", addr: " 127.0.0.1:18080 ", enabled: true},
		{name: "DNS deferred", target: "https://localhost:4017", addr: "does-not-resolve.invalid:80", enabled: true},
		{name: "HTTP", target: "http://relay.example", addr: "127.0.0.1:0", enabled: true, blocked: true},
		{name: "loopback HTTP", target: "http://localhost:4017", enabled: true, blocked: true},
		{name: "relative target", target: "//relay.example", enabled: true, blocked: true},
		{name: "credentials", target: "https://user:pass@relay.example", enabled: true, blocked: true},
		{name: "empty root", target: "https://./", enabled: true, blocked: true},
		{name: "zero target port", target: "https://relay.example:0", enabled: true, blocked: true},
		{name: "high target port", target: "https://relay.example:65536", enabled: true, blocked: true},
		{name: "nonnumeric target port", target: "https://relay.example:bad", enabled: true, blocked: true},
		{name: "missing listen port", target: "https://localhost:4017", addr: "127.0.0.1", enabled: true, blocked: true},
		{name: "empty listen port", target: "https://localhost:4017", addr: "127.0.0.1:", enabled: true, blocked: true},
		{name: "nonnumeric listen port", target: "https://localhost:4017", addr: ":bad", enabled: true, blocked: true},
		{name: "negative listen port", target: "https://localhost:4017", addr: ":-1", enabled: true, blocked: true},
		{name: "high listen port", target: "https://localhost:4017", addr: ":65536", enabled: true, blocked: true},
		{name: "invalid listen host", target: "https://localhost:4017", addr: "bad host:80", enabled: true, blocked: true},
		{name: "invalid IPv6", target: "https://localhost:4017", addr: "[gg::1]:80", enabled: true, blocked: true},
		{name: "disabled", target: "http://localhost:4017", addr: "invalid ignored address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := resolveWithEnvFile(t, writeEnvFile(t,
				"PORTAL_URL="+tc.target, "HTTP_REDIRECT_ADDR="+tc.addr,
				types.HTTPRedirectEnabledEnv+"="+strconv.FormatBool(tc.enabled)))
			f := featureByName(t, cfg, types.HTTPRedirectFeatureName)
			want := stateDisabled
			if tc.enabled {
				want = stateEnabled
			}
			if tc.blocked {
				want = stateBlocked
			}
			if f.State != want {
				t.Fatalf("redirect report=%+v, want state %s", f, want)
			}
			_, err := portal.NewServer(portal.ServerConfig{
				PortalURL: cfg.PortalURL, IdentityPath: t.TempDir(), HTTPRedirect: cfg.HTTPRedirect,
			})
			if tc.blocked {
				if err == nil || f.Missing != err.Error() {
					t.Fatalf("report reason=%q, NewServer error=%v", f.Missing, err)
				}
			} else if err != nil || f.Missing != "" {
				t.Fatalf("report=%+v, NewServer error=%v", f, err)
			}
			if tc.enabled && !tc.blocked && !strings.Contains(f.Detail, "listener binding occurs at startup") {
				t.Fatalf("report must distinguish configuration from readiness: %+v", f)
			}
		})
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
	if f.State != stateEnabled || f.Missing != "" {
		t.Fatalf("occupied address must not block configuration reporting: %+v", f)
	}
	_, err = portal.NewServer(portal.ServerConfig{
		PortalURL: cfg.PortalURL, IdentityPath: t.TempDir(), HTTPRedirect: cfg.HTTPRedirect,
	})
	if err != nil {
		t.Fatalf("NewServer must defer binding until Start: %v", err)
	}
}

func featureByName(t *testing.T, cfg relayServerConfig, name string) feature {
	t.Helper()
	for _, f := range evaluateFeatures(cfg) {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("feature %q not reported", name)
	return feature{}
}

// A variable absent from the env file must not leak in from the surrounding
// shell: Compose passes only the file, so a report that saw the shell would be
// describing a different deployment.
func TestEnvFileIsolationIgnoresInheritedValue(t *testing.T) {
	t.Setenv("DISCOVERY", "true")

	cfg := resolveWithEnvFile(t, writeEnvFile(t, "PORTAL_URL=https://relay.example.com"))

	if cfg.DiscoveryEnabled {
		t.Fatal("DISCOVERY was inherited from the process environment; the file did not set it")
	}
}

// A higher-priority alias in the shell must not beat a value the file supplies
// through a lower-priority name.
func TestEnvFileIsolationBeatsHigherPriorityAlias(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")

	cfg := resolveWithEnvFile(t, writeEnvFile(t, "AWS_DEFAULT_REGION=ap-northeast-2"))

	if cfg.AWSRegion != "ap-northeast-2" {
		t.Fatalf("AWS region = %q, want the file value ap-northeast-2", cfg.AWSRegion)
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
	cfg := relayServerConfig{
		PortalURL:       "https://localhost",
		ACMEDNSProvider: "cloudflare",
		CloudflareToken: "token",
	}

	f := featureByName(t, cfg, "acme")
	if f.State != stateBlocked {
		t.Fatalf("acme state = %q, want %q", f.State, stateBlocked)
	}
	if !strings.Contains(f.Missing, "local-only") {
		t.Fatalf("acme missing = %q, want it to name the local-only host", f.Missing)
	}
}

// ens-gasless drives the same provider, so it must inherit the blocked state
// rather than repeating half of the check.
func TestENSGaslessFollowsBlockedACME(t *testing.T) {
	cfg := relayServerConfig{
		PortalURL:         "https://localhost",
		ACMEDNSProvider:   "cloudflare",
		CloudflareToken:   "token",
		ENSGaslessEnabled: true,
	}

	f := featureByName(t, cfg, "ens-gasless")
	if f.State != stateBlocked {
		t.Fatalf("ens-gasless state = %q, want %q", f.State, stateBlocked)
	}
	if !strings.Contains(f.Missing, "local-only") {
		t.Fatalf("ens-gasless missing = %q, want the ACME reason propagated", f.Missing)
	}
}

func TestACMEFeatureEnabledForPublicHost(t *testing.T) {
	cfg := relayServerConfig{
		PortalURL:       "https://relay.example.com",
		ACMEDNSProvider: "cloudflare",
		CloudflareToken: "token",
	}

	f := featureByName(t, cfg, "acme")
	if f.State != stateEnabled {
		t.Fatalf("acme state = %q, want %q (missing: %s)", f.State, stateEnabled, f.Missing)
	}
}

func TestACMEFeatureBlockedWithoutCredential(t *testing.T) {
	cfg := relayServerConfig{
		PortalURL:       "https://relay.example.com",
		ACMEDNSProvider: "cloudflare",
	}

	f := featureByName(t, cfg, "acme")
	if f.State != stateBlocked {
		t.Fatalf("acme state = %q, want %q", f.State, stateBlocked)
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

	f := discoveryFeature(cfg)
	if f.State != stateBlocked {
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

	f := discoveryFeature(cfg)
	if f.State != stateBlocked {
		t.Fatalf("discovery state = %q, want blocked for an unusable BOOTSTRAPS", f.State)
	}
}

func TestDiscoveryEnabledCountsNormalizedBootstraps(t *testing.T) {
	path := writeEnvFile(t,
		"DISCOVERY=true",
		"PORTAL_URL=https://relay.example.com",
		"BOOTSTRAPS=https://a.example.com,https://b.example.com")
	cfg := resolveWithEnvFile(t, path)

	f := discoveryFeature(cfg)
	if f.State != stateEnabled {
		t.Fatalf("discovery state = %q, want enabled", f.State)
	}
	if !strings.Contains(f.Detail, "bootstraps=2") {
		t.Fatalf("detail = %q, want bootstraps=2", f.Detail)
	}
}

// An unset ACME_DNS_PROVIDER selects the embedded authoritative server, not
// "no automation". Reporting it as disabled would describe a relay that is in
// fact serving its own zone.
func TestACMEFeatureReportsEmbeddedWhenUnset(t *testing.T) {
	path := writeEnvFile(t, "PORTAL_URL=https://relay.example.com")
	cfg := resolveWithEnvFile(t, path)

	f := acmeFeature(cfg)
	if f.State != stateEnabled {
		t.Fatalf("acme state = %q, want enabled for the embedded default", f.State)
	}
	if !strings.Contains(f.By, "embedded") {
		t.Fatalf("by = %q, want it to name the embedded provider", f.By)
	}
}

// The embedded server cannot manage zone DNSSEC yet, and it is what an operator
// gets by enabling ENS and changing nothing else.
func TestENSGaslessBlockedOnEmbeddedProvider(t *testing.T) {
	path := writeEnvFile(t,
		"PORTAL_URL=https://relay.example.com",
		"ENS_GASLESS_ENABLED=true")
	cfg := resolveWithEnvFile(t, path)

	f := ensGaslessFeature(cfg)
	if f.State != stateBlocked {
		t.Fatalf("ens-gasless state = %q, want blocked on the embedded provider", f.State)
	}
	if !strings.Contains(f.Missing, "DNSSEC") {
		t.Fatalf("missing = %q, want it to name the DNSSEC limitation", f.Missing)
	}
}

func TestENSGaslessEnabledOnManagedProvider(t *testing.T) {
	path := writeEnvFile(t,
		"PORTAL_URL=https://relay.example.com",
		"ACME_DNS_PROVIDER=cloudflare",
		"CLOUDFLARE_TOKEN=token",
		"ENS_GASLESS_ENABLED=true")
	cfg := resolveWithEnvFile(t, path)

	if f := ensGaslessFeature(cfg); f.State != stateEnabled {
		t.Fatalf("ens-gasless state = %q (%s), want enabled", f.State, f.Missing)
	}
}
