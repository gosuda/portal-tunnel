package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
