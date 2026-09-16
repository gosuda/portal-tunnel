package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	cfg = resolveWithEnvFile(t, writeEnvFile(t))
	if cfg.Relay.HTTPRedirect.Enabled || cfg.Relay.HTTPRedirect.HSTS || cfg.Relay.HTTPRedirect.Addr != types.DefaultHTTPRedirectAddr {
		t.Fatalf("unexpected redirect defaults: %+v", cfg)
	}
}

// A variable absent from the env file must not leak in from the surrounding
// shell, or the report would describe a mixed environment.
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

// A line that is neither blank, a comment, nor an assignment is invalid input.
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
