package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal"
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

// resolveWithEnvFile uses the file values as the entire input environment and
// returns the resulting configuration.
func resolveWithEnvFile(t *testing.T, path string) appConfig {
	t.Helper()
	entries, err := loadEnvFile(path)
	if err != nil {
		t.Fatalf("load env file: %v", err)
	}
	var environ []string
	for _, entry := range entries {
		environ = append(environ, entry.Name+"="+entry.Value)
	}
	cfg, _, err := resolveAppConfig(nil, environ)
	if err != nil {
		t.Fatalf("resolve config: %v", err)
	}
	return cfg
}

func TestHTTPRedirectEnvironment(t *testing.T) {
	cfg := resolveWithEnvFile(t, writeEnvFile(t,
		"HTTP_REDIRECT_ENABLED=true", "HTTP_REDIRECT_ADDR=127.0.0.1:18080", "HTTP_REDIRECT_HSTS=true"))
	if !cfg.Relay.HTTPRedirect.Enabled || cfg.Relay.HTTPRedirect.Addr != "127.0.0.1:18080" || !cfg.Relay.HTTPRedirect.HSTS {
		t.Fatalf("redirect environment not resolved: %+v", cfg)
	}
	cfg = resolveWithEnvFile(t, writeEnvFile(t))
	if cfg.Relay.HTTPRedirect.Enabled || cfg.Relay.HTTPRedirect.HSTS || cfg.Relay.HTTPRedirect.Addr != portal.DefaultHTTPRedirectAddr {
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

func TestConfigResolutionDoesNotChangeEnvironment(t *testing.T) {
	t.Setenv("DISCOVERY", "true")
	t.Setenv("BOOTSTRAPS", "https://inherited.example.com")
	cfg := resolveWithEnvFile(t, writeEnvFile(t, "BOOTSTRAPS=https://file.example.com"))
	if cfg.Relay.DiscoveryEnabled || len(cfg.Relay.Bootstraps) != 1 || cfg.Relay.Bootstraps[0] != "https://file.example.com" {
		t.Fatalf("file did not resolve independently: %+v", cfg.Relay)
	}
	if os.Getenv("DISCOVERY") != "true" || os.Getenv("BOOTSTRAPS") != "https://inherited.example.com" {
		t.Fatal("reading the file changed the process environment")
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

// A key the env file supplies that nothing reads must be surfaced with a
// closest-match suggestion, not silently dropped: that silence is how a typo
// runs the relay on defaults while the operator believes their value is set.
func TestConfigReportSurfacesUnknownEnvFileKeys(t *testing.T) {
	path := writeEnvFile(t, "PORTAL_URL=https://relay.example.com", "DISCOVRY=true")
	entries, err := loadEnvFile(path)
	if err != nil {
		t.Fatalf("load env file: %v", err)
	}
	var environ []string
	for _, entry := range entries {
		environ = append(environ, entry.Name+"="+entry.Value)
	}
	cfg, env, err := resolveAppConfig(nil, environ)
	if err != nil {
		t.Fatalf("resolve config: %v", err)
	}
	var report strings.Builder
	writeConfigReport(&report, cfg, entries, path, env)
	for _, want := range []string{"DISCOVRY", "did you mean DISCOVERY?"} {
		if !strings.Contains(report.String(), want) {
			t.Fatalf("config report missing %q:\n%s", want, report.String())
		}
	}
}

func TestConfigReportRejectsInvalidEnvironment(t *testing.T) {
	cfg, env, err := resolveAppConfig(nil, []string{"DISCOVERY=invalid"})
	if err != nil {
		t.Fatal(err)
	}
	var report strings.Builder
	writeConfigReport(&report, cfg, nil, "process environment", env)
	if !strings.Contains(report.String(), "INVALID") || strings.Contains(report.String(), "OK relay configuration is valid") {
		t.Fatalf("invalid environment was reported as valid:\n%s", report.String())
	}
}

func TestPreparedConfigRetainsPortalDefaults(t *testing.T) {
	cfg, env, err := resolveAppConfig(nil, []string{"PORTAL_URL=https://localhost:8443", "IDENTITY_PATH=./state"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareAppConfig(&cfg, env.Issues); err != nil {
		t.Fatal(err)
	}
	if cfg.Relay.SNIPort != 8443 || cfg.Relay.SNIListenAddr != ":8443" || cfg.Relay.ACME.KeyDir != cfg.Relay.StateDir {
		t.Fatalf("normalized defaults were discarded: %+v", cfg.Relay)
	}
}
