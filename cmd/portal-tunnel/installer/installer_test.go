package installer

import (
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestRelayScriptInjectsTrustedReleaseVerificationEnv(t *testing.T) {
	t.Parallel()

	shellScript, filename, _, err := RelayScript("https://relay.example.com", false)
	if err != nil {
		t.Fatalf("RelayScript(shell) error = %v", err)
	}
	if filename != "install.sh" {
		t.Fatalf("filename = %q; want install.sh", filename)
	}
	for _, want := range []string{
		"BASE_URL='https://relay.example.com'",
		"BIN_PATH_PREFIX='api/install/bin'",
		"RELEASE_VERSION=" + quoteShellValue(types.ReleaseVersion),
		"TRUSTED_RELEASE_BASE_URL=" + quoteShellValue(types.OfficialReleaseBaseURL),
	} {
		if !strings.Contains(shellScript, want) {
			t.Fatalf("shell script missing %q", want)
		}
	}

	psScript, psFilename, _, err := RelayScript("https://relay.example.com", true)
	if err != nil {
		t.Fatalf("RelayScript(powershell) error = %v", err)
	}
	if psFilename != "install.ps1" {
		t.Fatalf("filename = %q; want install.ps1", psFilename)
	}
	for _, want := range []string{
		"$env:BASE_URL = 'https://relay.example.com'",
		"$env:BIN_PATH_PREFIX = 'api/install/bin'",
		"$env:RELEASE_VERSION = " + quotePowerShellValue(types.ReleaseVersion),
		"$env:TRUSTED_RELEASE_BASE_URL = " + quotePowerShellValue(types.OfficialReleaseBaseURL),
	} {
		if !strings.Contains(psScript, want) {
			t.Fatalf("powershell script missing %q", want)
		}
	}
}
