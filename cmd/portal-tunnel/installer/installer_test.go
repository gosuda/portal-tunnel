package installer

import (
	"strings"
	"testing"
)

func TestRelayScript_NormalizesCRLFInShellScript(t *testing.T) {
	script, filename, contentType, err := RelayScript("https://relay.example.com", false)
	if err != nil {
		t.Fatalf("RelayScript failed: %v", err)
	}
	if filename != "install.sh" {
		t.Errorf("expected install.sh, got %q", filename)
	}
	if contentType != "text/x-shellscript" {
		t.Errorf("expected text/x-shellscript, got %q", contentType)
	}
	if strings.Contains(script, "\r") {
		t.Errorf("expected shell script to contain no carriage returns (\\r), but found one")
	}
	if !strings.Contains(script, "BASE_URL='https://relay.example.com'") {
		t.Errorf("expected script to contain BASE_URL override")
	}
}

func TestRelayShellScript_StripCRLF(t *testing.T) {
	input := "#!/usr/bin/env sh\r\nset -eu\r\necho hello\r\n"
	result := relayShellScript("https://test.com", input)
	if strings.Contains(result, "\r") {
		t.Errorf("expected result to have no \\r, got: %q", result)
	}
	expectedPrefix := "#!/usr/bin/env sh\nBASE_URL='https://test.com'\n"
	if !strings.HasPrefix(result, expectedPrefix) {
		t.Errorf("expected prefix %q, got %q", expectedPrefix, result[:len(expectedPrefix)])
	}
}

func TestRelayScript_PowerShell(t *testing.T) {
	script, filename, contentType, err := RelayScript("https://relay.example.com", true)
	if err != nil {
		t.Fatalf("RelayScript failed: %v", err)
	}
	if filename != "install.ps1" {
		t.Errorf("expected install.ps1, got %q", filename)
	}
	if contentType != "text/plain; charset=utf-8" {
		t.Errorf("expected text/plain; charset=utf-8, got %q", contentType)
	}
	if !strings.Contains(script, "$env:BASE_URL = 'https://relay.example.com'") {
		t.Errorf("expected powershell script to contain BASE_URL override")
	}
}

func TestRelayScript_EmptyPortalURL(t *testing.T) {
	_, _, _, err := RelayScript("   ", false)
	if err != errPortalURLIsRequired {
		t.Errorf("expected errPortalURLIsRequired, got %v", err)
	}
}
