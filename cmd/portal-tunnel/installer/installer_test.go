package installer

import (
	"errors"
	"strings"
	"testing"
)

func TestRelayScriptShell(t *testing.T) {
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

func TestRelayShellScriptLineEndings(t *testing.T) {
	const script = "#!/usr/bin/env sh\nset -eu\necho hello\n"
	const expected = "#!/usr/bin/env sh\n" +
		"BASE_URL='https://relay.example.com'\n" +
		"RELAY_URL='https://relay.example.com'\n" +
		"BIN_PATH_PREFIX='api/install/bin'\n" +
		"set -eu\necho hello\n"
	for _, tc := range []struct {
		name, newline string
	}{
		{"LF", "\n"},
		{"CRLF", "\r\n"},
		{"CR", "\r"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.ReplaceAll(script, "\n", tc.newline)
			result := relayShellScript("https://relay.example.com", input)
			if result != expected {
				t.Errorf("normalized script = %q, want %q", result, expected)
			}
		})
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
	if !errors.Is(err, errPortalURLIsRequired) {
		t.Errorf("expected errPortalURLIsRequired, got %v", err)
	}
}
