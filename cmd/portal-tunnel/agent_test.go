package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func verifyUnknownThemeError(t *testing.T, err error, source string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error for an unknown theme")
		return
	}
	if !strings.HasPrefix(err.Error(), "invalid dashboard theme from "+source) {
		t.Fatalf("error %q should name %s", err, source)
	}
	for _, want := range []string{"purple", "amber", "green"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q should mention %q", err, want)
		}
	}
}

func TestAgentDashboardRefusesUnknownTheme(t *testing.T) {
	stateDir := t.TempDir()
	tests := []struct {
		name   string
		env    string
		args   []string
		source string
	}{
		{"flag", "", []string{"--state-dir", stateDir, "--theme", "purple"}, "--theme"},
		{"environment", "purple", []string{"--state-dir", stateDir}, "PORTAL_TUI_THEME"},
		{"flag wins over a valid environment", "green", []string{"--state-dir", stateDir, "--theme", "purple"}, "--theme"},
		{"flag wins over an unknown environment", "purple", []string{"--state-dir", stateDir, "--theme", "purple"}, "--theme"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PORTAL_TUI_THEME", tt.env)
			verifyUnknownThemeError(t, runAgentDashboardCommand(tt.args), tt.source)
		})
	}
}

func TestAgentRunForegroundWithoutTerminalIgnoresTheTheme(t *testing.T) {
	if agentCLIInteractive() {
		t.Skip("stdin and stdout are a terminal, so the run would open the dashboard")
	}
	missing := filepath.Join(t.TempDir(), "config.toml")
	err := runAgentRunCommand([]string{"--config", missing, "--foreground", "--theme", "purple"})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("error = %v, want the missing config, not the theme", err)
	}
}
