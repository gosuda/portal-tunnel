package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// An unknown dashboard theme is refused before the dashboard takes over the terminal, and the
// error names where it came from: --theme or PORTAL_TUI_THEME.
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
			err := runAgentDashboardCommand(tt.args)
			if err == nil {
				t.Fatal("expected an error for an unknown theme")
			}
			if !strings.HasPrefix(err.Error(), tt.source+" ") {
				t.Fatalf("error %q should name %s", err, tt.source)
			}
			for _, want := range []string{"purple", "amber", "green"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q should mention %q", err, want)
				}
			}
		})
	}
}

// Without a terminal `agent run --foreground` runs the agent headless and opens no dashboard,
// so an unknown theme must not stop it. The config is missing, so the run stops there instead.
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
