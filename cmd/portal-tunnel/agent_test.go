package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// An unknown dashboard theme is refused before the dashboard takes over the terminal,
// whether it came from --theme or from PORTAL_TUI_THEME.
func TestAgentDashboardRefusesUnknownTheme(t *testing.T) {
	stateDir := t.TempDir()
	tests := []struct {
		name string
		env  string
		args []string
	}{
		{"flag", "", []string{"--state-dir", stateDir, "--theme", "purple"}},
		{"environment", "purple", []string{"--state-dir", stateDir}},
		{"flag wins over a valid environment", "green", []string{"--state-dir", stateDir, "--theme", "purple"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PORTAL_TUI_THEME", tt.env)
			err := runAgentDashboardCommand(tt.args)
			if err == nil {
				t.Fatal("expected an error for an unknown theme")
			}
			for _, want := range []string{"--theme", "purple", "amber", "green"} {
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
