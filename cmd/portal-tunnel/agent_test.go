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

// The agent starts before the dashboard opens, so `agent run --foreground` has to refuse an
// unknown theme first. The config is missing, so reaching it would fail with another error.
func TestAgentRunForegroundRefusesUnknownThemeBeforeStarting(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "config.toml")
	err := runAgentRunCommand([]string{"--config", missing, "--foreground", "--theme", "purple"})
	if err == nil {
		t.Fatal("expected an error for an unknown theme")
	}
	for _, want := range []string{"--theme", "purple", "amber", "green"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q should mention %q", err, want)
		}
	}
}
