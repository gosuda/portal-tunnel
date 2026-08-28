//go:build linux

package service

import (
	"strings"
	"testing"
)

func TestSystemdUnitWorkingDirectoryIsAbsoluteAndUnquoted(t *testing.T) {
	t.Parallel()

	unit := systemdUnit(Definition{
		Name:        "portal-agent",
		Description: "Manages Portal tunnel definitions and relay membership.",
		Executable:  "/home/user/.local/bin/portal",
		Args: []string{
			"agent", "run", "--service",
			"--config", "/home/user/.config/portal-tunnel/agent/config.toml",
		},
		WorkingDir: "/home/user/.config/portal-tunnel/agent",
	})

	if !strings.Contains(unit, "WorkingDirectory=/home/user/.config/portal-tunnel/agent\n") {
		t.Fatalf("WorkingDirectory line missing or quoted:\n%s", unit)
	}
	if strings.Contains(unit, "WorkingDirectory='") {
		t.Fatal("WorkingDirectory must not use shell quotes; systemd 259 treats them as part of the path")
	}
	if !strings.Contains(unit, "ExecStart='/home/user/.local/bin/portal' 'agent' 'run'") {
		t.Fatalf("ExecStart should stay shell-quoted:\n%s", unit)
	}
}
