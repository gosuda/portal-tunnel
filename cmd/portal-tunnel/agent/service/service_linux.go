//go:build linux

package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func Install(ctx context.Context, def Definition) error {
	unitPath, userMode, err := linuxUnitPath(def.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(unitPath, []byte(systemdUnit(def)), 0o644); err != nil {
		return err
	}
	if err := runSystemctl(ctx, userMode, "daemon-reload"); err != nil {
		return err
	}
	return runSystemctl(ctx, userMode, "enable", def.Name+".service")
}

func Start(ctx context.Context, name string) error {
	_, userMode, err := linuxUnitPath(name)
	if err != nil {
		return err
	}
	return runSystemctl(ctx, userMode, "start", name+".service")
}

func Stop(ctx context.Context, name string) error {
	_, userMode, err := linuxUnitPath(name)
	if err != nil {
		return err
	}
	return runSystemctl(ctx, userMode, "stop", name+".service")
}

func StopDisable(ctx context.Context, name string) error {
	_, userMode, err := linuxUnitPath(name)
	if err != nil {
		return err
	}
	return runSystemctl(ctx, userMode, "disable", "--now", name+".service")
}

func Run(ctx context.Context, name string, run func(context.Context) error) error {
	return run(ctx)
}

func linuxUnitPath(name string) (string, bool, error) {
	if os.Geteuid() == 0 {
		return filepath.Join("/etc/systemd/system", name+".service"), false, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false, err
	}
	return filepath.Join(home, ".config", "systemd", "user", name+".service"), true, nil
}

func systemctlArgs(userMode bool, args ...string) []string {
	if userMode {
		return append([]string{"--user"}, args...)
	}
	return args
}

func runSystemctl(ctx context.Context, userMode bool, args ...string) error {
	commandArgs := systemctlArgs(userMode, args...)
	output, err := exec.CommandContext(ctx, "systemctl", commandArgs...).CombinedOutput()
	if err == nil {
		return nil
	}
	message := "systemctl " + strings.Join(commandArgs, " ")
	if detail := strings.TrimSpace(string(output)); detail != "" {
		message += ": " + detail
	}
	if userMode {
		message += "; user systemd must be available for managed agent mode"
	}
	return fmt.Errorf("%s: %w", message, err)
}

func systemdUnit(def Definition) string {
	parts := append([]string{def.Executable}, def.Args...)
	for i := range parts {
		parts[i] = shellQuote(parts[i])
	}
	return fmt.Sprintf(`[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%s
ExecStart=%s
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`, def.Description, shellQuote(def.WorkingDir), strings.Join(parts, " "))
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
