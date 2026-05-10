//go:build darwin

package service

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func Install(ctx context.Context, def Definition) error {
	plistPath, domain, err := launchdPlistPath(def.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(plistPath, []byte(launchdPlist(def)), 0o644); err != nil {
		return err
	}
	_ = exec.CommandContext(ctx, "launchctl", "bootout", domain, plistPath).Run()
	return exec.CommandContext(ctx, "launchctl", "bootstrap", domain, plistPath).Run()
}

func Start(ctx context.Context, name string) error {
	_, domain, err := launchdPlistPath(name)
	if err != nil {
		return err
	}
	return exec.CommandContext(ctx, "launchctl", "kickstart", "-k", domain+"/"+name).Run()
}

func Stop(ctx context.Context, name string) error {
	plistPath, domain, err := launchdPlistPath(name)
	if err != nil {
		return err
	}
	return exec.CommandContext(ctx, "launchctl", "bootout", domain, plistPath).Run()
}

func StopDisable(ctx context.Context, name string) error {
	plistPath, domain, err := launchdPlistPath(name)
	if err != nil {
		return err
	}
	_ = exec.CommandContext(ctx, "launchctl", "disable", domain+"/"+name).Run()
	return exec.CommandContext(ctx, "launchctl", "bootout", domain, plistPath).Run()
}

func Run(ctx context.Context, name string, run func(context.Context) error) error {
	return run(ctx)
}

func launchdPlistPath(name string) (string, string, error) {
	if os.Geteuid() == 0 {
		return filepath.Join("/Library/LaunchDaemons", name+".plist"), "system", nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", name+".plist"), fmt.Sprintf("gui/%d", os.Getuid()), nil
}

func launchdPlist(def Definition) string {
	args := append([]string{def.Executable}, def.Args...)
	argXML := ""
	for _, arg := range args {
		argXML += "\n    <string>" + xmlEscape(arg) + "</string>"
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>ProgramArguments</key>
  <array>%s
  </array>
  <key>WorkingDirectory</key>
  <string>%s</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
`, xmlEscape(def.Name), argXML, xmlEscape(def.WorkingDir))
}

func xmlEscape(value string) string {
	var out []byte
	xml.EscapeText((*appendWriter)(&out), []byte(value))
	return string(out)
}

type appendWriter []byte

func (w *appendWriter) Write(p []byte) (int, error) {
	*w = append(*w, p...)
	return len(p), nil
}
