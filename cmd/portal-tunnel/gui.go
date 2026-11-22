package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/gosuda/portal-tunnel/v2/cmd/internal/cli"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/installer"
)

var errDesktopNeedsDisplay = errors.New("portal desktop needs an X11 or XWayland display, and DISPLAY is not set; run portal gui in a desktop session")

// runGUICommand opens Portal Desktop, installed with this CLI. It installs
// nothing and does not touch the agent: the desktop finds the running agent
// itself, and closing it leaves the agent running.
func runGUICommand(args []string) error {
	var configPath string
	fs := cli.NewFlagSet("gui", printGUIUsage)
	fs.StringVar(&configPath, "config", "", "Portal agent TOML config path for Portal Desktop; defaults to the agent's default config")
	if err := cli.ParseFlagSet(fs, args, printGUIUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := cli.RequireNoArgs(fs.Args(), "gui"); err != nil {
		printGUIUsage(os.Stderr)
		return err
	}
	cliPath, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(cliPath); err == nil {
		cliPath = resolved
	}
	desktop, ok := installer.Desktop(cliPath)
	if !ok {
		return fmt.Errorf("portal desktop is not installed with this CLI; install both with: %s", installer.DesktopInstallCommand())
	}
	if runtime.GOOS == "linux" && os.Getenv("DISPLAY") == "" {
		return errDesktopNeedsDisplay
	}
	var desktopArgs []string
	if configPath != "" {
		abs, err := filepath.Abs(configPath)
		if err != nil {
			return err
		}
		desktopArgs = []string{"--config", abs}
	}
	if runtime.GOOS == "darwin" {
		// Launch Services starts the bundle as the app it is, or brings
		// forward the one already running.
		open := exec.CommandContext(context.Background(), "open", append([]string{desktop, "--args"}, desktopArgs...)...)
		if out, err := open.CombinedOutput(); err != nil {
			return fmt.Errorf("open %s: %w: %s", desktop, err, out)
		}
		return nil
	}
	desktopCmd := exec.CommandContext(context.Background(), desktop, desktopArgs...)
	if err := desktopCmd.Start(); err != nil {
		return fmt.Errorf("start portal desktop: %w", err)
	}
	return desktopCmd.Process.Release()
}

func printGUIUsage(w io.Writer) {
	cli.WriteCommandUsage(w,
		[]string{"portal gui [flags]"},
		[]string{"portal gui", "portal gui --config ./agent.toml"},
	)
}
