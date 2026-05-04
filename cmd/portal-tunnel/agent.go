package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/agent"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/agent/service"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func runAgentCommand(args []string) error {
	return utils.RunCommands(args, os.Stdout, os.Stderr, printAgentUsage, map[string]utils.CommandFunc{
		"run":       runAgentRunCommand,
		"dashboard": runAgentDashboardCommand,
		"stop":      runAgentStopCommand,
		"help": utils.MakeHelpCommand(printAgentUsage, []utils.HelpTopic{
			{Name: "run", Usage: printAgentRunUsage},
			{Name: "dashboard", Usage: printAgentDashboardUsage},
			{Name: "stop", Usage: printAgentStopUsage},
		}),
	})
}

func runAgentRunCommand(args []string) error {
	var configPath string
	var serviceMode bool
	var foreground bool
	fs := utils.NewFlagSet("agent run", printAgentRunUsage)
	utils.StringFlag(fs, &configPath, "config", service.DefaultConfigPath(), "Portal agent TOML config path")
	utils.BoolFlag(fs, &serviceMode, "service", false, "Run the foreground service process")
	utils.BoolFlag(fs, &foreground, "foreground", false, "Run in the current process without installing the OS service")
	if err := utils.ParseFlagSet(fs, args, printAgentRunUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := utils.RequireNoArgs(fs.Args(), "agent run"); err != nil {
		printAgentRunUsage(os.Stderr)
		return err
	}

	cfg, err := agent.LoadConfig(configPath)
	if err != nil {
		return err
	}
	if serviceMode {
		ctx, stop := utils.SignalContext()
		defer stop()
		return service.Run(ctx, cfg.Agent.ServiceName, func(ctx context.Context) error {
			return agent.Run(ctx, cfg)
		})
	}
	if foreground {
		return runAgentForeground(configPath, cfg)
	}

	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return err
	}
	configPath, err = filepath.Abs(strings.TrimSpace(configPath))
	if err != nil {
		return err
	}
	def := service.Definition{
		Name:        strings.TrimSpace(cfg.Agent.ServiceName),
		DisplayName: "Portal Agent",
		Description: "Manages Portal tunnel definitions and relay membership.",
		Executable:  executable,
		Args:        []string{"agent", "run", "--service", "--config", configPath},
		WorkingDir:  filepath.Dir(configPath),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := service.Install(ctx, def); err != nil {
		return fmt.Errorf("install portal agent service: %w; use --foreground when the OS service manager is unavailable", err)
	}
	if err := service.Start(ctx, cfg.Agent.ServiceName); err != nil {
		return fmt.Errorf("start portal agent service: %w; use --foreground when the OS service manager is unavailable", err)
	}
	status, err := waitAgentStatus(ctx, cfg.Agent.StateDir)
	if err != nil {
		return err
	}
	if agentCLIInteractive() {
		return agent.RunDashboard(configPath, cfg.Agent.StateDir)
	}

	fmt.Fprintf(os.Stdout, "Portal agent running at %s with %d tunnel(s).\n", status.ControlAddr, len(status.Tunnels))
	return nil
}

func runAgentForeground(configPath string, cfg agent.Config) error {
	ctx, stop := utils.SignalContext()
	defer stop()

	if !agentCLIInteractive() {
		return agent.Run(ctx, cfg)
	}

	resolvedConfigPath, err := filepath.Abs(strings.TrimSpace(configPath))
	if err != nil {
		return err
	}

	restoreLogs := suppressTerminalLogs()
	defer restoreLogs()

	errCh := make(chan error, 1)
	go func() {
		errCh <- agent.Run(ctx, cfg)
	}()

	readyCtx, readyCancel := context.WithTimeout(ctx, 15*time.Second)
	err = waitAgentStatusOrExit(readyCtx, cfg.Agent.StateDir, errCh)
	readyCancel()
	if err != nil {
		stop()
		return err
	}

	dashboardErr := agent.RunDashboard(resolvedConfigPath, cfg.Agent.StateDir)
	stop()
	runErr := <-errCh
	if errors.Is(runErr, context.Canceled) {
		runErr = nil
	}
	if dashboardErr != nil {
		return dashboardErr
	}
	if runErr != nil {
		return runErr
	}

	fmt.Fprintln(os.Stdout, "Portal agent stopped.")
	return nil
}

func suppressTerminalLogs() func() {
	previous := log.Logger
	log.Logger = zerolog.New(io.Discard)
	return func() {
		log.Logger = previous
	}
}

func runAgentStopCommand(args []string) error {
	var configPath string
	var stateDir string
	fs := utils.NewFlagSet("agent stop", printAgentStopUsage)
	utils.StringFlag(fs, &configPath, "config", "", "Portal agent TOML config path")
	utils.StringFlag(fs, &stateDir, "state-dir", "", "Portal agent state directory")
	if err := utils.ParseFlagSet(fs, args, printAgentStopUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := utils.RequireNoArgs(fs.Args(), "agent stop"); err != nil {
		printAgentStopUsage(os.Stderr)
		return err
	}

	cfg, resolvedStateDir, err := loadAgentCommandConfig(configPath, stateDir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_ = agent.Shutdown(ctx, resolvedStateDir)
	if err := service.StopDisable(ctx, cfg.Agent.ServiceName); err != nil {
		return fmt.Errorf("stop portal agent service: %w", err)
	}
	fmt.Fprintln(os.Stdout, "Portal agent stopped.")
	return nil
}

func runAgentDashboardCommand(args []string) error {
	var configPath string
	var stateDir string
	fs := utils.NewFlagSet("agent dashboard", printAgentDashboardUsage)
	utils.StringFlag(fs, &configPath, "config", "", "Portal agent TOML config path")
	utils.StringFlag(fs, &stateDir, "state-dir", "", "Portal agent state directory")
	if err := utils.ParseFlagSet(fs, args, printAgentDashboardUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := utils.RequireNoArgs(fs.Args(), "agent dashboard"); err != nil {
		printAgentDashboardUsage(os.Stderr)
		return err
	}

	_, resolvedStateDir, err := loadAgentCommandConfig(configPath, stateDir)
	if err != nil {
		return err
	}
	if strings.TrimSpace(configPath) == "" {
		configPath = service.DefaultConfigPath()
	}
	return agent.RunDashboard(configPath, resolvedStateDir)
}

func waitAgentStatus(ctx context.Context, stateDir string) (types.AgentStatusResponse, error) {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		status, err := agent.Status(ctx, stateDir)
		if err == nil {
			return status, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return types.AgentStatusResponse{}, fmt.Errorf("wait for portal agent status: %w", lastErr)
		case <-ticker.C:
		}
	}
}

func waitAgentStatusOrExit(ctx context.Context, stateDir string, errCh <-chan error) error {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		select {
		case err := <-errCh:
			if err == nil {
				err = errors.New("portal agent stopped before dashboard was ready")
			}
			return err
		default:
		}

		_, err := agent.Status(ctx, stateDir)
		if err == nil {
			return nil
		}
		lastErr = err
		select {
		case err := <-errCh:
			if err == nil {
				err = errors.New("portal agent stopped before dashboard was ready")
			}
			return err
		case <-ctx.Done():
			return fmt.Errorf("wait for portal agent status: %w", lastErr)
		case <-ticker.C:
		}
	}
}

func agentCLIInteractive() bool {
	stdin, err := os.Stdin.Stat()
	if err != nil || stdin.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	stdout, err := os.Stdout.Stat()
	return err == nil && stdout.Mode()&os.ModeCharDevice != 0
}

func loadAgentCommandConfig(configPath, stateDir string) (agent.Config, string, error) {
	if stateDir != "" && configPath == "" {
		cfg := agent.Config{Agent: agent.AgentConfig{StateDir: stateDir, ServiceName: agent.DefaultServiceName}}
		return cfg, stateDir, nil
	}
	if configPath != "" {
		cfg, err := agent.LoadConfig(configPath)
		if err != nil {
			return agent.Config{}, "", err
		}
		if stateDir != "" {
			cfg.Agent.StateDir = stateDir
		}
		return cfg, cfg.Agent.StateDir, nil
	}
	defaultStateDir := service.DefaultDataDir()
	cfg := agent.Config{Agent: agent.AgentConfig{StateDir: defaultStateDir, ServiceName: agent.DefaultServiceName}}
	return cfg, defaultStateDir, nil
}

func printAgentUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
		[]string{
			"portal agent run [flags]",
			"portal agent dashboard [flags]",
			"portal agent stop [flags]",
		},
		[]string{
			"portal agent run",
			"portal agent run --config config.toml --foreground",
			"portal agent dashboard",
			"portal agent stop",
		},
	)
}

func printAgentRunUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
		[]string{"portal agent run [flags]"},
		[]string{
			"portal agent run",
			"portal agent run --config config.toml --foreground",
		},
	)
}

func printAgentDashboardUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
		[]string{"portal agent dashboard [flags]"},
		[]string{
			"portal agent dashboard",
			"portal agent dashboard --config config.toml",
		},
	)
}

func printAgentStopUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
		[]string{"portal agent stop [flags]"},
		[]string{
			"portal agent stop",
			"portal agent stop --config config.toml",
		},
	)
}
