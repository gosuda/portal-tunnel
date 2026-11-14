package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/internal/cli"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/agent"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/agent/service"
)

var errWaitPortalAgentShutdownAgentStill = errors.New("wait for portal agent shutdown: agent is still running")

var errPortalAgentStoppedBeforeDashboard = errors.New("portal agent stopped before dashboard was ready")

func runAgentCommand(args []string) error {
	return cli.RunCommands(args, os.Stdout, os.Stderr, printAgentUsage, map[string]cli.CommandFunc{
		"run":       runAgentRunCommand,
		"dashboard": runAgentDashboardCommand,
		"stop":      runAgentStopCommand,
		"restart":   runAgentRestartCommand,
		"help": cli.MakeHelpCommand(printAgentUsage, []cli.HelpTopic{
			{Name: "run", Usage: printAgentRunUsage},
			{Name: "dashboard", Usage: printAgentDashboardUsage},
			{Name: "stop", Usage: printAgentStopUsage},
			{Name: "restart", Usage: printAgentRestartUsage},
		}),
	})
}

func runAgentRunCommand(args []string) error {
	configPath, serviceMode, foreground, theme, err := parseAgentRunArgs(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	cfg, err := agent.LoadExistingConfig(configPath)
	if err != nil {
		return err
	}
	if serviceMode {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
		defer stop()
		return service.Run(ctx, cfg.Agent.ServiceName, func(ctx context.Context) error {
			return agent.Run(ctx, cfg)
		})
	}
	if foreground {
		return runAgentForeground(configPath, cfg, theme)
	}
	return startAgentRunService(configPath, cfg)
}

func parseAgentRunArgs(args []string) (string, bool, bool, string, error) {
	env := cli.NewEnv(os.Environ())
	var configPath string
	var serviceMode bool
	var foreground bool
	var theme string
	fs := cli.NewFlagSet("agent run", printAgentRunUsage)
	fs.StringVar(&configPath, "config", service.DefaultConfigPath(), "Portal agent TOML config path")
	fs.BoolVar(&serviceMode, "service", false, "Run the foreground service process")
	fs.BoolVar(&foreground, "foreground", false, "Run in the current process without installing the OS service")
	env.String(fs, &theme, "theme", agent.DefaultDashboardTheme, "Dashboard color theme with --foreground: amber or green", "PORTAL_TUI_THEME")
	if err := cli.ParseFlagSet(fs, args, printAgentRunUsage); err != nil {
		return "", false, false, "", err
	}
	if err := cli.RequireNoArgs(fs.Args(), "agent run"); err != nil {
		printAgentRunUsage(os.Stderr)
		return "", false, false, "", err
	}
	if foreground && !serviceMode && agentCLIInteractive() {
		if err := validateDashboardTheme(fs, theme); err != nil {
			return "", false, false, "", err
		}
	}
	return configPath, serviceMode, foreground, theme, nil
}

func startAgentRunService(configPath string, cfg agent.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, err := startAgentService(ctx, configPath, cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Portal agent running at %s with %d tunnel(s).\n", status.ControlAddr, len(status.Tunnels))
	return nil
}

func runAgentRestartCommand(args []string) error {
	configPath, cfg, err := loadRunAgentRestartCommandConfig(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	stopRunAgentRestartCommandService(ctx, cfg)
	if err := waitAgentStopped(ctx, cfg.Agent.StateDir); err != nil {
		return err
	}
	status, err := startAgentService(ctx, configPath, cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Portal agent restarted at %s with %d tunnel(s).\n", status.ControlAddr, len(status.Tunnels))
	return nil
}

func loadRunAgentRestartCommandConfig(args []string) (string, agent.Config, error) {
	var configPath string
	fs := cli.NewFlagSet("agent restart", printAgentRestartUsage)
	fs.StringVar(&configPath, "config", "", "Portal agent TOML config path")
	if err := cli.ParseFlagSet(fs, args, printAgentRestartUsage); err != nil {
		return "", agent.Config{}, err
	}
	if err := cli.RequireNoArgs(fs.Args(), "agent restart"); err != nil {
		printAgentRestartUsage(os.Stderr)
		return "", agent.Config{}, err
	}
	if strings.TrimSpace(configPath) == "" {
		configPath = service.DefaultConfigPath()
	}
	cfg, err := agent.LoadExistingConfig(configPath)
	if err != nil {
		return "", agent.Config{}, err
	}
	return configPath, cfg, nil
}

func stopRunAgentRestartCommandService(ctx context.Context, cfg agent.Config) {
	shutdownErr := agent.Shutdown(ctx, cfg.Agent.StateDir)
	if err := service.Stop(ctx, cfg.Agent.ServiceName); err != nil {
		if shutdownErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: existing agent stop failed: %v\n", errors.Join(shutdownErr, err))
		} else {
			fmt.Fprintf(os.Stderr, "Warning: service manager stop failed: %v\n", err)
		}
	}
}

func startAgentService(ctx context.Context, configPath string, cfg agent.Config) (agent.AgentStatusResponse, error) {
	resolvedConfigPath, executable, err := resolveStartAgentServicePaths(configPath)
	if err != nil {
		return agent.AgentStatusResponse{}, err
	}
	def := service.Definition{
		Name:        strings.TrimSpace(cfg.Agent.ServiceName),
		DisplayName: "Portal Agent",
		Description: "Manages Portal tunnel definitions and relay membership.",
		Executable:  executable,
		Args:        []string{"agent", "run", "--service", "--config", resolvedConfigPath},
		WorkingDir:  filepath.Dir(resolvedConfigPath),
	}
	if err := installStartAgentService(ctx, def, cfg.Agent.ServiceName); err != nil {
		return agent.AgentStatusResponse{}, err
	}
	return waitAgentStatus(ctx, cfg.Agent.StateDir)
}

func resolveStartAgentServicePaths(configPath string) (string, string, error) {
	resolvedConfigPath, err := filepath.Abs(strings.TrimSpace(configPath))
	if err != nil {
		return "", "", err
	}
	executable, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return "", "", err
	}
	return resolvedConfigPath, executable, nil
}

func installStartAgentService(ctx context.Context, def service.Definition, serviceName string) error {
	if err := service.Install(ctx, def); err != nil {
		return fmt.Errorf("install portal agent service: %w; use --foreground when the OS service manager is unavailable", err)
	}
	if err := service.Start(ctx, serviceName); err != nil {
		return fmt.Errorf("start portal agent service: %w; use --foreground when the OS service manager is unavailable", err)
	}
	return nil
}

func runAgentForeground(configPath string, cfg agent.Config, theme string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	if !agentCLIInteractive() {
		return agent.Run(ctx, cfg)
	}
	resolvedConfigPath, restoreLogs, errCh, err := startForegroundAgent(ctx, configPath, cfg)
	if err != nil {
		return err
	}
	defer restoreLogs()
	if err := waitRunAgentForegroundReady(ctx, cfg.Agent.StateDir, errCh); err != nil {
		stop()
		return err
	}
	dashboardErr := agent.RunDashboard(resolvedConfigPath, cfg.Agent.StateDir, theme, true)
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

func startForegroundAgent(ctx context.Context, configPath string, cfg agent.Config) (string, func(), <-chan error, error) {
	resolvedConfigPath, err := filepath.Abs(strings.TrimSpace(configPath))
	if err != nil {
		return "", nil, nil, err
	}
	restoreLogs := suppressTerminalLogs()
	errCh := make(chan error, 1)
	go func() {
		errCh <- agent.Run(ctx, cfg)
	}()
	return resolvedConfigPath, restoreLogs, errCh, nil
}

func waitRunAgentForegroundReady(ctx context.Context, stateDir string, errCh <-chan error) error {
	readyCtx, readyCancel := context.WithTimeout(ctx, 15*time.Second)
	defer readyCancel()
	return waitAgentStatusOrExit(readyCtx, stateDir, errCh)
}

func runAgentStopCommand(args []string) error {
	configPath, stateDir, err := parseRunAgentStopCommandArgs(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	cfg, err := resolveRunAgentStopCommandConfig(configPath, stateDir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return shutdownRunAgentStopCommand(ctx, cfg)
}

func parseRunAgentStopCommandArgs(args []string) (string, string, error) {
	var configPath string
	var stateDir string
	fs := cli.NewFlagSet("agent stop", printAgentStopUsage)
	fs.StringVar(&configPath, "config", "", "Portal agent TOML config path")
	fs.StringVar(&stateDir, "state-dir", "", "Portal agent state directory")
	if err := cli.ParseFlagSet(fs, args, printAgentStopUsage); err != nil {
		return "", "", err
	}
	if err := cli.RequireNoArgs(fs.Args(), "agent stop"); err != nil {
		printAgentStopUsage(os.Stderr)
		return "", "", err
	}
	return strings.TrimSpace(configPath), strings.TrimSpace(stateDir), nil
}

func resolveRunAgentStopCommandConfig(configPath, stateDir string) (agent.Config, error) {
	cfg := agent.Config{Agent: agent.AgentConfig{ServiceName: agent.DefaultServiceName}}
	if configPath != "" || stateDir == "" {
		configPath = cmp.Or(configPath, service.DefaultConfigPath())
		var err error
		cfg, err = agent.LoadExistingConfig(configPath)
		if err != nil {
			return agent.Config{}, err
		}
	}
	if stateDir != "" {
		cfg.Agent.StateDir = stateDir
	}
	return cfg, nil
}

func shutdownRunAgentStopCommand(ctx context.Context, cfg agent.Config) error {
	shutdownErr := agent.Shutdown(ctx, cfg.Agent.StateDir)
	serviceErr := service.StopDisable(ctx, cfg.Agent.ServiceName)
	if errors.Is(shutdownErr, agent.ErrNotRunning) {
		if serviceErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: agent is not running, but service manager cleanup failed: %v\n", serviceErr)
		}
		fmt.Fprintln(os.Stdout, "Portal agent is not running.")
		return nil
	}
	if shutdownErr != nil {
		return fmt.Errorf("stop portal agent: %w", errors.Join(shutdownErr, serviceErr))
	}
	if err := waitAgentStopped(ctx, cfg.Agent.StateDir); err != nil {
		return fmt.Errorf("stop portal agent: %w", errors.Join(err, serviceErr))
	}
	if serviceErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: agent stopped, but service manager cleanup failed: %v\n", serviceErr)
	}
	fmt.Fprintln(os.Stdout, "Portal agent stopped.")
	return nil
}

func runAgentDashboardCommand(args []string) error {
	configPath, stateDir, theme, err := parseRunAgentDashboardCommandArgs(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	resolvedStateDir, err := resolveDashboardStateDir(configPath, stateDir)
	if err != nil {
		return err
	}
	return agent.RunDashboard(configPath, resolvedStateDir, theme, false)
}

func parseRunAgentDashboardCommandArgs(args []string) (string, string, string, error) {
	env := cli.NewEnv(os.Environ())
	var configPath string
	var stateDir string
	var theme string
	fs := cli.NewFlagSet("agent dashboard", printAgentDashboardUsage)
	fs.StringVar(&configPath, "config", "", "Portal agent TOML config path")
	fs.StringVar(&stateDir, "state-dir", "", "Portal agent state directory")
	env.String(fs, &theme, "theme", agent.DefaultDashboardTheme, "Dashboard color theme: amber or green", "PORTAL_TUI_THEME")
	if err := cli.ParseFlagSet(fs, args, printAgentDashboardUsage); err != nil {
		return "", "", "", err
	}
	if err := cli.RequireNoArgs(fs.Args(), "agent dashboard"); err != nil {
		printAgentDashboardUsage(os.Stderr)
		return "", "", "", err
	}
	if err := validateDashboardTheme(fs, theme); err != nil {
		return "", "", "", err
	}
	configPath = strings.TrimSpace(configPath)
	stateDir = strings.TrimSpace(stateDir)
	return cmp.Or(configPath, service.DefaultConfigPath()), stateDir, theme, nil
}

func resolveDashboardStateDir(configPath, stateDir string) (string, error) {
	if stateDir != "" {
		return stateDir, nil
	}
	_, statErr := os.Stat(configPath)
	if statErr == nil {
		cfg, err := agent.LoadExistingConfig(configPath)
		if err != nil {
			return "", err
		}
		return cfg.Agent.StateDir, nil
	}
	if errors.Is(statErr, os.ErrNotExist) {
		return service.DefaultDataDir(), nil
	}
	return "", statErr
}

func validateDashboardTheme(fs *flag.FlagSet, theme string) error {
	err := agent.ValidateDashboardTheme(theme)
	if err == nil {
		return nil
	}
	source := "PORTAL_TUI_THEME"
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "theme" {
			source = "--theme"
		}
	})
	return fmt.Errorf("invalid dashboard theme from %s: %w", source, err)
}

func waitAgentStatus(ctx context.Context, stateDir string) (agent.AgentStatusResponse, error) {
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
			return agent.AgentStatusResponse{}, fmt.Errorf("wait for portal agent status: %w", lastErr)
		case <-ticker.C:
		}
	}
}

func waitAgentStopped(ctx context.Context, stateDir string) error {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, err := agent.Status(ctx, stateDir)
		if err != nil {
			if errors.Is(err, agent.ErrNotRunning) {
				return nil
			}
			return fmt.Errorf("check portal agent status while waiting for shutdown: %w", err)
		}
		select {
		case <-ctx.Done():
			return errWaitPortalAgentShutdownAgentStill
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
			return wrapWaitAgentStatusOrExitStopped(err)
		default:
		}

		_, err := agent.Status(ctx, stateDir)
		if err == nil {
			return nil
		}
		lastErr = err
		select {
		case err := <-errCh:
			return wrapWaitAgentStatusOrExitStopped(err)
		case <-ctx.Done():
			return fmt.Errorf("wait for portal agent status: %w", lastErr)
		case <-ticker.C:
		}
	}
}

func wrapWaitAgentStatusOrExitStopped(err error) error {
	if err == nil {
		return errPortalAgentStoppedBeforeDashboard
	}
	return err
}

func agentCLIInteractive() bool {
	stdin, err := os.Stdin.Stat()
	if err != nil || stdin.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	stdout, err := os.Stdout.Stat()
	return err == nil && stdout.Mode()&os.ModeCharDevice != 0
}

func suppressTerminalLogs() func() {
	previous := log.Logger
	log.Logger = zerolog.New(io.Discard)
	return func() {
		log.Logger = previous
	}
}

func printAgentUsage(w io.Writer) {
	cli.WriteCommandUsage(w,
		[]string{
			"portal agent run [flags]",
			"portal agent dashboard [flags]",
			"portal agent stop [flags]",
			"portal agent restart [flags]",
		},
		[]string{
			"portal agent run",
			"portal agent run --config config.toml --foreground",
			"portal agent dashboard",
			"portal agent stop",
			"portal agent restart",
		},
	)
}

func printAgentRunUsage(w io.Writer) {
	cli.WriteCommandUsage(w,
		[]string{"portal agent run [flags]"},
		[]string{
			"portal agent run",
			"portal agent run --config config.toml --foreground",
			"portal agent run --foreground --theme green",
		},
	)
}

func printAgentDashboardUsage(w io.Writer) {
	cli.WriteCommandUsage(w,
		[]string{"portal agent dashboard [flags]"},
		[]string{
			"portal agent dashboard",
			"portal agent dashboard --config config.toml",
			"portal agent dashboard --theme green",
		},
	)
}

func printAgentStopUsage(w io.Writer) {
	cli.WriteCommandUsage(w,
		[]string{"portal agent stop [flags]"},
		[]string{
			"portal agent stop",
			"portal agent stop --config config.toml",
		},
	)
}

func printAgentRestartUsage(w io.Writer) {
	cli.WriteCommandUsage(w,
		[]string{"portal agent restart [flags]"},
		[]string{
			"portal agent restart",
			"portal agent restart --config config.toml",
		},
	)
}
