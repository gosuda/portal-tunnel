package utils

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type CommandFunc func([]string) error
type IntEnvParser func(string, int) int
type boolFlagValue interface{ IsBoolFlag() bool }

// EnvVar records one environment variable that backs a flag, together with the
// flag's own documentation. Flag definitions already carry the name, default,
// and usage text, so registering them here lets `relay-server config`, the
// startup feature report, and the generated .env.example all read from the flag
// definitions instead of a second hand-maintained list.
type EnvVar struct {
	Name    string
	Aliases []string
	Flag    string
	Usage   string
	Default string
	// SetBy is the environment variable that supplied the value, or empty when
	// the default was used. It answers "I set that, why did nothing change?".
	SetBy string
}

// EnvIssue is a value that was present but unusable. Without recording these,
// the resolve helpers below silently fall back and a typo is indistinguishable
// from an intentional default.
type EnvIssue struct {
	Name    string
	Value   string
	Problem string
}

// The process environment is process-global, so the registry is too. Flag
// registration happens once per process before any concurrent work starts.
var (
	envVars     []EnvVar
	envVarIndex = map[string]int{}
	envIssues   []EnvIssue
)

// EnvVars returns every environment variable backing a registered flag, in
// registration order.
func EnvVars() []EnvVar {
	return slices.Clone(envVars)
}

// EnvIssues returns values that were set but could not be used.
func EnvIssues() []EnvIssue {
	return slices.Clone(envIssues)
}

func registerEnvVar(flagName, usage, defaultValue, setBy string, envNames []string) {
	names := make([]string, 0, len(envNames))
	for _, envName := range envNames {
		if envName = strings.TrimSpace(envName); envName != "" {
			names = append(names, envName)
		}
	}
	if len(names) == 0 {
		return
	}

	entry := EnvVar{
		Name:    names[0],
		Aliases: names[1:],
		Flag:    flagName,
		Usage:   usage,
		Default: defaultValue,
		SetBy:   setBy,
	}
	// Registering the same flag twice (a re-parsed command, a test) replaces the
	// entry rather than duplicating it.
	if i, ok := envVarIndex[entry.Name]; ok {
		envVars[i] = entry
		return
	}
	envVarIndex[entry.Name] = len(envVars)
	envVars = append(envVars, entry)
}

func recordEnvIssue(name, value, problem string) {
	envIssues = append(envIssues, EnvIssue{Name: name, Value: value, Problem: problem})
}

func trimmedEnv(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}

func resolveStringEnv(fallback string, envNames ...string) (string, string) {
	for _, envName := range envNames {
		if envValue := trimmedEnv(envName); envValue != "" {
			return envValue, envName
		}
	}
	return fallback, ""
}

func resolveBoolEnv(fallback bool, envNames ...string) (bool, string) {
	for _, envName := range envNames {
		raw := trimmedEnv(envName)
		if raw == "" {
			continue
		}
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			recordEnvIssue(envName, raw, "not a boolean; use true or false")
			return fallback, ""
		}
		return parsed, envName
	}
	return fallback, ""
}

func resolveIntEnv(fallback int, parse IntEnvParser, envNames ...string) (int, string) {
	if parse == nil {
		parse = func(raw string, fallback int) int {
			v, err := strconv.Atoi(strings.TrimSpace(raw))
			if err != nil {
				return fallback
			}
			return v
		}
	}
	for _, envName := range envNames {
		raw := trimmedEnv(envName)
		if raw == "" {
			continue
		}
		// Parse first so a non-numeric value is reported as such instead of
		// being flattened into the parser's fallback.
		number, err := strconv.Atoi(raw)
		if err != nil {
			recordEnvIssue(envName, raw, "not an integer")
			return fallback, ""
		}
		value := parse(raw, fallback)
		if value != number && value == fallback {
			recordEnvIssue(envName, raw, "out of the accepted range")
			return fallback, ""
		}
		return value, envName
	}
	return fallback, ""
}

func ParsePortNumber(raw string, fallback int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return fallback
	}
	return port
}

func ParseOptionalPortNumber(raw string, fallback int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	if raw == "0" {
		return 0
	}
	return ParsePortNumber(raw, fallback)
}

func DurationOrDefault(v, fallback time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return fallback
}

func IntOrDefault(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

func StringOrDefault(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

func StringFlag(fs *flag.FlagSet, target *string, name, fallback, usage string) {
	ensureFlagSet(fs).StringVar(target, name, fallback, usage)
}

func StringFlagEnv(fs *flag.FlagSet, target *string, name, fallback, usage string, envNames ...string) {
	value, setBy := resolveStringEnv(fallback, envNames...)
	registerEnvVar(name, usage, fallback, setBy, envNames)
	ensureFlagSet(fs).StringVar(target, name, value, flagUsage(usage, envNames...))
}

func BoolFlag(fs *flag.FlagSet, target *bool, name string, fallback bool, usage string) {
	ensureFlagSet(fs).BoolVar(target, name, fallback, usage)
}

func BoolFlagEnv(fs *flag.FlagSet, target *bool, name string, fallback bool, usage string, envNames ...string) {
	value, setBy := resolveBoolEnv(fallback, envNames...)
	registerEnvVar(name, usage, strconv.FormatBool(fallback), setBy, envNames)
	ensureFlagSet(fs).BoolVar(target, name, value, flagUsage(usage, envNames...))
}

func IntFlagEnv(fs *flag.FlagSet, target *int, name string, fallback int, parse IntEnvParser, usage string, envNames ...string) {
	value, setBy := resolveIntEnv(fallback, parse, envNames...)
	registerEnvVar(name, usage, strconv.Itoa(fallback), setBy, envNames)
	ensureFlagSet(fs).IntVar(target, name, value, flagUsage(usage, envNames...))
}

func RepeatedStringFlag(fs *flag.FlagSet, target *[]string, name, usage string) {
	ensureFlagSet(fs).Func(name, usage, func(value string) error {
		if target == nil {
			return nil
		}
		*target = append(*target, value)
		return nil
	})
}

func ensureFlagSet(fs *flag.FlagSet) *flag.FlagSet {
	if fs != nil {
		return fs
	}
	return flag.CommandLine
}

func flagUsage(usage string, envNames ...string) string {
	names := make([]string, 0, len(envNames))
	for _, envName := range envNames {
		envName = strings.TrimSpace(envName)
		if envName != "" {
			names = append(names, envName)
		}
	}
	if len(names) == 0 {
		return usage
	}
	var envUsage string
	switch len(names) {
	case 1:
		envUsage = names[0]
	case 2:
		envUsage = names[0] + " or " + names[1]
	default:
		envUsage = strings.Join(names[:len(names)-1], ", ") + ", or " + names[len(names)-1]
	}
	if strings.TrimSpace(usage) == "" {
		return "(env: " + envUsage + ")"
	}
	return usage + " (env: " + envUsage + ")"
}

func SignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
}

func RunCommands(
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	usage func(io.Writer),
	commands map[string]CommandFunc,
) error {
	defaultCommand, hasDefaultCommand := commands[""]
	if len(args) == 0 {
		if hasDefaultCommand {
			return defaultCommand(nil)
		}
		if usage != nil {
			usage(stdout)
		}
		return nil
	}

	command := strings.TrimSpace(args[0])
	switch {
	case command == "help":
		if runCommand, ok := commands[command]; ok {
			return runCommand(args[1:])
		}
		if usage != nil {
			usage(stdout)
		}
		return nil
	case command == "-h" || command == "--help":
		if usage != nil {
			usage(stdout)
		}
		return nil
	case command == "" || strings.HasPrefix(command, "-"):
		if hasDefaultCommand {
			return defaultCommand(args)
		}
	}

	runCommand, ok := commands[command]
	if !ok {
		if usage != nil {
			usage(stderr)
		}
		return fmt.Errorf("unknown command %q", command)
	}
	return runCommand(args[1:])
}

func NewFlagSet(name string, usage func(io.Writer)) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if usage != nil {
		fs.Usage = func() {
			usage(fs.Output())
		}
	}
	return fs
}

func ParseFlagSet(fs *flag.FlagSet, args []string, usage func(io.Writer)) error {
	args = normalizeFlagArgs(fs, args)
	if len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		if usage != nil {
			usage(os.Stdout)
		}
		return flag.ErrHelp
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if usage != nil {
				usage(os.Stdout)
			}
			return flag.ErrHelp
		}
		if usage != nil {
			usage(os.Stderr)
		}
		return err
	}
	return nil
}

func normalizeFlagArgs(fs *flag.FlagSet, args []string) []string {
	if fs == nil || len(args) < 2 {
		return args
	}

	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if arg == "" || arg == "-" || !strings.HasPrefix(arg, "-") {
			positionals = append(positionals, args[i])
			continue
		}
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}

		name := strings.TrimLeft(strings.TrimSpace(arg), "-")
		if name == "" {
			positionals = append(positionals, args[i])
			continue
		}
		hasInlineValue := false
		if cut, _, ok := strings.Cut(name, "="); ok {
			name = strings.TrimSpace(cut)
			hasInlineValue = true
		}
		if name == "" {
			positionals = append(positionals, args[i])
			continue
		}

		flags = append(flags, args[i])

		flagDef := fs.Lookup(name)
		if hasInlineValue || flagDef == nil {
			continue
		}
		boolValue, ok := flagDef.Value.(boolFlagValue)
		if ok && boolValue.IsBoolFlag() {
			if i+1 < len(args) {
				next := strings.TrimSpace(args[i+1])
				if _, err := strconv.ParseBool(next); err == nil {
					flags[len(flags)-1] = args[i] + "=" + next
					i++
				}
			}
			continue
		}
		if i+1 >= len(args) {
			continue
		}
		i++
		flags = append(flags, args[i])
	}

	return append(flags, positionals...)
}

func OptionalSingleArg(args []string, name string) (string, error) {
	switch len(args) {
	case 0:
		return "", nil
	case 1:
		return strings.TrimSpace(args[0]), nil
	default:
		return "", fmt.Errorf("only one %s is supported", strings.TrimSpace(name))
	}
}

func RequireNoArgs(args []string, command string) error {
	if len(args) == 0 {
		return nil
	}
	return fmt.Errorf("%s does not accept positional arguments", strings.TrimSpace(command))
}

func NormalizeLoopbackTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if port, ok := strings.CutPrefix(raw, ":"); ok {
		if _, err := strconv.Atoi(port); err == nil {
			return net.JoinHostPort("127.0.0.1", port), nil
		}
	}
	if _, err := strconv.Atoi(raw); err == nil {
		return net.JoinHostPort("127.0.0.1", raw), nil
	}
	return NormalizeTargetAddr(raw)
}

// HelpTopic maps a subcommand name to its usage printer.
type HelpTopic struct {
	Name  string
	Usage func(io.Writer)
}

// MakeHelpCommand returns a CommandFunc that dispatches help topics.
// Topics are matched in order; the slice provides deterministic output.
func MakeHelpCommand(rootUsage func(io.Writer), topics []HelpTopic) CommandFunc {
	return func(args []string) error {
		if len(args) == 0 {
			rootUsage(os.Stdout)
			return nil
		}
		if len(args) > 1 {
			rootUsage(os.Stderr)
			return errors.New("only one help topic is supported")
		}
		topic := strings.TrimSpace(args[0])
		switch topic {
		case "", "help", "-h", "--help":
			rootUsage(os.Stdout)
			return nil
		}
		for _, t := range topics {
			if t.Name == topic {
				t.Usage(os.Stdout)
				return nil
			}
		}
		rootUsage(os.Stderr)
		return fmt.Errorf("unknown help topic %q", topic)
	}
}

func WriteCommandUsage(w io.Writer, usage []string, examples []string) {
	if w == nil {
		return
	}
	if len(usage) > 0 {
		fmt.Fprintln(w, "Usage:")
		for _, line := range usage {
			fmt.Fprintln(w, "  "+strings.TrimSpace(line))
		}
	}
	if len(examples) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	for _, line := range examples {
		fmt.Fprintln(w, "  "+strings.TrimSpace(line))
	}
}
