package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

var errOnlyOneHelpTopicSupported = errors.New("only one help topic is supported")

type CommandFunc func([]string) error
type boolFlagValue interface{ IsBoolFlag() bool }

func RepeatedStringFlag(fs *flag.FlagSet, target *[]string, name, usage string) {
	fs.Func(name, usage, func(value string) error {
		*target = append(*target, value)
		return nil
	})
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
	helpRequested := len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help")
	if helpRequested {
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
	terminated := false

	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if arg == "" || arg == "-" || !strings.HasPrefix(arg, "-") {
			positionals = append(positionals, args[i])
			continue
		}
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			terminated = true
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

	// Keep the terminator ahead of every positional after moving flags.
	// Otherwise, a flag-like target after -- becomes an executable option.
	if terminated {
		flags = append(flags, "--")
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
			return errOnlyOneHelpTopicSupported
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

// WriteFlagDefaults prints the registered flags. Custom Usage printers replace
// FlagSet defaults, so --help would otherwise list examples and omit the flags
// agents need (identity-path, relays).
func WriteFlagDefaults(w io.Writer, fs *flag.FlagSet) {
	if w == nil || fs == nil {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fs.SetOutput(w)
	fs.PrintDefaults()
}

func WriteHelpSection(w io.Writer, heading string, lines []string) {
	if w == nil || strings.TrimSpace(heading) == "" || len(lines) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, strings.TrimSpace(heading)+":")
	for _, line := range lines {
		fmt.Fprintln(w, "  "+strings.TrimSpace(line))
	}
}
