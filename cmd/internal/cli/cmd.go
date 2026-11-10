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
	if len(args) == 0 {
		return dispatchRunCommandsNoArgs(stdout, usage, commands)
	}

	command := strings.TrimSpace(args[0])
	switch {
	case command == "help":
		return dispatchRunCommandsHelp(args[1:], stdout, usage, commands)
	case command == "-h" || command == "--help":
		if usage != nil {
			usage(stdout)
		}
		return nil
	case command == "" || strings.HasPrefix(command, "-"):
		if defaultCommand, ok := commands[""]; ok {
			return defaultCommand(args)
		}
	}

	runCommand, ok := commands[command]
	if !ok {
		return reportRunCommandsUnknown(command, stderr, usage)
	}
	return runCommand(args[1:])
}

func dispatchRunCommandsHelp(args []string, stdout io.Writer, usage func(io.Writer), commands map[string]CommandFunc) error {
	if runCommand, ok := commands["help"]; ok {
		return runCommand(args)
	}
	if usage != nil {
		usage(stdout)
	}
	return nil
}

func reportRunCommandsUnknown(command string, stderr io.Writer, usage func(io.Writer)) error {
	if usage != nil {
		usage(stderr)
	}
	return fmt.Errorf("unknown command %q", command)
}

func dispatchRunCommandsNoArgs(stdout io.Writer, usage func(io.Writer), commands map[string]CommandFunc) error {
	if defaultCommand, ok := commands[""]; ok {
		return defaultCommand(nil)
	}
	if usage != nil {
		usage(stdout)
	}
	return nil
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

func splitFlagName(arg string) (string, bool) {
	name := strings.TrimLeft(strings.TrimSpace(arg), "-")
	before, _, hasInlineValue := strings.Cut(name, "=")
	if hasInlineValue {
		name = strings.TrimSpace(before)
	}
	return name, hasInlineValue
}

func appendFlagOperand(flagDef *flag.Flag, args []string, i int, flags []string) ([]string, int) {
	boolValue, ok := flagDef.Value.(boolFlagValue)
	if ok && boolValue.IsBoolFlag() {
		if i+1 >= len(args) {
			return flags, i
		}
		next := strings.TrimSpace(args[i+1])
		if _, err := strconv.ParseBool(next); err == nil {
			flags[len(flags)-1] = args[i] + "=" + next
			return flags, i + 1
		}
		return flags, i
	}
	if i+1 >= len(args) {
		return flags, i
	}
	return append(flags, args[i+1]), i + 1
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
			flags = append(flags, "--")
			break
		}
		updated, next, handled := consumeSingleFlagArg(fs, args, i, flags)
		flags, i = updated, next
		if !handled {
			positionals = append(positionals, args[i])
		}
	}

	return append(flags, positionals...)
}

func consumeSingleFlagArg(fs *flag.FlagSet, args []string, i int, flags []string) ([]string, int, bool) {
	name, hasInlineValue := splitFlagName(args[i])
	if name == "" {
		return flags, i, false
	}
	flags = append(flags, args[i])
	if hasInlineValue {
		return flags, i, true
	}
	flagDef := fs.Lookup(name)
	if flagDef == nil {
		return flags, i, true
	}
	updated, next := appendFlagOperand(flagDef, args, i, flags)
	return updated, next, true
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

type HelpTopic struct {
	Name  string
	Usage func(io.Writer)
}

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
