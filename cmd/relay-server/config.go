package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// envFileEntry is one assignment read from an env file, kept in file order so
// the report follows the operator's own layout.
type envFileEntry struct {
	Name  string
	Value string
}

func loadEnvFile(path string) ([]envFileEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var entries []envFileEntry
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		// A line that is neither blank, a comment, nor an assignment is invalid.
		name, value, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("%s:%d: not an assignment: %q", path, lineNo, line)
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("%s:%d: assignment has no name: %q", path, lineNo, line)
		}
		// Values read from an env file are not expanded.
		value = strings.TrimSpace(value)
		doubleQuoted := len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"'
		singleQuoted := len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\''
		if doubleQuoted || singleQuoted {
			value = value[1 : len(value)-1]
		}
		entries = append(entries, envFileEntry{Name: name, Value: value})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// knownEnvNames indexes every name the relay reads, including flag aliases.
func knownEnvNames() map[string]utils.EnvVar {
	index := make(map[string]utils.EnvVar)
	for _, entry := range utils.EnvVars() {
		index[entry.Name] = entry
		for _, alias := range entry.Aliases {
			index[alias] = entry
		}
	}
	return index
}

func secretEnvName(name string) bool {
	upper := strings.ToUpper(name)
	for _, marker := range []string{"TOKEN", "SECRET", "KEY", "PASSWORD", "CREDENTIALS"} {
		if strings.Contains(upper, marker) {
			return true
		}
	}
	return false
}

// valueMarker distinguishes a key that something supplied from one running on
// its default, so a long list can be skimmed for what the operator actually set.
func valueMarker(entry utils.EnvVar) string {
	if entry.SetBy == "" {
		return "--"
	}
	return "OK"
}

// valueSource names where the effective value came from. When an alias supplied
// it, the alias is named: "I set AWS_REGION, why is the value different?" is
// answered by seeing that AWS_DEFAULT_REGION was consulted first.
func valueSource(entry utils.EnvVar, supplied map[string]bool, envFile string) string {
	if entry.SetBy == "" {
		return fmt.Sprintf("default (%s)", defaultDisplay(entry.Default))
	}

	origin := "process environment"
	if supplied[entry.SetBy] {
		origin = envFile
	}
	if entry.SetBy != entry.Name {
		return fmt.Sprintf("%s, via the alias %s", origin, entry.SetBy)
	}
	return origin
}

func displayValue(name, value string) string {
	if strings.TrimSpace(value) == "" {
		return "<unset>"
	}
	if secretEnvName(name) {
		return "<set>"
	}
	return value
}

func writeConfigReport(w io.Writer, cfg appConfig, entries []envFileEntry, source string) {
	fmt.Fprintf(w, "Portal relay configuration (%s)\n", source)
	// Reading a file in isolation applies relay defaults to every key the file
	// omits. Inspect the environment inside the target process or container when
	// another launcher supplies additional relay values.
	if len(entries) > 0 {
		fmt.Fprint(w, "Keys absent from this file take relay defaults. To inspect values supplied\n"+
			"by a launcher, run this command in the relay's actual environment.\n")
	}
	fmt.Fprintln(w)

	supplied := make(map[string]bool, len(entries))
	for _, entry := range entries {
		supplied[entry.Name] = true
	}

	// Every relay key is listed with the value the flag actually resolved to,
	// not the text of whichever line happened to appear in the file. A key that
	// an alias or a higher-priority name overrode would otherwise read as though
	// it were in effect, which is the confusion this report exists to remove.
	fmt.Fprintln(w, "Keys")
	for _, entry := range utils.EnvVars() {
		fmt.Fprintf(w, "  %-4s %-30s %-24s relay --%s\n",
			valueMarker(entry), entry.Name, displayValue(entry.Name, entry.Value), entry.Flag)
		fmt.Fprintf(w, "         source: %s\n", valueSource(entry, supplied, source))
		writeWrapped(w, entry.Usage)
	}
	// Keys the file supplies that nothing reads are how deployment drift hides:
	// the relay runs on defaults while the operator believes their value is in
	// effect. Surface every unrecognized name instead of dropping it.
	relay := knownEnvNames()
	var unknown []envFileEntry
	for _, entry := range entries {
		if _, isRelay := relay[entry.Name]; !isRelay {
			unknown = append(unknown, entry)
		}
	}
	if len(unknown) > 0 {
		fmt.Fprintf(w, "\nUNKNOWN  %d key(s) are not read by the relay and are silently ignored:\n", len(unknown))
		for _, entry := range unknown {
			if suggestion := nearestEnvName(entry.Name, relay); suggestion != "" {
				fmt.Fprintf(w, "  %-30s did you mean %s?\n", entry.Name, suggestion)
				continue
			}
			fmt.Fprintf(w, "  %-30s no equivalent key exists\n", entry.Name)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Validation")
	if _, err := portal.ValidateServerConfig(cfg.Relay); err != nil {
		fmt.Fprintf(w, "  INVALID %s\n", err)
	} else if err := cfg.Reputation.validate(); err != nil {
		fmt.Fprintf(w, "  INVALID %s\n", err)
	} else {
		fmt.Fprintln(w, "  OK relay configuration is valid")
	}

	if issues := utils.EnvIssues(); len(issues) > 0 {
		fmt.Fprintln(w, "\nInvalid values")
		for _, issue := range issues {
			fmt.Fprintf(w, "  %s=%s  %s\n", issue.Name, displayValue(issue.Name, issue.Value), issue.Problem)
		}
	}
}

// writeWrapped prints an indented, soft-wrapped continuation line.
func writeWrapped(w io.Writer, text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	const width = 72
	const indent = "         "
	line := indent
	for _, word := range strings.Fields(text) {
		if len(line)+len(word)+1 > width && strings.TrimSpace(line) != "" {
			fmt.Fprintln(w, line)
			line = indent
		}
		if strings.TrimSpace(line) == "" {
			line += word
			continue
		}
		line += " " + word
	}
	if strings.TrimSpace(line) != "" {
		fmt.Fprintln(w, line)
	}
}

// nearestEnvName suggests the closest known key for a typo. Deployment drift
// usually looks like ADMIN_WALLETS for ADMIN_TOKEN: close enough to look right,
// far enough that nothing reads it.
func nearestEnvName(name string, relay map[string]utils.EnvVar) string {
	candidates := make([]string, 0, len(relay))
	for candidate := range relay {
		candidates = append(candidates, candidate)
	}
	sort.Strings(candidates)

	best := ""
	bestDistance := len(name)/2 + 2
	for _, candidate := range candidates {
		if distance := editDistance(name, candidate); distance < bestDistance {
			best, bestDistance = candidate, distance
		}
	}
	return best
}

func editDistance(a, b string) int {
	previous := make([]int, len(b)+1)
	current := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(a); i++ {
		current[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			current[j] = min(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
		}
		previous, current = current, previous
	}
	return previous[len(b)]
}

// writeEnvReference emits every key the relay reads. It is generated from the
// flag definitions so it cannot drift from the binary.
func writeEnvReference(w io.Writer) {
	fmt.Fprintln(w, "# Generated by `relay-server config --format env`. Do not edit by hand.")
	fmt.Fprintln(w, "# Every environment key read by the relay binary.")
	fmt.Fprintln(w, "# See .env.example for a deployment-specific starting point.")

	fmt.Fprintln(w, "\n# ── relay ──")
	for _, entry := range utils.EnvVars() {
		fmt.Fprintf(w, "\n# %s  [relay --%s]  default: %s\n", entry.Name, entry.Flag, defaultDisplay(entry.Default))
		if len(entry.Aliases) > 0 {
			fmt.Fprintf(w, "#   also accepted: %s\n", strings.Join(entry.Aliases, ", "))
		}
		writeCommentWrapped(w, entry.Usage)
		fmt.Fprintf(w, "%s=%s\n", entry.Name, entry.Default)
	}
}

// writeEnvNames lists every key the relay reads, one per line.
func writeEnvNames(w io.Writer) {
	var names []string
	for _, entry := range utils.EnvVars() {
		names = append(names, entry.Name)
	}
	sort.Strings(names)
	for _, name := range slices.Compact(names) {
		fmt.Fprintln(w, name)
	}
}

func defaultDisplay(value string) string {
	if value == "" {
		return "(empty)"
	}
	return value
}

func writeCommentWrapped(w io.Writer, text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	const width = 74
	line := "#  "
	for _, word := range strings.Fields(text) {
		if len(line)+len(word)+1 > width && strings.TrimSpace(line) != "#" {
			fmt.Fprintln(w, line)
			line = "#  "
		}
		if line == "#  " {
			line += word
			continue
		}
		line += " " + word
	}
	if strings.TrimSpace(line) != "#" {
		fmt.Fprintln(w, line)
	}
}

// applyEnvFileInIsolation makes the file the whole environment for the pass
// that follows, and returns a function restoring what was there before.
//
// Setting only the file's own keys is not enough. A relay variable absent from
// the file would stay inherited from the shell, and a higher-priority alias in
// the shell would beat a value the file does supply — process AWS_REGION over
// file AWS_DEFAULT_REGION, for instance. The report would then describe a mix
// of file and shell, not the file against relay defaults.
func applyEnvFileInIsolation(entries []envFileEntry) (func(), error) {
	// A first pass populates the registry, which is how the set of names the
	// relay reads is known.
	if _, err := resolveAppConfig(nil); err != nil {
		return nil, err
	}

	var names []string
	for _, entry := range utils.EnvVars() {
		names = append(names, entry.Name)
		names = append(names, entry.Aliases...)
	}
	for _, entry := range entries {
		names = append(names, entry.Name)
	}

	type saved struct {
		value string
		set   bool
	}
	previous := make(map[string]saved, len(names))
	restore := func() {
		for name, prior := range previous {
			if prior.set {
				_ = os.Setenv(name, prior.value)
				continue
			}
			_ = os.Unsetenv(name)
		}
	}

	for _, name := range names {
		if _, recorded := previous[name]; recorded {
			continue
		}
		value, set := os.LookupEnv(name)
		previous[name] = saved{value: value, set: set}
		if err := os.Unsetenv(name); err != nil {
			restore()
			return nil, fmt.Errorf("isolate %s: %w", name, err)
		}
	}

	for _, entry := range entries {
		if err := os.Setenv(entry.Name, entry.Value); err != nil {
			restore()
			return nil, fmt.Errorf("apply %s: %w", entry.Name, err)
		}
	}
	return restore, nil
}

func runConfigCommand(args []string) error {
	var (
		envFilePath string
		format      string
	)
	fs := utils.NewFlagSet("relay-server config", printConfigUsage)
	utils.StringFlag(fs, &envFilePath, "env-file", "",
		"read this file in place of the process environment, against relay defaults")
	utils.StringFlag(fs, &format, "format", "text", "output format: text, env or names")

	if err := utils.ParseFlagSet(fs, args, printConfigUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := utils.RequireNoArgs(fs.Args(), "relay-server config"); err != nil {
		printConfigUsage(os.Stderr)
		return err
	}

	var entries []envFileEntry
	source := "process environment"
	if strings.TrimSpace(envFilePath) != "" {
		loaded, err := loadEnvFile(envFilePath)
		if err != nil {
			return fmt.Errorf("read env file: %w", err)
		}
		restore, err := applyEnvFileInIsolation(loaded)
		if err != nil {
			return err
		}
		defer restore()
		entries = loaded
		source = envFilePath
	}

	cfg, err := resolveAppConfig(nil)
	if err != nil {
		return err
	}

	switch strings.TrimSpace(format) {
	case "", "text":
		writeConfigReport(os.Stdout, cfg, entries, source)
		return nil
	case "env":
		writeEnvReference(os.Stdout)
		return nil
	case "names":
		writeEnvNames(os.Stdout)
		return nil
	default:
		printConfigUsage(os.Stderr)
		return fmt.Errorf("unknown format %q", format)
	}
}

func printConfigUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
		[]string{
			"relay-server config [--env-file PATH] [--format text|env]",
		},
		[]string{
			"relay-server config                 # this process environment",
			"relay-server config --env-file .env # one file, against relay defaults",
			"relay-server config --format env > env.reference",
		},
	)
}

// envIssueError turns recorded parse failures into a startup error. A value
// that cannot be parsed is always a mistake, and falling back silently is what
// let relays run with settings nothing read.
func envIssueError() error {
	issues := utils.EnvIssues()
	if len(issues) == 0 {
		return nil
	}
	messages := make([]string, 0, len(issues))
	for _, issue := range issues {
		messages = append(messages, fmt.Sprintf("%s=%q: %s", issue.Name, issue.Value, issue.Problem))
	}
	slices.Sort(messages)
	return errors.New("invalid environment values: " + strings.Join(messages, "; "))
}
