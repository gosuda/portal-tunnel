package cli

import (
	"flag"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

type IntEnvParser func(string, int) int

type EnvVar struct {
	Name    string
	Aliases []string
	Flag    string
	Usage   string
	Default string
	Value   string
	SetBy   string
}

type EnvIssue struct {
	Name    string
	Value   string
	Problem string
}

type Env struct {
	values map[string]string
	Vars   []EnvVar
	Issues []EnvIssue
}

func NewEnv(environ []string) *Env {
	e := &Env{values: make(map[string]string, len(environ))}
	for _, entry := range environ {
		if name, value, ok := strings.Cut(entry, "="); ok {
			if runtime.GOOS == "windows" {
				name = strings.ToUpper(name)
			}
			e.values[name] = value
		}
	}
	return e
}

func (e *Env) registerEnvVar(flagName, usage, defaultValue, value, setBy string, envNames []string) {
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
		Value:   value,
		SetBy:   setBy,
	}
	e.Vars = append(e.Vars, entry)
}

func (e *Env) trimmedEnv(name string) string {
	if runtime.GOOS == "windows" {
		name = strings.ToUpper(name)
	}
	return strings.TrimSpace(e.values[name])
}

func (e *Env) resolveStringEnv(fallback string, envNames ...string) (string, string) {
	for _, envName := range envNames {
		if envValue := e.trimmedEnv(envName); envValue != "" {
			return envValue, envName
		}
	}
	return fallback, ""
}

func (e *Env) resolveBoolEnv(fallback bool, envNames ...string) (bool, string) {
	for _, envName := range envNames {
		raw := e.trimmedEnv(envName)
		if raw == "" {
			continue
		}
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			e.Issues = append(e.Issues, EnvIssue{Name: envName, Value: raw, Problem: "not a boolean; use true or false"})
			return fallback, ""
		}
		return parsed, envName
	}
	return fallback, ""
}

func (e *Env) resolveIntEnv(fallback int, parse IntEnvParser, envNames ...string) (int, string) {
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
		raw := e.trimmedEnv(envName)
		if raw == "" {
			continue
		}
		number, err := strconv.Atoi(raw)
		if err != nil {
			e.Issues = append(e.Issues, EnvIssue{Name: envName, Value: raw, Problem: "not an integer"})
			return fallback, ""
		}
		value := parse(raw, fallback)
		if value != number && value == fallback {
			e.Issues = append(e.Issues, EnvIssue{Name: envName, Value: raw, Problem: "out of the accepted range"})
			return fallback, ""
		}
		return value, envName
	}
	return fallback, ""
}

func (e *Env) String(fs *flag.FlagSet, target *string, name, fallback, usage string, envNames ...string) {
	value, setBy := e.resolveStringEnv(fallback, envNames...)
	e.registerEnvVar(name, usage, fallback, value, setBy, envNames)
	fs.StringVar(target, name, value, flagUsage(usage, envNames...))
	fs.Lookup(name).DefValue = fallback
}

func (e *Env) CSV(fs *flag.FlagSet, target *[]string, name, fallback, usage string, envNames ...string) {
	value, setBy := e.resolveStringEnv(fallback, envNames...)
	e.registerEnvVar(name, usage, fallback, value, setBy, envNames)
	if target != nil {
		*target = utils.SplitCSV(value)
	}
	fs.Func(name, flagUsage(usage, envNames...), func(value string) error {
		if target != nil {
			*target = utils.SplitCSV(value)
		}
		return nil
	})
	fs.Lookup(name).DefValue = fallback
}

func (e *Env) Bool(fs *flag.FlagSet, target *bool, name string, fallback bool, usage string, envNames ...string) {
	value, setBy := e.resolveBoolEnv(fallback, envNames...)
	e.registerEnvVar(name, usage, strconv.FormatBool(fallback), strconv.FormatBool(value), setBy, envNames)
	fs.BoolVar(target, name, value, flagUsage(usage, envNames...))
	fs.Lookup(name).DefValue = strconv.FormatBool(fallback)
}

func (e *Env) Int(fs *flag.FlagSet, target *int, name string, fallback int, parse IntEnvParser, usage string, envNames ...string) {
	value, setBy := e.resolveIntEnv(fallback, parse, envNames...)
	e.registerEnvVar(name, usage, strconv.Itoa(fallback), strconv.Itoa(value), setBy, envNames)
	fs.IntVar(target, name, value, flagUsage(usage, envNames...))
	fs.Lookup(name).DefValue = strconv.Itoa(fallback)
}

func (e *Env) Duration(fs *flag.FlagSet, target *time.Duration, name string, fallback time.Duration, usage string, envNames ...string) {
	raw, setBy := e.resolveStringEnv(fallback.String(), envNames...)
	value, err := time.ParseDuration(raw)
	if err != nil {
		e.Issues = append(e.Issues, EnvIssue{Name: setBy, Value: raw, Problem: "not a duration; use values such as 30m or 24h"})
		value, setBy = fallback, ""
	}
	e.registerEnvVar(name, usage, fallback.String(), value.String(), setBy, envNames)
	fs.DurationVar(target, name, value, flagUsage(usage, envNames...))
	fs.Lookup(name).DefValue = fallback.String()
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
