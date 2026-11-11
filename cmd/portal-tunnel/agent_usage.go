package main

import (
	"io"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/internal/cli"
)

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
