package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func runServeCommand(args []string) error {
	cfg, env, err := resolveAppConfig(args, os.Environ())
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	ingress, x402Settings, err := prepareAppConfig(&cfg, env.Issues)
	if err != nil {
		return err
	}

	log.Info().
		Str("release_version", types.ReleaseVersion).
		Str("state_dir", cfg.Relay.StateDir).
		Int("sni_port", cfg.Relay.SNIPort).
		Msg("starting relay server")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	return runServer(ctx, cfg, ingress, x402Settings)
}
