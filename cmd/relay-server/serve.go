package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/relay-server/policy"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func openRelayServer(cfg appConfig, ingress *policy.Ingress) (*portal.Server, *policy.Store, *RelayAPI, error) {
	cfg.Relay.ApplicationOwnsDomainReport = true
	server, err := portal.NewServer(cfg.Relay)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create relay server: %w", err)
	}
	policies := policy.NewStore()
	policyPath := filepath.Join(cfg.Relay.StateDir, types.RelayPolicyFilename)
	initialPolicy := types.PolicySettings{
		ApprovalMode: cfg.ApprovalMode,
		UDP:          types.PolicyPortSettings{Enabled: cfg.UDPEnabled},
		TCPPort:      types.PolicyPortSettings{Enabled: cfg.TCPEnabled},
	}
	relayAPI, err := NewRelayAPI(server, policies, ingress, policyPath, cfg.AdminToken, cfg.FrontendDir, initialPolicy)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create relay api: %w", err)
	}
	if policy.Mode(cfg.ApprovalMode) == policy.ModeManual && policies.Snapshot().Mode() == policy.ModeAuto {
		log.Warn().Str("policy_path", policyPath).Msg("approval mode manual is ignored: policy.json saves auto, so every lease is approved; set the mode with the admin API")
	}
	return server, policies, relayAPI, nil
}

func runServeRelayWithPprofUntilStopped(ctx context.Context, server *portal.Server, handler http.Handler, stopPprof func(context.Context) error, pprofErrs <-chan error) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	relayResult := make(chan error, 1)
	go func() {
		relayResult <- server.Serve(runCtx, handler)
	}()

	var serveErr error
	select {
	case serveErr = <-relayResult:
	case err := <-pprofErrs:
		serveErr = fmt.Errorf("serve pprof: %w", err)
		cancel()
		relayErr := <-relayResult
		serveErr = errors.Join(serveErr, relayErr)
	}
	cancel()

	shutdownCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	if err := stopPprof(shutdownCtx); err != nil {
		log.Warn().Err(err).Msg("shutdown pprof server")
	}
	stop()
	return serveErr
}

func runServer(ctx context.Context, cfg appConfig, ingress *policy.Ingress, x402Settings x402FacilitatorSettings) error {
	server, policies, relayAPI, err := openRelayServer(cfg, ingress)
	if err != nil {
		return err
	}

	appRoutes := relayAPI.Handler()
	if err := mountRelayRoutes(x402Settings, server, appRoutes); err != nil {
		return err
	}
	base := policy.ControlBodyHandler(appRoutes)
	handler := policy.Mux(server, base, ingress,
		policy.NewSourceLimiter(cfg.PreAuth.SourcePerMinute, cfg.PreAuth.SourceBurst, cfg.PreAuth.GlobalPerMinute, cfg.PreAuth.GlobalBurst),
		policies, cfg.PreAuth)
	handler = relayAPI.metrics.instrument(handler)
	if !cfg.PprofEnabled {
		return server.Serve(ctx, handler)
	}

	bound, stopPprof, pprofErrs, err := startPprofServer(ctx, normalizePprofAddr(cfg.PprofListenAddr))
	if err != nil {
		return err
	}
	log.Info().Str("pprof_addr", hostPortOrLoopback(bound.String())).Msg("starting pprof server")

	return runServeRelayWithPprofUntilStopped(ctx, server, handler, stopPprof, pprofErrs)
}
