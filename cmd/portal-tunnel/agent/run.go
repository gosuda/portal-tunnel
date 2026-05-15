package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	portalauth "github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func Run(ctx context.Context, cfg Config) error {
	endpointStateDir := strings.TrimSpace(cfg.Agent.StateDir)
	if endpointStateDir == "" {
		return errors.New("agent.state_dir is required")
	}
	if err := os.MkdirAll(endpointStateDir, 0o700); err != nil {
		return err
	}
	token := utils.RandomID("agent_")

	runtimeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	manager := newManager(cfg, "")
	walletAuth, err := portalauth.NewWalletAuthenticator(portalauth.WalletAuthConfig{
		AllowedAddresses: cfg.Agent.AllowedWallets,
		AllowAnyAddress:  len(cfg.Agent.AllowedWallets) == 0,
		Statement:        "Sign in to Portal agent",
	})
	if err != nil {
		return err
	}
	controlAddr := strings.TrimSpace(cfg.Agent.ControlAddr)
	if controlAddr == "" {
		return errors.New("control address is required")
	}
	host, _, err := net.SplitHostPort(controlAddr)
	if err != nil {
		return fmt.Errorf("control address must be host:port: %w", err)
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return errors.New("control address must include a loopback host")
	}
	if !strings.EqualFold(host, "localhost") {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("control address must bind to loopback, got %q", host)
		}
	}
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(runtimeCtx, "tcp", controlAddr)
	if err != nil {
		return err
	}
	control := &http.Server{
		Handler: &controlHandler{
			manager:  manager,
			token:    token,
			auth:     walletAuth,
			shutdown: cancel,
		},
		ReadHeaderTimeout: 5 * time.Second,
	}
	listenAddr := listener.Addr().String()
	manager.controlAddr = listenAddr

	if err := utils.WriteJSONFile(filepath.Join(endpointStateDir, endpointFilename), endpoint{
		ControlAddr: listenAddr,
		Token:       token,
	}, 0o600); err != nil {
		_ = listener.Close()
		_ = control.Shutdown(context.Background())
		return err
	}
	defer func() {
		_ = os.Remove(filepath.Join(endpointStateDir, endpointFilename))
	}()

	manager.Start(runtimeCtx)

	errCh := make(chan error, 1)
	go func() {
		err := control.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			err = nil
		}
		errCh <- err
	}()

	log.Info().
		Str("control_addr", listenAddr).
		Int("tunnel_count", len(cfg.Tunnels)).
		Msg("portal agent started")

	var serveErr error
	select {
	case <-runtimeCtx.Done():
	case serveErr = <-errCh:
		cancel()
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	stopErr := manager.Stop(shutdownCtx)
	closeErr := control.Shutdown(shutdownCtx)
	if serveErr == nil {
		select {
		case serveErr = <-errCh:
		default:
		}
	}
	if errors.Is(serveErr, context.Canceled) {
		serveErr = nil
	}
	log.Info().Msg("portal agent stopped")
	return errors.Join(serveErr, stopErr, closeErr)
}
