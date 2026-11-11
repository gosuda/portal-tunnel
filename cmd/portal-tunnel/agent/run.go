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

	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errControlAddressIsRequired              = errors.New("control address is required")
	errControlAddressMustIncludeLoopbackHost = errors.New("control address must include a loopback host")
)

func Run(ctx context.Context, cfg Config) error {
	runtimeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	manager := newManager(cfg, "")
	creds, err := prepareAgentCredentials(cfg)
	if err != nil {
		return err
	}
	server, err := manager.openControlServer(runtimeCtx, cancel, creds)
	if err != nil {
		return err
	}
	return server.serve(runtimeCtx)
}

type agentControlServer struct {
	listener     net.Listener
	server       *http.Server
	manager      *manager
	shutdown     context.CancelFunc
	endpointPath string
	listenAddr   string
}

type agentCredentials struct {
	stateDir string
	token    string
	auth     *walletAuthenticator
}

func (m *manager) openControlServer(runtimeCtx context.Context, cancel context.CancelFunc, creds agentCredentials) (*agentControlServer, error) {
	endpointPath := filepath.Join(creds.stateDir, endpointFilename)
	listener, listenAddr, localhostAuthority, err := listenAgentControl(runtimeCtx, m.cfg.Agent.ControlAddr)
	if err != nil {
		return nil, err
	}
	control := &http.Server{
		Handler: &controlHandler{
			manager:            m,
			token:              creds.token,
			auth:               creds.auth,
			shutdown:           cancel,
			authority:          listenAddr,
			localhostAuthority: localhostAuthority,
		},
		ReadHeaderTimeout: 5 * time.Second,
	}
	m.controlAddr = listenAddr
	server := &agentControlServer{
		listener:     listener,
		server:       control,
		manager:      m,
		shutdown:     cancel,
		endpointPath: endpointPath,
		listenAddr:   listenAddr,
	}
	if err := server.publishEndpoint(creds.token); err != nil {
		return nil, err
	}
	return server, nil
}

func (s *agentControlServer) publishEndpoint(token string) error {
	if err := utils.WriteJSONFile(s.endpointPath, endpoint{ControlAddr: s.listenAddr, Token: token}, 0o600); err != nil {
		_ = s.listener.Close()
		_ = s.server.Shutdown(context.Background())
		return err
	}
	if err := utils.EnsurePrivateFile(s.endpointPath); err != nil {
		_ = s.listener.Close()
		_ = s.server.Shutdown(context.Background())
		_ = os.Remove(s.endpointPath)
		return fmt.Errorf("secure agent endpoint: %w", err)
	}
	return nil
}

func prepareAgentCredentials(cfg Config) (agentCredentials, error) {
	endpointStateDir, token, err := secureAgentState(cfg)
	if err != nil {
		return agentCredentials{}, err
	}
	walletAuth, err := newWalletAuthenticator(walletAuthConfig{
		AllowedAddresses: cfg.Agent.AllowedWallets,
		AllowAnyAddress:  len(cfg.Agent.AllowedWallets) == 0,
		Statement:        "Sign in to Portal agent",
	})
	if err != nil {
		return agentCredentials{}, err
	}
	return agentCredentials{stateDir: endpointStateDir, token: token, auth: walletAuth}, nil
}

func secureAgentState(cfg Config) (string, string, error) {
	endpointStateDir := strings.TrimSpace(cfg.Agent.StateDir)
	if endpointStateDir == "" {
		return "", "", errAgentStateDirIsRequired
	}
	if err := utils.EnsurePrivateDir(endpointStateDir); err != nil {
		return "", "", fmt.Errorf("secure agent state directory: %w", err)
	}
	endpointPath := filepath.Join(endpointStateDir, endpointFilename)
	if err := utils.EnsurePrivateFile(endpointPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", "", fmt.Errorf("secure existing agent endpoint: %w", err)
	}
	return endpointStateDir, utils.RandomID("agent_"), nil
}

func listenAgentControl(runtimeCtx context.Context, controlAddr string) (net.Listener, string, string, error) {
	controlAddr = strings.TrimSpace(controlAddr)
	if controlAddr == "" {
		return nil, "", "", errControlAddressIsRequired
	}
	host, _, err := net.SplitHostPort(controlAddr)
	if err != nil {
		return nil, "", "", fmt.Errorf("control address must be host:port: %w", err)
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return nil, "", "", errControlAddressMustIncludeLoopbackHost
	}
	if !strings.EqualFold(host, "localhost") {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, "", "", fmt.Errorf("control address must bind to loopback, got %q", host)
		}
	}
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(runtimeCtx, "tcp", controlAddr)
	if err != nil {
		return nil, "", "", err
	}
	listenAddr := listener.Addr().String()
	localhostAuthority := fmt.Sprintf("localhost:%d", listener.Addr().(*net.TCPAddr).Port)
	return listener, listenAddr, localhostAuthority, nil
}

func (s *agentControlServer) serve(runtimeCtx context.Context) error {
	defer func() {
		_ = os.Remove(s.endpointPath)
	}()
	s.manager.Start(runtimeCtx)
	errCh := make(chan error, 1)
	go func() {
		err := s.server.Serve(s.listener)
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			err = nil
		}
		errCh <- err
	}()
	log.Info().
		Str("control_addr", s.listenAddr).
		Int("tunnel_count", len(s.manager.cfg.Tunnels)).
		Msg("portal agent started")
	var serveErr error
	select {
	case <-runtimeCtx.Done():
	case serveErr = <-errCh:
		s.shutdown()
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	stopErr := s.manager.Stop(shutdownCtx)
	closeErr := s.server.Shutdown(shutdownCtx)
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
