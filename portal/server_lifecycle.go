package portal

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func (s *Server) Wait() error {
	if s.group == nil {
		return nil
	}
	err := s.group.Wait()
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (s *Server) closeSNIServer() error {
	if s.sniListener == nil {
		return nil
	}
	if err := s.sniListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func (s *Server) shutdownAPIServer(ctx context.Context) error {
	if s.apiServer == nil {
		return nil
	}
	return s.apiServer.Shutdown(ctx)
}

func (s *Server) shutdownRedirectServer(ctx context.Context) error {
	if s.redirectServer == nil {
		return nil
	}
	err := s.redirectServer.Shutdown(ctx)
	if err != nil {
		_ = s.redirectServer.Close()
	}
	_ = s.redirectListener.Close()
	return err
}

func (s *Server) stopShutdownACME(ctx context.Context) error {
	if s.acmeManager == nil {
		return nil
	}
	if err := s.acmeManager.Stop(ctx); err != nil {
		return fmt.Errorf("stop acme manager: %w", err)
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	var shutdownErr error
	s.shutdownOnce.Do(func() {
		records := s.haltRelayTransports(ctx)
		s.deleteHaltedLeaseDNS(ctx, records)
		if err := s.closeRelayServers(ctx); err != nil {
			shutdownErr = err
		}
		if err := s.stopShutdownACME(ctx); err != nil && shutdownErr == nil {
			shutdownErr = err
		}
	})
	return shutdownErr
}

func (s *Server) prepareAPITLS(ctx context.Context) (*tls.Config, error) {
	cfg := s.config()
	acmeCfg := cfg.ACME
	if baseDomain := utils.NormalizeHostname(acmeCfg.BaseDomain); baseDomain != "" && baseDomain != s.identity.Name {
		return nil, fmt.Errorf("acme base domain %q does not match portal root host %q", acmeCfg.BaseDomain, s.identity.Name)
	}
	acmeCfg.BaseDomain = s.identity.Name
	if strings.TrimSpace(acmeCfg.ENSGaslessAddress) == "" {
		acmeCfg.ENSGaslessAddress = s.identity.Address
	}

	manager, err := acme.NewManager(acmeCfg)
	if err != nil {
		return nil, fmt.Errorf("create acme manager: %w", err)
	}

	if err := manager.EnsureTLSMaterial(ctx); err != nil {
		_ = manager.Stop(ctx)
		return nil, fmt.Errorf("ensure relay certificate: %w", err)
	}
	s.acmeManager = manager

	apiTLS := &tls.Config{
		GetCertificate: manager.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.1"},
	}
	return apiTLS, nil
}
