package portal

import (
	"fmt"
	"path/filepath"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/overlay"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func loadRelayIdentityAuthority(cfg ServerConfig) (identity.RelayIdentity, identity.Authority, error) {
	identityPath := filepath.Join(cfg.StateDir, types.RelayIdentityFilename)
	relayIdentity, err := identity.LoadOrCreateRelayIdentity(identityPath, utils.PortalRootHost(cfg.PortalURL))
	if err != nil {
		return identity.RelayIdentity{}, nil, fmt.Errorf("load relay identity: %w", err)
	}
	return relayIdentity, identity.NewLocalAuthority(relayIdentity.Identity), nil
}

func createLeaseRegistry(cfg ServerConfig, relayIdentity identity.RelayIdentity, relayAuthority identity.Authority) (*leaseRegistry, error) {
	registry, err := newLeaseRegistry(cfg.MinPort, cfg.MaxPort, relayIdentity.Name, relayAuthority, cfg.PortalURL, int64(cfg.DefaultIdentityBPS))
	if err != nil {
		return nil, err
	}
	registry.unapprovedPerSource = cfg.UnapprovedLeasesPerSource
	return registry, nil
}

func resolveRelaySet(cfg ServerConfig) (ServerConfig, *discovery.RelaySet, error) {
	if !cfg.DiscoveryEnabled {
		return cfg, nil, nil
	}
	bootstraps, err := discovery.ResolveRelayURLs(cfg.Bootstraps, true)
	if err != nil {
		return ServerConfig{}, nil, fmt.Errorf("resolve discovery bootstraps: %w", err)
	}
	cfg.Bootstraps = bootstraps
	cfg.Bootstraps = removeRelayURL(cfg.Bootstraps, cfg.PortalURL)
	return cfg, discovery.NewRelaySet(cfg.Bootstraps), nil
}

func attachOverlay(server *Server, cfg ServerConfig, relayAuthority identity.Authority) error {
	if cfg.IVNPConfigPath == "" {
		return nil
	}
	overlayRuntime, err := overlay.New(overlay.Config{
		ConfigPath: cfg.IVNPConfigPath,
		Authority:  relayAuthority,
	})
	if err != nil {
		return err
	}
	server.overlay = overlayRuntime
	server.registry.overlay = overlayRuntime
	return nil
}

func finishNewServer(cfg ServerConfig, relayIdentity identity.RelayIdentity, relayAuthority identity.Authority) (*Server, error) {
	registry, err := createLeaseRegistry(cfg, relayIdentity, relayAuthority)
	if err != nil {
		return nil, err
	}
	return completeNewServer(cfg, registry, relayIdentity, relayAuthority)
}

func completeNewServer(cfg ServerConfig, registry *leaseRegistry, relayIdentity identity.RelayIdentity, relayAuthority identity.Authority) (*Server, error) {
	resolved, relaySet, err := resolveRelaySet(cfg)
	if err != nil {
		return nil, err
	}
	server := &Server{
		cfg:       utils.NewSnapshot(resolved, ServerConfig.snapshot),
		identity:  relayIdentity,
		authority: relayAuthority,
		registry:  registry,
		relaySet:  relaySet,
	}
	if err := attachOverlay(server, resolved, relayAuthority); err != nil {
		return nil, err
	}
	return server, nil
}

func assembleNewServer(cfg ServerConfig) (*Server, error) {
	relayIdentity, relayAuthority, err := loadRelayIdentityAuthority(cfg)
	if err != nil {
		return nil, err
	}
	return finishNewServer(cfg, relayIdentity, relayAuthority)
}

func NewServer(cfg ServerConfig) (*Server, error) {
	validated, err := ValidateServerConfig(cfg)
	if err != nil {
		return nil, err
	}
	return assembleNewServer(validated)
}
