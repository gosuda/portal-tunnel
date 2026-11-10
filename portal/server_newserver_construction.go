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

func NewServer(cfg ServerConfig) (*Server, error) {
	validated, err := ValidateServerConfig(cfg)
	if err != nil {
		return nil, err
	}
	identityPath := filepath.Join(validated.StateDir, types.RelayIdentityFilename)
	relayIdentity, err := identity.LoadOrCreateRelayIdentity(identityPath, utils.PortalRootHost(validated.PortalURL))
	if err != nil {
		return nil, fmt.Errorf("load relay identity: %w", err)
	}
	relayAuthority := identity.NewLocalAuthority(relayIdentity.Identity)
	registry, err := newLeaseRegistry(validated.MinPort, validated.MaxPort, relayIdentity.Name, relayAuthority, validated.PortalURL, int64(validated.DefaultIdentityBPS))
	if err != nil {
		return nil, err
	}
	registry.unapprovedPerSource = validated.UnapprovedLeasesPerSource
	return completeNewServer(validated, registry, relayIdentity, relayAuthority)
}
