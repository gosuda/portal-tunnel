package sdk

import (
	"crypto/sha256"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func resolveExposeMembership(relayURLs []string, cfg options, identity types.Identity) ([]string, *discovery.Controller, error) {
	if !cfg.discoveryEnabled {
		if len(relayURLs) == 0 {
			return nil, nil, errPortalSDKLeastOneInitialRelay
		}
		return relayURLs, nil, nil
	}
	resolved, err := discovery.ResolveRelayURLs(relayURLs, true)
	if err != nil {
		return nil, nil, err
	}
	if len(resolved) == 0 {
		return nil, nil, errPortalSDKLeastOneInitialRelay
	}
	bootstraps, err := discovery.BootstrapRelayURLs()
	if err != nil {
		return nil, nil, err
	}
	controller := discovery.NewController(bootstraps)
	controller.SetExplicitRelays(relayURLs)
	controller.SetMaxActiveRelays(cfg.maxActiveRelays)
	controller.SetTransportRequirements(cfg.UDPEnabled, cfg.TCPEnabled)
	controller.SetLocalAddress(identity.Address)
	controller.SetSelectionKey(deriveSelectionKey(identity))
	return relayURLs, controller, nil
}

func deriveSelectionKey(identity types.Identity) []byte {
	sum := sha256.Sum256(append([]byte("portal-tunnel/mols-selection-key\x00"), identity.PrivateKey...))
	return sum[:]
}
