package sdk

import (
	"fmt"
	"slices"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// ExposeOption applies a client-side exposure policy to ExposeConfig.
//
// ExposeConfig remains the compatibility surface for advanced protocol and
// application settings. These options provide the small, listener-oriented
// entry point without introducing another package-level facade.
type ExposeOption func(*ExposeConfig)

// WithDiscovery merges the built-in relay registry into the relay pool.
func WithDiscovery() ExposeOption {
	return func(cfg *ExposeConfig) { cfg.Discovery = true }
}

// WithOverlay prefers the IVNP overlay transport when relays offer it.
func WithOverlay() ExposeOption {
	return func(cfg *ExposeConfig) { cfg.Overlay = true }
}

// WithECH enables Encrypted Client Hello for relay connections.
func WithECH() ExposeOption {
	return func(cfg *ExposeConfig) { cfg.ECH = true }
}

// WithBanMITM rejects relays that fail the man-in-the-middle probe.
func WithBanMITM() ExposeOption {
	return func(cfg *ExposeConfig) { cfg.BanMITM = true }
}

// WithRawTCP requires relays with raw TCP stream support.
func WithRawTCP() ExposeOption {
	return func(cfg *ExposeConfig) { cfg.TCPEnabled = true }
}

// WithMaxActiveRelays caps simultaneously active relay listeners.
func WithMaxActiveRelays(maxActiveRelays int) ExposeOption {
	return func(cfg *ExposeConfig) {
		if maxActiveRelays > 0 {
			cfg.MaxActiveRelays = maxActiveRelays
		}
	}
}

// WithMetadata attaches service metadata published through the relay
// directory.
func WithMetadata(metadata types.LeaseMetadata) ExposeOption {
	return func(cfg *ExposeConfig) { cfg.Metadata = metadata.Copy() }
}

// DefaultRelays returns a copy of the embedded relay registry in registry
// order. Callers may safely modify the returned slice.
func DefaultRelays() []string {
	return slices.Clone(defaultRelays)
}

var defaultRelays = mustDefaultRelays()

func mustDefaultRelays() []string {
	relays, err := utils.NormalizeRelayURLs(types.BootstrapRelays...)
	if err != nil {
		panic(fmt.Errorf("sdk: normalize built-in relays: %w", err))
	}
	return relays
}
