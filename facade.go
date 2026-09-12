// Package portal is the stable facade for embedding Portal tunnels.
//
// Expose creates a virtual net.Listener backed by one or more relays;
// everything else — discovery, overlay, ECH, policy, metadata — is optional
// policy layered around it through ExposeOption values. Proxying to local
// services is a separate concern (see Proxy), and identity persistence is a
// construction concern (see GenerateIdentity, ParseIdentity, LoadIdentity).
//
// The sdk package remains the protocol/client implementation and keeps the
// full feature surface; this facade only guarantees the listener-oriented
// contract above.
package portal

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// ExposeConfig configures a relayed listener. The relay pool, the resolved
// identity, and the datagram plane are the only first-class fields.
type ExposeConfig struct {
	Relays     []string
	Identity   types.Identity
	UDPEnabled bool
}

// ExposeOption layers optional Portal policy onto an exposure.
type ExposeOption func(*exposeSettings)

type exposeSettings struct {
	discovery       bool
	overlay         bool
	ech             bool
	banMITM         bool
	rawTCP          bool
	maxActiveRelays int
	metadata        types.LeaseMetadata
}

// WithDiscovery merges the built-in relay registry into the relay pool.
func WithDiscovery() ExposeOption {
	return func(s *exposeSettings) { s.discovery = true }
}

// WithOverlay prefers the IVNP overlay transport when relays offer it.
func WithOverlay() ExposeOption {
	return func(s *exposeSettings) { s.overlay = true }
}

// WithECH enables Encrypted Client Hello for relay connections.
func WithECH() ExposeOption {
	return func(s *exposeSettings) { s.ech = true }
}

// WithBanMITM rejects relays that fail the man-in-the-middle probe.
func WithBanMITM() ExposeOption {
	return func(s *exposeSettings) { s.banMITM = true }
}

// WithRawTCP requires relays with raw TCP stream support.
func WithRawTCP() ExposeOption {
	return func(s *exposeSettings) { s.rawTCP = true }
}

// WithMaxActiveRelays caps simultaneously active relay listeners. Values
// below 1 keep the sdk default.
func WithMaxActiveRelays(maxActiveRelays int) ExposeOption {
	return func(s *exposeSettings) {
		if maxActiveRelays > 0 {
			s.maxActiveRelays = maxActiveRelays
		}
	}
}

// WithMetadata attaches service metadata published through the relay
// directory.
func WithMetadata(metadata types.LeaseMetadata) ExposeOption {
	return func(s *exposeSettings) { s.metadata = metadata }
}

// assembleExposeConfig maps the facade configuration onto the sdk
// configuration. It is a pure function so tests can lock the mapping.
func assembleExposeConfig(cfg ExposeConfig, settings exposeSettings) sdk.ExposeConfig {
	return sdk.ExposeConfig{
		RelayURLs:       cfg.Relays,
		Discovery:       settings.discovery,
		Overlay:         settings.overlay,
		Identity:        cfg.Identity,
		UDPEnabled:      cfg.UDPEnabled,
		TCPEnabled:      settings.rawTCP,
		ECH:             settings.ech,
		BanMITM:         settings.banMITM,
		MaxActiveRelays: settings.maxActiveRelays,
		Metadata:        settings.metadata,
	}
}

// Expose creates relay listeners for cfg and returns them as one virtual
// net.Listener. It returns without waiting for network readiness; use
// (*Exposure).WaitReady for that. The identity must already be resolved;
// generate or load one with GenerateIdentity, ParseIdentity, or LoadIdentity.
func Expose(ctx context.Context, cfg ExposeConfig, opts ...ExposeOption) (*Exposure, error) {
	if ctx == nil {
		return nil, errNilContext
	}
	if strings.TrimSpace(cfg.Identity.Name) == "" {
		return nil, errors.New("portal: identity is required")
	}

	var settings exposeSettings
	for _, opt := range opts {
		if opt != nil {
			opt(&settings)
		}
	}
	if len(cfg.Relays) == 0 && !settings.discovery {
		return nil, errors.New("portal: at least one relay is required")
	}

	facadeCtx, cancel := context.WithCancel(ctx)
	inner, err := sdk.Expose(facadeCtx, assembleExposeConfig(cfg, settings))
	if err != nil {
		cancel()
		return nil, err
	}
	return &Exposure{inner: inner, ctx: facadeCtx, cancel: cancel}, nil
}

// DefaultRelays returns the canonical built-in relay URLs in registry order.
func DefaultRelays() []string {
	return slices.Clone(defaultRelays)
}

// defaultRelays normalizes the embedded registry once. The registry is a
// static manifest, so a normalization failure is a packaging bug and fails
// at init, mirroring the types package's manifest handling.
var defaultRelays = mustDefaultRelays()

func mustDefaultRelays() []string {
	relays, err := utils.NormalizeRelayURLs(types.BootstrapRelays...)
	if err != nil {
		panic(fmt.Errorf("portal: normalize built-in relays: %w", err))
	}
	return relays
}
