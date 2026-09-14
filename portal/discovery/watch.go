package discovery

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// FailureKind classifies a relay failure for discovery policy. Callers map
// their own failure vocabulary onto these kinds explicitly (the sdk does so
// in one place, next to its RelayFailure type), while the POLICY — which
// kind means permanent ban versus suppression/backoff — stays inside
// discovery.
type FailureKind string

const (
	FailureRuntime  FailureKind = "runtime"
	FailureTerminal FailureKind = "terminal"
	FailureMITM     FailureKind = "mitm"
)

// Controller is a thin discovery selection and refresh layer. It owns no
// relay runtime state: RelaySet owns failure/backoff/ban/candidate state,
// Exposure owns runtime/listener state, and the Controller only refreshes
// discovery, selects relays, and signals changes.
//
// The Controller is the policy owner: callers set explicit relays, max
// active relays, transport requirements, and local address via the Set*
// methods; the Controller builds the selection state internally and
// publishes concrete relay URLs through the Watch callback.
type Controller struct {
	relaySet *RelaySet
	changed  chan struct{}

	mu              sync.Mutex
	explicitRelays  []string
	maxActiveRelays int
	requireUDP      bool
	requireTCP      bool
	localAddress    string
}

// NewController creates a discovery controller from bootstrap relay URLs.
func NewController(bootstrapRelayURLs []string) *Controller {
	return &Controller{
		relaySet: NewRelaySet(bootstrapRelayURLs),
		changed:  make(chan struct{}, 1),
	}
}

// Report feeds a relay failure into discovery policy. FailureMITM
// permanently bans the relay; runtime and terminal failures unconfirm
// the relay and apply backoff suppression. Failures are deduped by
// RelaySet's own suppression state — once a relay is suppressed, further
// failures are skipped until suppression expires.
func (c *Controller) Report(relayURL string, kind FailureKind) {
	if c == nil || relayURL == "" {
		return
	}
	switch kind {
	case FailureMITM:
		c.relaySet.BanRelayURL(relayURL)
	default:
		c.relaySet.UnconfirmRelayURL(relayURL)
		if !c.relaySet.IsSuppressed(relayURL, time.Now().UTC()) {
			c.relaySet.RecordActiveFailure(relayURL, 1)
		}
	}
	c.signal()
}

// Deactivate drops a relay out of active selection while keeping its
// discovered descriptor as a candidate: the relay stays suppressed until
// the recovery backoff expires, after which discovery may select it again.
// Exposure.RemoveRelay routes an explicit disconnect here so a disconnected
// relay is not immediately re-selected from the candidate pool.
func (c *Controller) Deactivate(relayURL string) {
	if c == nil || relayURL == "" {
		return
	}
	c.relaySet.DeactivateRelayURL(relayURL)
	c.signal()
}

// Allow clears a relay's ban and suppression so an explicitly re-added
// relay is immediately eligible for selection again.
func (c *Controller) Allow(relayURL string) {
	if c == nil || relayURL == "" {
		return
	}
	c.relaySet.AllowRelayURL(relayURL)
	c.signal()
}

// SetExplicitRelays sets the explicit relay URLs for selection. The
// controller normalizes and stores a defensive copy, then signals the
// watch loop to re-evaluate immediately.
func (c *Controller) SetExplicitRelays(urls []string) {
	if c == nil {
		return
	}
	normalized, err := utils.NormalizeRelayURLs(urls...)
	if err != nil {
		normalized = urls
	}
	c.mu.Lock()
	c.explicitRelays = append([]string(nil), normalized...)
	c.mu.Unlock()
	c.signal()
}

// SetMaxActiveRelays caps auto-selected listener entries. Zero or
// negative values use the selection default.
func (c *Controller) SetMaxActiveRelays(n int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.maxActiveRelays = n
	c.mu.Unlock()
	c.signal()
}

// SetTransportRequirements sets UDP/TCP eligibility filters for
// auto-selected relays.
func (c *Controller) SetTransportRequirements(requireUDP, requireTCP bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.requireUDP = requireUDP
	c.requireTCP = requireTCP
	c.mu.Unlock()
	c.signal()
}

// SetLocalAddress sets the ingress identity address used by MOLS route
// selection to derive a deterministic row index.
func (c *Controller) SetLocalAddress(address string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.localAddress = address
	c.mu.Unlock()
}

func (c *Controller) signal() {
	select {
	case c.changed <- struct{}{}:
	default:
	}
}

// Watch refreshes discovery and publishes selected concrete relay URLs.
// activeRelays returns the caller's currently active relay URLs (typically
// from Exposure.ActiveRelays) so selection preserves connection-level
// stickiness and avoids listener churn. onChange applies the new concrete
// membership (the exposure's internal membership callback).
func (c *Controller) Watch(
	ctx context.Context,
	activeRelays func() []string,
	onChange func([]string) error,
) error {
	if c == nil {
		return errors.New("relay discovery: controller is nil")
	}
	if ctx == nil {
		return errors.New("relay discovery: context is nil")
	}
	if onChange == nil {
		return errors.New("relay discovery: change callback is nil")
	}

	refresher := NewRefresher(c.relaySet)
	ticker := time.NewTicker(DiscoveryPollInterval)
	defer ticker.Stop()

	var selected []string
	published := false
	refresh := true
	for {
		if refresh {
			if err := refresher.Refresh(ctx, nil); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				log.Warn().Err(err).Msg("relay discovery refresh failed; will retry")
			}
		}
		rs := c.buildRouteState(activeRelays)
		routes := c.relaySet.SelectRelays(rs)
		next := make([]string, 0, len(routes))
		for _, route := range routes {
			next = append(next, route.RelayURL)
		}
		if !published || !slices.Equal(selected, next) {
			if err := onChange(next); err != nil {
				return err
			}
			selected = next
			published = true
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			refresh = true
		case <-c.changed:
			refresh = false
		}
	}
}

func (c *Controller) buildRouteState(activeRelays func() []string) routeState {
	var active []string
	if activeRelays != nil {
		active = activeRelays()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return routeState{
		ExplicitRelayURLs: append([]string(nil), c.explicitRelays...),
		ActiveRelayURLs:   active,
		MaxActiveRelays:   c.maxActiveRelays,
		RequireUDP:        c.requireUDP,
		RequireTCP:        c.requireTCP,
		LocalAddress:      c.localAddress,
	}
}

// BootstrapRelayURLs returns the normalized built-in bootstrap relay URLs.
func BootstrapRelayURLs() ([]string, error) {
	return utils.NormalizeRelayURLs(types.BootstrapRelays...)
}

// ResolveRelayURLs resolves explicit relay URLs, optionally merged with
// the built-in bootstrap set. When includeBootstrap is false, only the
// explicit URLs are returned (normalized). When true, bootstrap URLs are
// merged with explicit URLs, deduped.
func ResolveRelayURLs(explicit []string, includeBootstrap bool) ([]string, error) {
	explicit, err := utils.NormalizeRelayURLs(explicit...)
	if err != nil {
		return nil, err
	}
	if !includeBootstrap {
		return explicit, nil
	}
	defaults, err := BootstrapRelayURLs()
	if err != nil {
		return nil, err
	}
	if len(defaults) == 0 {
		return explicit, nil
	}
	return utils.MergeRelayURLs(defaults, nil, explicit)
}
