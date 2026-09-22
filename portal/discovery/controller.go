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
// methods, and forward add/remove relay user intent through AddRelay /
// RemoveRelay, which apply the explicit-list change together with the
// matching eligibility change as one atomic unit. Next returns each changed
// desired relay set as a value for the runtime to reconcile.
type Controller struct {
	relaySet  *RelaySet
	refresher *Refresher
	changed   chan struct{}
	selected  []string
	published bool
	refreshAt time.Time

	mu              sync.Mutex
	explicitRelays  []string
	activeRelays    []string
	maxActiveRelays int
	requireUDP      bool
	requireTCP      bool
	localAddress    string
	salt            uint64
}

// NewController creates a discovery controller from bootstrap relay URLs.
func NewController(bootstrapRelayURLs []string) *Controller {
	relaySet := NewRelaySet(bootstrapRelayURLs)
	return &Controller{
		relaySet:  relaySet,
		refresher: NewRefresher(relaySet),
		changed:   make(chan struct{}, 1),
	}
}

// Report feeds a relay failure into discovery policy. FailureMITM
// permanently bans the relay; runtime and terminal failures apply
// backoff suppression. Failures are deduped by
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
		if !c.relaySet.IsSuppressed(relayURL, time.Now().UTC()) {
			c.relaySet.RecordActiveFailure(relayURL, 1)
		}
	}
	c.signal()
}

// SetExplicitRelays replaces the explicit relay URLs for selection. The
// controller normalizes and stores a defensive copy, gives every URL a
// durable RelaySet candidate state (so later failure reports stick for
// custom relays that never entered through discovery), and signals the
// selection loop to re-evaluate immediately.
func (c *Controller) SetExplicitRelays(urls []string) {
	if c == nil {
		return
	}
	normalized, err := utils.NormalizeRelayURLs(urls...)
	if err != nil {
		normalized = urls
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.explicitRelays = append([]string(nil), normalized...)
	for _, relayURL := range normalized {
		c.relaySet.EnsureRelayURL(relayURL)
	}
	c.signal()
}

// SetActiveRelays supplies the runtime's current active-session snapshot for
// selection stickiness. Discovery retains the value but does not own or query
// the sessions that produced it.
func (c *Controller) SetActiveRelays(urls []string) {
	if c == nil {
		return
	}
	urls = append([]string(nil), urls...)
	c.mu.Lock()
	if slices.Equal(c.activeRelays, urls) {
		c.mu.Unlock()
		return
	}
	c.activeRelays = urls
	c.mu.Unlock()
	c.signal()
}

// AddRelay applies one add-relay user intent as a single atomic unit: the
// explicit-list change, the durable RelaySet candidate state, and the
// eligibility reset (ban and suppression cleared, so a re-added relay is
// immediately selectable) all serialize together under the controller lock.
// A concurrent RemoveRelay can therefore never interleave a stale eligibility
// reset past the removal — the final state always matches one serial order.
func (c *Controller) AddRelay(relayURL string) {
	if c == nil || relayURL == "" {
		return
	}
	if normalized, err := utils.NormalizeRelayURL(relayURL); err == nil {
		relayURL = normalized
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !slices.Contains(c.explicitRelays, relayURL) {
		c.explicitRelays = append(c.explicitRelays, relayURL)
		slices.Sort(c.explicitRelays)
	}
	c.relaySet.AllowRelayURL(relayURL)
	c.signal()
}

// RemoveRelay applies one remove-relay user intent as a single atomic unit:
// the explicit-list change and the selection deactivation (dropped from
// active selection, kept as a future candidate) serialize together under
// the controller lock, symmetric with AddRelay.
func (c *Controller) RemoveRelay(relayURL string) {
	if c == nil || relayURL == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	next := make([]string, 0, len(c.explicitRelays))
	for _, existing := range c.explicitRelays {
		if existing != relayURL {
			next = append(next, existing)
		}
	}
	c.explicitRelays = next
	c.relaySet.DeactivateRelayURL(relayURL)
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

// SetSelectionSalt sets the per-client secret mixed into all MOLS ranking
// hashes, making rankings unpredictable to outside observers and immune to
// relay URL grinding. The sdk derives a stable value from the identity
// private key, so rankings stay stable across restarts.
func (c *Controller) SetSelectionSalt(salt uint64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.salt = salt
	c.mu.Unlock()
}

func (c *Controller) signal() {
	select {
	case c.changed <- struct{}{}:
	default:
	}
}

// Next refreshes discovery as needed and blocks until the desired relay set
// changes. The caller remains responsible for reconciling the result.
func (c *Controller) Next(ctx context.Context) ([]string, error) {
	if c == nil {
		return nil, errors.New("relay discovery: controller is nil")
	}
	if ctx == nil {
		return nil, errors.New("relay discovery: context is nil")
	}
	for {
		now := time.Now()
		refresh := !c.published || !now.Before(c.refreshAt)
		if refresh {
			if err := c.refresher.Refresh(ctx, nil); err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				log.Warn().Err(err).Msg("relay discovery refresh failed; will retry")
			}
			c.refreshAt = time.Now().Add(DiscoveryPollInterval)
		}
		rs := c.buildRouteState()
		next := c.relaySet.SelectRelays(rs)
		if !c.published || !slices.Equal(c.selected, next) {
			c.selected = append([]string(nil), next...)
			c.published = true
			return next, nil
		}

		wait := time.Until(c.refreshAt)
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil, ctx.Err()
		case <-timer.C:
		case <-c.changed:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
	}
}

func (c *Controller) buildRouteState() routeState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return routeState{
		ExplicitRelayURLs: append([]string(nil), c.explicitRelays...),
		ActiveRelayURLs:   append([]string(nil), c.activeRelays...),
		MaxActiveRelays:   c.maxActiveRelays,
		RequireUDP:        c.requireUDP,
		RequireTCP:        c.requireTCP,
		LocalAddress:      c.localAddress,
		SelectionSalt:     c.salt,
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
	return utils.NormalizeRelayURLs(append(defaults, explicit...)...)
}
