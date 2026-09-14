package discovery

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/rs/zerolog/log"
)

// Controller is a thin discovery selection and refresh layer. It owns no
// relay runtime state: RelaySet owns failure/backoff/ban/candidate state,
// Exposure owns runtime/listener state, and the Controller only refreshes
// discovery, selects relays, and signals changes.
type Controller struct {
	relaySet *RelaySet
	changed  chan struct{}
}

// NewController creates a discovery controller from bootstrap relay URLs.
func NewController(bootstrapRelayURLs []string) *Controller {
	return &Controller{
		relaySet: NewRelaySet(bootstrapRelayURLs),
		changed:  make(chan struct{}, 1),
	}
}

// ReportFailure removes a failed relay from active selection with backoff.
// It applies the failure directly to RelaySet: UnconfirmRelayURL drops the
// listener confirmation, and RecordActiveFailure applies backoff suppression.
// Failures are deduped by RelaySet's own suppression state — once a relay is
// suppressed, further RecordActiveFailure calls are skipped until the
// suppression expires, at which point a new failure records again.
func (c *Controller) ReportFailure(relayURL string) {
	if c == nil || relayURL == "" {
		return
	}
	c.relaySet.UnconfirmRelayURL(relayURL)
	if !c.relaySet.IsSuppressed(relayURL, time.Now().UTC()) {
		c.relaySet.RecordActiveFailure(relayURL, 1)
	}
	c.signal()
}

// Ban permanently excludes a relay from this controller's selections.
func (c *Controller) Ban(relayURL string) {
	if c == nil || relayURL == "" {
		return
	}
	c.relaySet.BanRelayURL(relayURL)
	c.signal()
}

func (c *Controller) signal() {
	select {
	case c.changed <- struct{}{}:
	default:
	}
}

// Reconcile prompts the controller to re-evaluate its relay selection
// immediately. It is intended for callers that have changed policy inputs
// (such as the agent's max_active_relays) so membership reconciles without
// waiting for the next poll tick. It signals the Watch loop, which re-reads
// its state callback and republishes if the selection changed.
func (c *Controller) Reconcile() {
	if c == nil {
		return
	}
	c.signal()
}

// Watch refreshes discovery and publishes selected concrete relay URLs.
// The state callback MUST supply the caller's current active relay URLs
// (typically derived from the exposure's live relay statuses) via
// RouteState.ActiveRelayURLs so selection preserves connection-level
// stickiness and avoids listener churn.
func (c *Controller) Watch(
	ctx context.Context,
	state func() RouteState,
	onChange func([]string) error,
) error {
	if c == nil {
		return errors.New("relay discovery: controller is nil")
	}
	if ctx == nil {
		return errors.New("relay discovery: context is nil")
	}
	if state == nil {
		return errors.New("relay discovery: state callback is nil")
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
		routeState := state()
		routes := c.relaySet.SelectRelays(routeState)
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
