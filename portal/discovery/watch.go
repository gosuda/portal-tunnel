package discovery

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Controller owns discovery refresh, runtime feedback, and relay selection.
type Controller struct {
	relaySet *RelaySet
	changed  chan struct{}

	mu              sync.RWMutex
	activeRelayURLs []string
	failedRelays    map[string]struct{} // per selection episode: markers cleared on republish so a reselected relay's later failure reports again
}

// NewController creates a discovery controller from bootstrap relay URLs.
func NewController(bootstrapRelayURLs []string) *Controller {
	return &Controller{
		relaySet:     NewRelaySet(bootstrapRelayURLs),
		changed:      make(chan struct{}, 1),
		failedRelays: make(map[string]struct{}),
	}
}

// ReportActive replaces the relay URLs that currently have live SDK listeners.
func (c *Controller) ReportActive(relayURLs []string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	previous := c.activeRelayURLs
	c.activeRelayURLs = append([]string(nil), relayURLs...)
	for _, relayURL := range relayURLs {
		delete(c.failedRelays, relayURL)
	}
	c.mu.Unlock()

	for _, relayURL := range previous {
		if !slices.Contains(relayURLs, relayURL) {
			c.relaySet.UnconfirmRelayURL(relayURL)
		}
	}
	for _, relayURL := range relayURLs {
		c.relaySet.ConfirmRelayURL(relayURL)
	}
	c.signal()
}

// ReportFailure removes a failed relay from active selection with backoff.
func (c *Controller) ReportFailure(relayURL string) {
	if c == nil || relayURL == "" {
		return
	}
	c.mu.Lock()
	if _, reported := c.failedRelays[relayURL]; reported {
		c.mu.Unlock()
		return
	}
	c.failedRelays[relayURL] = struct{}{}
	c.activeRelayURLs = slices.DeleteFunc(c.activeRelayURLs, func(active string) bool {
		return active == relayURL
	})
	c.mu.Unlock()
	c.relaySet.UnconfirmRelayURL(relayURL)
	c.relaySet.RecordActiveFailure(relayURL, 1)
	c.signal()
}

// Ban permanently excludes a relay from this controller's selections.
func (c *Controller) Ban(relayURL string) {
	if c == nil || relayURL == "" {
		return
	}
	c.relaySet.BanRelayURL(relayURL)
	c.mu.Lock()
	c.activeRelayURLs = slices.DeleteFunc(c.activeRelayURLs, func(active string) bool {
		return active == relayURL
	})
	c.mu.Unlock()
	c.signal()
}

func (c *Controller) signal() {
	select {
	case c.changed <- struct{}{}:
	default:
	}
}

func (c *Controller) activeRelays() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string(nil), c.activeRelayURLs...)
}

// beginSelectionEpisode starts a new failure-dedupe episode for every relay in
// the published selection set, clearing their failedRelays markers so a later
// ReportFailure reports again even if the relay failed in a prior episode.
func (c *Controller) beginSelectionEpisode(relayURLs []string) {
	c.mu.Lock()
	for _, relayURL := range relayURLs {
		delete(c.failedRelays, relayURL)
	}
	c.mu.Unlock()
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
		routeState.ActiveRelayURLs = c.activeRelays()
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
			c.beginSelectionEpisode(next)
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
