package discovery

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/rs/zerolog/log"
)

// Watch refreshes relay discovery and publishes the currently selected
// concrete relay URLs. Discovery owns refresh and selection; the callback owns
// what to do with the resulting membership.
func Watch(
	ctx context.Context,
	bootstrapRelayURLs []string,
	state func() RouteState,
	onChange func([]string) error,
) error {
	if ctx == nil {
		return errors.New("relay discovery: context is nil")
	}
	if state == nil {
		return errors.New("relay discovery: state callback is nil")
	}
	if onChange == nil {
		return errors.New("relay discovery: change callback is nil")
	}

	relaySet := NewRelaySet(bootstrapRelayURLs)
	refresher := NewRefresher(relaySet)
	ticker := time.NewTicker(DiscoveryPollInterval)
	defer ticker.Stop()

	var selected []string
	published := false
	for {
		if err := refresher.Refresh(ctx, nil); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Warn().Err(err).Msg("relay discovery refresh failed; will retry")
		} else {
			routeState := state()
			routeState.ActiveRelayURLs = append([]string(nil), selected...)
			routes := relaySet.SelectRelays(routeState)
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
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
