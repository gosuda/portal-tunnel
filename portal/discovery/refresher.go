package discovery

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultRequestTimeout   = 15 * time.Second
	DiscoveryPollInterval   = 30 * time.Second
	defaultRecoveryFailures = 5
)

type OverlayRuntime interface {
	DiscoverRelay(context.Context, types.RelayDescriptor) (types.DiscoveryResponse, error)
	Sync([]RelayState) error
}

type Refresher struct {
	relaySet               *RelaySet
	httpClient             *http.Client
	overlay                OverlayRuntime
	directRecoveryFailures int
	lastAnnounceSuccess    map[string]bool
}

func NewRefresher(relaySet *RelaySet, overlay OverlayRuntime) *Refresher {
	return &Refresher{
		relaySet: relaySet,
		httpClient: utils.NewHTTPClient(
			utils.WithHTTPTLSConfig(&tls.Config{
				MinVersion: tls.VersionTLS12,
				NextProtos: []string{"http/1.1"},
			}),
			utils.WithoutHTTP2(),
			utils.WithHTTPTimeout(defaultRequestTimeout),
		),
		overlay:                overlay,
		directRecoveryFailures: defaultRecoveryFailures,
		lastAnnounceSuccess:    make(map[string]bool),
	}
}

func (r *Refresher) Refresh(ctx context.Context, self *types.RelayDescriptor) error {
	if r.overlay != nil {
		if err := r.refreshOverlay(ctx); err != nil && ctx.Err() == nil {
			log.Warn().
				Err(err).
				Msg("overlay discovery failed")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if err := r.refreshHTTPS(ctx); err != nil {
		return err
	}
	if self != nil {
		if err := r.announceSelf(ctx, *self); err != nil {
			return err
		}
	}
	return nil
}

func (r *Refresher) announceSelf(ctx context.Context, descriptor types.RelayDescriptor) error {
	req := types.DiscoveryAnnounceRequest{
		ProtocolVersion: types.DiscoveryVersion,
		Descriptor:      descriptor,
	}

	for _, relayURL := range r.relaySet.BootstrapRelayURLs() {
		if relayURL == descriptor.APIHTTPSAddr {
			continue
		}
		baseURL, err := url.Parse(relayURL)
		if err != nil {
			if r.shouldLogAnnounce(relayURL, false) {
				log.Warn().
					Err(err).
					Str("relay", relayURL).
					Msg("relay discovery announce target skipped")
			}
			continue
		}

		if err := utils.HTTPDoAPIPath(ctx, r.httpClient, baseURL, http.MethodPost, types.PathDiscoveryAnnounce, req, nil, nil); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if r.shouldLogAnnounce(relayURL, false) {
				log.Warn().
					Err(err).
					Str("relay", relayURL).
					Msg("relay discovery announce failed")
			}
			continue
		}
		if r.shouldLogAnnounce(relayURL, true) {
			log.Info().
				Str("relay", relayURL).
				Msg("relay discovery announce succeeded")
		}
	}
	return nil
}

func (r *Refresher) shouldLogAnnounce(relayURL string, success bool) bool {
	previous, ok := r.lastAnnounceSuccess[relayURL]
	if ok && previous == success {
		return false
	}
	r.lastAnnounceSuccess[relayURL] = success
	return true
}

func (r *Refresher) refreshHTTPS(ctx context.Context) error {
	r.relaySet.mu.RLock()
	states := make([]RelayState, 0, len(r.relaySet.relays))
	for _, state := range r.relaySet.relays {
		states = append(states, state)
	}
	r.relaySet.mu.RUnlock()

	now := time.Now().UTC()
	for _, state := range states {
		if state.Banned {
			continue
		}
		if !state.hasObservedDescriptor() {
			if !state.Bootstrap {
				continue
			}
		} else if !state.Bootstrap {
			if !state.nextDiscoveryRefreshAt.IsZero() && state.nextDiscoveryRefreshAt.After(now) {
				continue
			}
		}
		relayURL := state.Descriptor.APIHTTPSAddr
		if relayURL == "" {
			continue
		}

		recoveryFailures := r.directRecoveryFailures
		if state.Bootstrap {
			recoveryFailures = 0
		}

		baseURL, err := url.Parse(relayURL)
		if err != nil {
			if recoveryFailures > 0 {
				r.logDiscoveryFailure(relayURL, relayURL, recoveryFailures, err)
			}
			continue
		}

		startedAt := time.Now()
		var resp types.DiscoveryResponse
		if err := utils.HTTPDoAPIPath(ctx, r.httpClient, baseURL, http.MethodGet, types.PathDiscovery, nil, nil, &resp); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if recoveryFailures > 0 {
				r.logDiscoveryFailure(relayURL, relayURL, recoveryFailures, err)
			}
			continue
		}
		measuredAt := time.Now().UTC()

		if _, err := r.relaySet.ApplyRelayDiscoveryResponse(relayURL, resp, measuredAt); err != nil {
			if recoveryFailures > 0 {
				r.logDiscoveryFailure(relayURL, relayURL, recoveryFailures, err)
			}
			continue
		}
		r.relaySet.RecordDiscoveryRTT(relayURL, time.Since(startedAt), measuredAt)
	}
	return nil
}

func (r *Refresher) refreshOverlay(ctx context.Context) error {
	states := r.relaySet.OverlayPeerStates()
	if len(states) == 0 {
		return nil
	}
	if err := r.overlay.Sync(states); err != nil {
		return err
	}
	relaySetChanged := false
	for _, state := range states {
		if !state.nextDiscoveryRefreshAt.IsZero() && state.nextDiscoveryRefreshAt.After(time.Now().UTC()) {
			continue
		}
		relay := state.Descriptor
		recoveryFailures := r.directRecoveryFailures
		if state.Bootstrap {
			recoveryFailures = 0
		}
		startedAt := time.Now()
		resp, err := r.overlay.DiscoverRelay(ctx, relay)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if recoveryFailures > 0 {
				r.logDiscoveryFailure(relay.APIHTTPSAddr, relay.APIHTTPSAddr, recoveryFailures, err)
			}
			continue
		}

		measuredAt := time.Now().UTC()
		changed, err := r.relaySet.ApplyRelayDiscoveryResponse(relay.APIHTTPSAddr, resp, measuredAt)
		if err != nil {
			if recoveryFailures > 0 {
				r.logDiscoveryFailure(relay.APIHTTPSAddr, relay.APIHTTPSAddr, recoveryFailures, err)
			}
			continue
		}
		r.relaySet.RecordDiscoveryRTT(relay.APIHTTPSAddr, time.Since(startedAt), measuredAt)
		if changed {
			relaySetChanged = true
		}
	}
	if !relaySetChanged {
		return nil
	}
	if err := r.overlay.Sync(r.relaySet.OverlayPeerStates()); err != nil {
		return err
	}
	return nil
}

func (r *Refresher) logDiscoveryFailure(targetRelayURL, sourceURL string, recoveryFailures int, err error) {
	backedOff, backoffReason, failureCount := r.relaySet.RecordDiscoveryFailure(targetRelayURL, err, recoveryFailures)
	if !backedOff {
		return
	}

	event := log.Warn().
		Err(err).
		Str("relay", sourceURL).
		Bool("backed_off", true).
		Str("reason", backoffReason)
	if failureCount > 0 {
		event = event.Int("discovery_failures", failureCount)
	}
	event.Msg("discovery source retry delayed")
}
