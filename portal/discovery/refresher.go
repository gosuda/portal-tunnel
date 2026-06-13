package discovery

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultRequestTimeout    = 15 * time.Second
	DiscoveryPollInterval    = 30 * time.Second
	defaultRecoveryFailures  = 5
	maxConcurrentRefresh     = 8
	maxConcurrentAnnounce    = 8
	maxConcurrentOverlayDial = 8
)

type OverlayRuntime interface {
	DiscoverRelay(context.Context, types.RelayDescriptor) (types.DiscoveryResponse, error)
	Sync([]types.RelayDescriptor) error
}

type Refresher struct {
	relaySet               *RelaySet
	httpClient             *http.Client
	overlay                OverlayRuntime
	directRecoveryFailures int
	lastAnnounceSuccess    map[string]bool
	lastAnnounceMu         sync.Mutex
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

	targets := r.relaySet.BootstrapRelayURLs()
	if len(targets) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentAnnounce)
	errCh := make(chan error, 1)

	for _, relayURL := range targets {
		if relayURL == descriptor.APIHTTPSAddr {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(relayURL string) {
			defer wg.Done()
			defer func() { <-sem }()

			baseURL, err := url.Parse(relayURL)
			if err != nil {
				if r.shouldLogAnnounce(relayURL, false) {
					log.Warn().
						Err(err).
						Str("relay", relayURL).
						Msg("relay discovery announce target skipped")
				}
				return
			}

			if err := utils.HTTPDoAPIPath(ctx, r.httpClient, baseURL, http.MethodPost, types.PathDiscoveryAnnounce, req, nil, nil); err != nil {
				if ctx.Err() != nil {
					select {
					case errCh <- ctx.Err():
					default:
					}
					return
				}
				if r.shouldLogAnnounce(relayURL, false) {
					log.Warn().
						Err(err).
						Str("relay", relayURL).
						Msg("relay discovery announce failed")
				}
				return
			}
			if r.shouldLogAnnounce(relayURL, true) {
				log.Info().
					Str("relay", relayURL).
					Msg("relay discovery announce succeeded")
			}
		}(relayURL)
	}

	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func (r *Refresher) shouldLogAnnounce(relayURL string, success bool) bool {
	r.lastAnnounceMu.Lock()
	defer r.lastAnnounceMu.Unlock()
	previous, ok := r.lastAnnounceSuccess[relayURL]
	if ok && previous == success {
		return false
	}
	r.lastAnnounceSuccess[relayURL] = success
	return true
}

// sortRefreshCandidates orders relays so that the most important sources are
// refreshed first under concurrency limits: bootstrap, then confirmed, then
// discovered healthy relays, and finally recovery/backoff candidates.
func sortRefreshCandidates(states []RelayState) []RelayState {
	slices.SortFunc(states, func(a, b RelayState) int {
		if a.Bootstrap != b.Bootstrap {
			if a.Bootstrap {
				return -1
			}
			return 1
		}
		if a.Confirmed != b.Confirmed {
			if a.Confirmed {
				return -1
			}
			return 1
		}
		if a.discoveryFailures != b.discoveryFailures {
			return a.discoveryFailures - b.discoveryFailures
		}
		if !a.nextDiscoveryRefreshAt.Equal(b.nextDiscoveryRefreshAt) {
			if a.nextDiscoveryRefreshAt.IsZero() {
				return -1
			}
			if b.nextDiscoveryRefreshAt.IsZero() {
				return 1
			}
			if a.nextDiscoveryRefreshAt.Before(b.nextDiscoveryRefreshAt) {
				return -1
			}
			return 1
		}
		return 0
	})
	return states
}

func (r *Refresher) refreshHTTPS(ctx context.Context) error {
	now := time.Now().UTC()
	candidates := r.relaySet.refreshCandidates(now)
	if len(candidates) == 0 {
		return nil
	}
	candidates = sortRefreshCandidates(candidates)

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentRefresh)
	errCh := make(chan error, 1)

	for _, state := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(state RelayState) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := r.refreshOneHTTPS(ctx, state); err != nil {
				select {
				case errCh <- err:
				default:
				}
			}
		}(state)
	}

	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func (r *Refresher) refreshOneHTTPS(ctx context.Context, state RelayState) error {
	relayURL := state.Descriptor.APIHTTPSAddr

	recoveryFailures := r.directRecoveryFailures
	if state.Bootstrap {
		recoveryFailures = 0
	}

	baseURL, err := url.Parse(relayURL)
	if err != nil {
		if recoveryFailures > 0 {
			r.logDiscoveryFailure(relayURL, relayURL, recoveryFailures, err)
		}
		return nil
	}
	client := r.httpClient
	var closeClient func()
	if utils.IsLocalRelayHost(baseURL.Hostname()) {
		_, localClient, transport, err := utils.NewHTTPTLSClient(ctx, baseURL, defaultRequestTimeout)
		if err != nil {
			if recoveryFailures > 0 {
				r.logDiscoveryFailure(relayURL, relayURL, recoveryFailures, err)
			}
			return nil
		}
		client = localClient
		closeClient = transport.CloseIdleConnections
	}

	startedAt := time.Now()
	var resp types.DiscoveryResponse
	if err := utils.HTTPDoAPIPath(ctx, client, baseURL, http.MethodGet, types.PathDiscovery, nil, nil, &resp); err != nil {
		if closeClient != nil {
			closeClient()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if recoveryFailures > 0 {
			r.logDiscoveryFailure(relayURL, relayURL, recoveryFailures, err)
		}
		return nil
	}
	if closeClient != nil {
		closeClient()
	}
	measuredAt := time.Now().UTC()

	if _, err := r.relaySet.ApplyRelayDiscoveryResponse(relayURL, resp, measuredAt); err != nil {
		if recoveryFailures > 0 {
			r.logDiscoveryFailure(relayURL, relayURL, recoveryFailures, err)
		}
		return nil
	}
	r.relaySet.RecordDiscoveryRTT(relayURL, time.Since(startedAt), measuredAt)
	return nil
}

func (r *Refresher) refreshOverlay(ctx context.Context) error {
	now := time.Now().UTC()
	states := r.relaySet.overlayPeerRelayStates(now)
	if len(states) == 0 {
		return nil
	}
	descriptors := make([]types.RelayDescriptor, 0, len(states))
	for _, state := range states {
		descriptors = append(descriptors, state.Descriptor)
	}
	if err := r.overlay.Sync(descriptors); err != nil {
		return err
	}

	candidates := r.relaySet.overlayRefreshCandidates(now)
	if len(candidates) == 0 {
		return nil
	}
	candidates = sortRefreshCandidates(candidates)

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentOverlayDial)
	errCh := make(chan error, 1)
	var relaySetChanged atomic.Bool

	for _, state := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(state RelayState) {
			defer wg.Done()
			defer func() { <-sem }()
			changed, err := r.refreshOneOverlay(ctx, state)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
			if changed {
				relaySetChanged.Store(true)
			}
		}(state)
	}

	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
	}

	if !relaySetChanged.Load() {
		return nil
	}
	if err := r.overlay.Sync(r.relaySet.OverlayPeerDescriptor()); err != nil {
		return err
	}
	return nil
}

func (r *Refresher) refreshOneOverlay(ctx context.Context, state RelayState) (bool, error) {
	relay := state.Descriptor
	recoveryFailures := r.directRecoveryFailures
	if state.Bootstrap {
		recoveryFailures = 0
	}
	startedAt := time.Now()
	resp, err := r.overlay.DiscoverRelay(ctx, relay)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if recoveryFailures > 0 {
			r.logDiscoveryFailure(relay.APIHTTPSAddr, relay.APIHTTPSAddr, recoveryFailures, err)
		}
		return false, nil
	}

	measuredAt := time.Now().UTC()
	changed, err := r.relaySet.ApplyRelayDiscoveryResponse(relay.APIHTTPSAddr, resp, measuredAt)
	if err != nil {
		if recoveryFailures > 0 {
			r.logDiscoveryFailure(relay.APIHTTPSAddr, relay.APIHTTPSAddr, recoveryFailures, err)
		}
		return false, nil
	}
	r.relaySet.RecordDiscoveryRTT(relay.APIHTTPSAddr, time.Since(startedAt), measuredAt)
	return changed, nil
}

func (r *Refresher) logDiscoveryFailure(targetRelayURL, sourceURL string, recoveryFailures int, err error) {
	backedOff, backoffReason, failureCount := r.relaySet.RecordDiscoveryFailure(targetRelayURL, recoveryFailures)
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
	if backoffReason == "unhealthy" {
		event.Msg("discovery source removed from relay pool")
		return
	}
	event.Msg("discovery source retry delayed")
}
