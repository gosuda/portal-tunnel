package discovery

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultRequestTimeout   = 15 * time.Second
	DiscoveryPollInterval   = 30 * time.Second
	defaultRecoveryFailures = 5
	maxConcurrentRefresh    = 8
	maxConcurrentAnnounce   = 8
)

type Refresher struct {
	// DiscoverOverlay exchanges catalogs without measuring public ingress health.
	DiscoverOverlay        func(context.Context, types.RelayDescriptor) (types.DiscoveryResponse, error)
	nextOverlayRefresh     map[string]time.Time
	relaySet               *RelaySet
	httpClient             *http.Client
	directRecoveryFailures int
	lastAnnounceSuccess    map[string]bool
	lastAnnounceMu         sync.Mutex
}

func NewRefresher(relaySet *RelaySet) *Refresher {
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
		directRecoveryFailures: defaultRecoveryFailures,
		lastAnnounceSuccess:    make(map[string]bool),
	}
}

func (r *Refresher) Refresh(ctx context.Context, self *types.RelayDescriptor) error {
	if err := r.refreshHTTPS(ctx); err != nil {
		return err
	}
	if self != nil {
		if err := r.announceSelf(ctx, *self); err != nil {
			return err
		}
	}
	if r.DiscoverOverlay != nil {
		return r.refreshOverlay(ctx)
	}
	return nil
}

// Overlay polls are slower than public HTTPS probes and have independent retry
// state. An overlay failure must not evict a healthy public relay or affect MOLS.
func (r *Refresher) refreshOverlay(ctx context.Context) error {
	now := time.Now().UTC()
	states := r.relaySet.currentRelayStates(now)
	if r.nextOverlayRefresh == nil {
		r.nextOverlayRefresh = make(map[string]time.Time)
	}
	live := make(map[string]bool, len(states))
	var candidates []RelayState
	for _, state := range states {
		desc := state.Descriptor
		key := desc.APIHTTPSAddr + "/" + desc.IVNPDestination
		live[key] = true
		if state.Banned || desc.IVNPDestination == "" || !desc.ExpiresAt.After(now) || r.nextOverlayRefresh[key].After(now) {
			continue
		}
		candidates = append(candidates, state)
	}
	for key := range r.nextOverlayRefresh {
		if !live[key] {
			delete(r.nextOverlayRefresh, key)
		}
	}
	slices.SortFunc(candidates, func(a, b RelayState) int {
		left := r.nextOverlayRefresh[a.Descriptor.APIHTTPSAddr+"/"+a.Descriptor.IVNPDestination]
		right := r.nextOverlayRefresh[b.Descriptor.APIHTTPSAddr+"/"+b.Descriptor.IVNPDestination]
		return left.Compare(right)
	})
	if len(candidates) > maxConcurrentRefresh {
		candidates = candidates[:maxConcurrentRefresh]
	}
	for _, state := range candidates {
		r.nextOverlayRefresh[state.Descriptor.APIHTTPSAddr+"/"+state.Descriptor.IVNPDestination] = now.Add(2 * time.Minute)
	}
	return parallel(candidates, 4, func(state RelayState) error {
		resp, err := r.DiscoverOverlay(ctx, state.Descriptor)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			log.Debug().Err(err).Str("relay", state.Descriptor.APIHTTPSAddr).Msg("IVNP discovery unavailable")
			return nil
		}
		if resp.ProtocolVersion != types.DiscoveryVersion {
			return nil
		}
		// Gossip admission only: reaching I2P does not verify HTTPS reachability.
		_, err = r.relaySet.ApplyRelayDiscoveryResponse("", resp, time.Now().UTC())
		return err
	})
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

	return parallel(targets, maxConcurrentAnnounce, func(relayURL string) error {
		if relayURL == descriptor.APIHTTPSAddr {
			return nil
		}
		baseURL, err := url.Parse(relayURL)
		if err != nil {
			if r.shouldLogAnnounce(relayURL, false) {
				log.Warn().Err(err).Str("relay", relayURL).Msg("relay discovery announce target skipped")
			}
			return nil
		}
		if err := utils.HTTPDoAPIPath(ctx, r.httpClient, baseURL, http.MethodPost, types.PathDiscoveryAnnounce, req, nil, nil); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if r.shouldLogAnnounce(relayURL, false) {
				log.Warn().Err(err).Str("relay", relayURL).Msg("relay discovery announce failed")
			}
			return nil
		}
		if r.shouldLogAnnounce(relayURL, true) {
			log.Info().Str("relay", relayURL).Msg("relay discovery announce succeeded")
		}
		return nil
	})
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

	return parallel(candidates, maxConcurrentRefresh, func(state RelayState) error {
		return r.refreshOneHTTPS(ctx, state)
	})
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

func parallel[T any](items []T, limit int, fn func(T) error) error {
	var wg sync.WaitGroup
	sem := make(chan struct{}, limit)
	errs := make(chan error, 1)
	for _, item := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(item T) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := fn(item); err != nil {
				select {
				case errs <- err:
				default:
				}
			}
		}(item)
	}
	wg.Wait()
	select {
	case err := <-errs:
		return err
	default:
		return nil
	}
}

func (r *Refresher) logDiscoveryFailure(targetRelayURL, sourceURL string, recoveryFailures int, err error) {
	backedOff, backoffReason, failureCount := r.relaySet.RecordDiscoveryFailure(targetRelayURL, recoveryFailures)
	if !backedOff {
		return
	}

	event := log.Debug().
		Err(err).
		Str("relay", sourceURL).
		Bool("backed_off", true).
		Str("reason", backoffReason)
	if failureCount > 0 {
		event = event.Int("discovery_failures", failureCount)
	}
	if backoffReason == "unhealthy" {
		log.Warn().
			Err(err).
			Str("relay", sourceURL).
			Bool("backed_off", true).
			Str("reason", backoffReason).
			Int("discovery_failures", failureCount).
			Msg("discovery source removed from relay pool")
		return
	}
	event.Msg("discovery source retry delayed")
}
