package discovery

import (
	"context"
	"crypto/tls"
	"errors"
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
	relaySet         *RelaySet
	httpClient       *http.Client
	publicHTTPClient *http.Client
}

func NewRefresher(relaySet *RelaySet) *Refresher {
	client := utils.NewHTTPClient(
		utils.WithHTTPTLSConfig(&tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		}),
		utils.WithoutHTTP2(),
		utils.WithHTTPTimeout(defaultRequestTimeout),
		utils.WithHTTPCheckRedirect(rejectDiscoveryRedirect),
	)
	publicTransport := client.Transport.(*http.Transport).Clone()
	publicTransport.Proxy = nil
	publicTransport.DialContext = dialPublicRelay

	return &Refresher{
		relaySet:   relaySet,
		httpClient: client,
		publicHTTPClient: &http.Client{
			Transport:     publicTransport,
			CheckRedirect: rejectDiscoveryRedirect,
			Timeout:       defaultRequestTimeout,
		},
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

	return parallel(targets, maxConcurrentAnnounce, func(relayURL string) error {
		if relayURL == descriptor.APIHTTPSAddr {
			return nil
		}
		baseURL, err := url.Parse(relayURL)
		if err != nil {
			log.Warn().Err(err).Str("relay", relayURL).Msg("relay discovery announce target skipped")
			return nil
		}
		if err := utils.HTTPDoAPIPath(ctx, r.httpClient, baseURL, http.MethodPost, types.PathDiscoveryAnnounce, req, nil, nil); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Debug().Err(err).Str("relay", relayURL).Msg("relay discovery announce failed")
			return nil
		}
		log.Debug().Str("relay", relayURL).Msg("relay discovery announce succeeded")
		return nil
	})
}

func sortRefreshCandidates(states []relayState) []relayState {
	slices.SortFunc(states, func(a, b relayState) int {
		if a.Bootstrap != b.Bootstrap {
			if a.Bootstrap {
				return -1
			}
			return 1
		}
		if a.discoveryFailures != b.discoveryFailures {
			return a.discoveryFailures - b.discoveryFailures
		}
		return a.nextDiscoveryRefreshAt.Compare(b.nextDiscoveryRefreshAt)
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

	return parallel(candidates, maxConcurrentRefresh, func(state relayState) error {
		return r.refreshOneHTTPS(ctx, state)
	})
}

func (r *Refresher) refreshOneHTTPS(ctx context.Context, state relayState) error {
	relayURL := state.Descriptor.APIHTTPSAddr

	baseURL, err := url.Parse(relayURL)
	if err != nil {
		r.logDiscoveryFailure(state, err)
		return nil
	}
	client := r.httpClient
	if !state.Bootstrap {
		if err := requirePublicRelayURL(relayURL); err != nil {
			r.logDiscoveryFailure(state, err)
			return nil
		}
		client = r.publicHTTPClient
	} else if utils.IsLocalRelayHost(baseURL.Hostname()) {
		_, localClient, transport, err := utils.NewHTTPTLSClient(ctx, baseURL, defaultRequestTimeout)
		if err != nil {
			r.logDiscoveryFailure(state, err)
			return nil
		}
		localClient.CheckRedirect = rejectDiscoveryRedirect
		client = localClient
		defer transport.CloseIdleConnections()
	}

	startedAt := time.Now()
	var resp types.DiscoveryResponse
	if err := utils.HTTPDoAPIPath(ctx, client, baseURL, http.MethodGet, types.PathDiscovery, nil, nil, &resp); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r.logDiscoveryFailure(state, err)
		return nil
	}
	measuredAt := time.Now().UTC()

	if _, err := r.relaySet.ApplyRelayDiscoveryResponse(relayURL, resp, measuredAt); err != nil {
		if errors.Is(err, ErrProtocolMismatch) {
			log.Debug().Err(err).Str("relay", relayURL).Msg("discovery protocol mismatch; relay kept visible as incompatible")
			return nil
		}
		r.logDiscoveryFailure(state, err)
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

func (r *Refresher) logDiscoveryFailure(state relayState, err error) {
	if state.Bootstrap {
		return
	}
	relayURL := state.Descriptor.APIHTTPSAddr
	backedOff, backoffReason, failureCount := r.relaySet.RecordDiscoveryFailure(relayURL, defaultRecoveryFailures)
	if !backedOff {
		return
	}

	event := log.Debug().
		Err(err).
		Str("relay", relayURL).
		Bool("backed_off", true).
		Str("reason", backoffReason)
	if failureCount > 0 {
		event = event.Int("discovery_failures", failureCount)
	}
	if backoffReason == "unhealthy" {
		log.Warn().
			Err(err).
			Str("relay", relayURL).
			Bool("backed_off", true).
			Str("reason", backoffReason).
			Int("discovery_failures", failureCount).
			Msg("discovery source removed from relay pool")
		return
	}
	event.Msg("discovery source retry delayed")
}
