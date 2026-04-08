package discovery

import (
	"context"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// ManagerConfig controls discovery manager behavior.
type ManagerConfig struct {
	Identity   types.Identity
	PortalURL  string
	Bootstraps []string
	RootCAPEM  []byte
	MaxRouting int
}

// Manager centralizes bootstrap relay discovery and direct confirmation polling.
// It owns the RelaySet and keeps the
// ordering logic (OLS-based permutation) out of server.go to preserve
// separation of concerns.
type Manager struct {
	relaySet   *RelaySet
	rootCAPEM  []byte
	maxRouting int
}

// NewManager constructs a discovery manager that owns its RelaySet.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	set := NewRelaySet()
	if strings.TrimSpace(cfg.PortalURL) != "" ||
		strings.TrimSpace(cfg.Identity.Name) != "" ||
		strings.TrimSpace(cfg.Identity.Address) != "" {
		if err := set.SetSelfRelay(cfg.Identity, cfg.PortalURL); err != nil {
			return nil, err
		}
	}
	set.SetBootstrapRelayURLs(cfg.Bootstraps)
	if err := utils.ValidateMaxRouting(cfg.MaxRouting); err != nil {
		return nil, err
	}

	mgr := &Manager{
		relaySet:   set,
		rootCAPEM:  cfg.RootCAPEM,
		maxRouting: cfg.MaxRouting,
	}
	return mgr, nil
}

// Run starts the discovery poll loop until ctx is canceled. onSnapshot receives
// the latest RelaySet snapshot after each refresh so callers can synchronize
// additional runtimes (e.g., OLS routing engines).
func (m *Manager) Run(ctx context.Context, onSnapshot func(map[string]types.RelayState)) error {
	if m == nil || m.relaySet == nil {
		<-ctx.Done()
		return nil
	}

	ticker := time.NewTicker(types.DiscoveryPollInterval)
	defer ticker.Stop()

	var round uint64
	for {
		m.refresh(ctx, round)
		if ctx.Err() != nil {
			return nil
		}
		if onSnapshot != nil {
			onSnapshot(m.relaySet.Snapshot())
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			round++
		}
	}
}

func (m *Manager) refresh(ctx context.Context, round uint64) {
	if m == nil || m.relaySet == nil {
		return
	}

	m.runBootstrapPass(ctx, round)
	if ctx.Err() != nil {
		return
	}

	for _, relay := range m.relaySet.confirmableDescriptors() {
		resp, err := DiscoverRelayDiscovery(ctx, relay.APIHTTPSAddr, m.rootCAPEM, nil)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			expired, expireReason, consecutiveFailures := m.relaySet.RecordDiscoveryFailure(relay.Identity, relay.APIHTTPSAddr, err)
			logDirectDiscoveryFailure(relay.APIHTTPSAddr, err, expired, expireReason, consecutiveFailures)
			continue
		}
		if err := m.relaySet.ApplyRelayDiscoveryResponse(relay.Identity, relay.APIHTTPSAddr, resp, time.Now().UTC()); err != nil {
			expired, expireReason, consecutiveFailures := m.relaySet.RecordDiscoveryFailure(relay.Identity, relay.APIHTTPSAddr, err)
			logDirectDiscoveryFailure(relay.APIHTTPSAddr, err, expired, expireReason, consecutiveFailures)
		}
	}
}

func (m *Manager) runBootstrapPass(ctx context.Context, round uint64) {
	bootstraps := m.relaySet.BootstrapDescriptors()
	if len(bootstraps) == 0 {
		return
	}
	if len(bootstraps) > 1 {
		bootstraps = orderDescriptors(bootstraps, nil, round)
	}

	visited := make(map[string]struct{}, len(bootstraps))
	processed := 0
	for _, desc := range bootstraps {
		if processed >= m.maxRouting {
			break
		}
		relayURL := strings.TrimSpace(desc.APIHTTPSAddr)
		if relayURL == "" {
			continue
		}
		if _, ok := visited[relayURL]; ok {
			continue
		}
		visited[relayURL] = struct{}{}
		processed++

		resp, err := DiscoverRelayDiscovery(ctx, relayURL, m.rootCAPEM, nil)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logBootstrapDiscoveryFailure(relayURL, err)
			continue
		}
		if err := m.relaySet.ApplyRelayDiscoveryResponse(desc.Identity, relayURL, resp, time.Now().UTC()); err != nil {
			log.Warn().
				Err(err).
				Str("relay", relayURL).
				Msg("bootstrap relay discovery failed")
		}
	}
}

// ActiveRelayDescriptors returns currently advertised relay descriptors.
func (m *Manager) ActiveRelayDescriptors() []types.RelayDescriptor {
	if m == nil || m.relaySet == nil {
		return nil
	}
	return m.relaySet.ActiveRelayDescriptors()
}

// ActiveRelayURLs returns the URLs of currently advertised relays.
func (m *Manager) ActiveRelayURLs() []string {
	if m == nil || m.relaySet == nil {
		return nil
	}
	return m.relaySet.ActiveRelayURLs()
}

// Snapshot exposes the RelaySet snapshot (identity key -> state).
func (m *Manager) Snapshot() map[string]types.RelayState {
	if m == nil || m.relaySet == nil {
		return nil
	}
	return m.relaySet.Snapshot()
}

// SetBootstrapRelayURLs replaces the bootstrap relay URLs.
func (m *Manager) SetBootstrapRelayURLs(urls []string) {
	if m == nil || m.relaySet == nil {
		return
	}
	m.relaySet.SetBootstrapRelayURLs(urls)
}

// ApplyRelayDiscoveryResponse injects a discovery response into the RelaySet.
func (m *Manager) ApplyRelayDiscoveryResponse(identity types.Identity, relayURL string, resp types.DiscoveryResponse, now time.Time) error {
	if m == nil || m.relaySet == nil {
		return nil
	}
	return m.relaySet.ApplyRelayDiscoveryResponse(identity, relayURL, resp, now)
}

// RecordDiscoveryFailure mirrors RelaySet.RecordDiscoveryFailure.
func (m *Manager) RecordDiscoveryFailure(identity types.Identity, relayURL string, err error) (bool, string, int) {
	if m == nil || m.relaySet == nil {
		return false, "", 0
	}
	return m.relaySet.RecordDiscoveryFailure(identity, relayURL, err)
}

// RelaySet exposes the underlying relay set for caller coordination.
func (m *Manager) RelaySet() *RelaySet {
	if m == nil {
		return nil
	}
	return m.relaySet
}

// orderDescriptors applies the OLS-style permutation that previously lived in
// the standalone OLSManager. Keeping the logic here avoids an extra struct
// whose only job was to shuffle descriptors for each round.
func orderDescriptors(relays []types.RelayDescriptor, loadByURL map[string]float64, round uint64) []types.RelayDescriptor {
	if len(relays) <= 1 {
		return relays
	}

	ordered := make([]types.RelayDescriptor, len(relays))
	copy(ordered, relays)
	slices.SortStableFunc(ordered, func(a, b types.RelayDescriptor) int {
		switch {
		case a.APIHTTPSAddr < b.APIHTTPSAddr:
			return -1
		case a.APIHTTPSAddr > b.APIHTTPSAddr:
			return 1
		default:
			return 0
		}
	})

	type weighted struct {
		desc        types.RelayDescriptor
		compensated float64
	}
	weights := make([]weighted, 0, len(ordered))
	for _, relay := range ordered {
		load := clampNonNegative(loadByURL[relay.APIHTTPSAddr])
		distorted := load * load
		compensated := math.Sqrt(distorted + 1.0)
		weights = append(weights, weighted{
			desc:        relay,
			compensated: compensated,
		})
	}
	slices.SortStableFunc(weights, func(a, b weighted) int {
		switch {
		case a.compensated < b.compensated:
			return -1
		case a.compensated > b.compensated:
			return 1
		case a.desc.APIHTTPSAddr < b.desc.APIHTTPSAddr:
			return -1
		case a.desc.APIHTTPSAddr > b.desc.APIHTTPSAddr:
			return 1
		default:
			return 0
		}
	})

	n := len(weights)
	a := pickCoprimeStep(n, int(round))
	b := int(round % uint64(n))
	out := make([]types.RelayDescriptor, 0, n)
	for i := 0; i < n; i++ {
		slot := (a*i + b) % n
		out = append(out, weights[slot].desc)
	}
	return out
}

func clampNonNegative(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0
	}
	return v
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	if a < 0 {
		return -a
	}
	return a
}

func pickCoprimeStep(n int, round int) int {
	if n <= 1 {
		return 1
	}
	candidate := (round % (n - 1)) + 1
	for candidate < n {
		if gcd(candidate, n) == 1 {
			return candidate
		}
		candidate++
	}
	return 1
}
