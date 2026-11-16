package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/namespace"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	serviceRelayLimit    = 8
	serviceConcurrency   = 4
	serviceCacheLimit    = 32
	serviceResultLimit   = 100
	serviceLeaseLimit    = 1000
	serviceResponseBytes = 1 << 20
	serviceLookupTimeout = 5 * time.Second
	serviceRelayTimeout  = 2 * time.Second
	serviceCacheTTL      = 30 * time.Second
	serviceNegativeTTL   = 10 * time.Second
)

type serviceObservation struct {
	leases []types.Lease
	at     time.Time
	until  time.Time
	failed bool
}

// ServiceLookup owns bounded, request-driven public-directory observations.
// It neither discovers new relays nor changes their routing/health policy.
type ServiceLookup struct {
	relays *RelaySet
	client *http.Client
	slots  chan struct{}
	mu     sync.Mutex
	cache  map[string]serviceObservation
}

func NewServiceLookup(relays *RelaySet) *ServiceLookup {
	return &ServiceLookup{relays: relays, client: newPublicRelayClient(), slots: make(chan struct{}, serviceConcurrency), cache: make(map[string]serviceObservation)}
}

// serviceTargets keeps eligibility in Discovery rather than duplicating it at
// the HTTP/UI boundary. Suppression also applies to cached observations.
func (s *RelaySet) serviceTargets(now time.Time) []string {
	if s == nil {
		return nil
	}
	states := s.currentRelayStates(now)
	var targets []string
	for _, state := range states {
		if state.Banned || state.Dead || state.Trust != relayVerified || !state.hasObservedDescriptor() || !state.Descriptor.ExpiresAt.After(now) || state.suppressActiveUntil.After(now) {
			continue
		}
		if requirePublicRelayURL(state.Descriptor.APIHTTPSAddr) == nil {
			targets = append(targets, state.Descriptor.APIHTTPSAddr)
		}
	}
	slices.Sort(targets)
	return targets
}

// Lookup filters the same relay observations by address and optional service
// name. Local entries are read directly and never depend on remote success.
func (s *ServiceLookup) Lookup(ctx context.Context, self string, local []types.Lease, address string, name *string) types.ServiceDiscoveryResponse {
	ctx, cancel := context.WithTimeout(ctx, serviceLookupTimeout)
	defer cancel()
	response := types.ServiceDiscoveryResponse{Services: []types.DiscoveredService{}, RelaysChecked: 1}
	now := time.Now().UTC()
	observations := map[string]serviceObservation{self: {leases: local, at: now, until: now.Add(serviceCacheTTL)}}
	targets := slices.DeleteFunc(s.relays.serviceTargets(now), func(target string) bool { return target == self })
	if len(targets) > serviceRelayLimit {
		response.RelaysSkipped = len(targets) - serviceRelayLimit
		targets = targets[:serviceRelayLimit]
	}
	type result struct {
		relay       string
		observation serviceObservation
	}
	results := make(chan result, len(targets))
	var workers sync.WaitGroup
	for _, target := range targets {
		workers.Go(func() { results <- result{target, s.observe(ctx, target)} })
	}
	workers.Wait()
	close(results)
	now = time.Now().UTC()
	eligible := s.relays.serviceTargets(now)
	for result := range results {
		if result.observation.failed || !result.observation.until.After(now) || !slices.Contains(eligible, result.relay) {
			response.RelaysSkipped++
			continue
		}
		response.RelaysChecked++
		observations[result.relay] = result.observation
	}
	indices := make(map[types.ServiceIdentityKey]int)
	relayURLs := make([]string, 0, len(observations))
	for relay := range observations {
		relayURLs = append(relayURLs, relay)
	}
	slices.Sort(relayURLs)
	// Prefer this relay's metadata when the same identity has remote locations.
	if index := slices.Index(relayURLs, self); index >= 0 {
		relayURLs = append([]string{self}, slices.Delete(relayURLs, index, index+1)...)
	}
	for _, relay := range relayURLs {
		observation := observations[relay]
		for _, lease := range observation.leases {
			if lease.Metadata.Hide || lease.Metadata.Validate() != nil || !lease.ExpiresAt.After(now) {
				continue
			}
			id, err := identity.NormalizeIdentity(types.Identity{Name: lease.Name, Address: lease.Address})
			if err != nil || !strings.EqualFold(id.Address, address) || (name != nil && id.Name != *name) {
				continue
			}
			location, valid := serviceLocation(relay, lease, id, observation.at, observation.until)
			if !valid {
				continue
			}
			location.CurrentRelay = relay == self
			key := id.ServiceKey()
			index, exists := indices[key]
			if !exists {
				if len(response.Services) == serviceResultLimit {
					response.Partial = true
					continue
				}
				index = len(response.Services)
				indices[key] = index
				metadata := lease.Metadata.Copy()
				metadata.Thumbnail = "" // Remote observations must not trigger browser image requests.
				response.Services = append(response.Services, types.DiscoveredService{Name: id.Name, Address: id.Address, Metadata: metadata, Locations: []types.ServiceLocation{}})
			}
			locations := response.Services[index].Locations
			if !slices.ContainsFunc(locations, func(existing types.ServiceLocation) bool { return existing.RelayURL == relay }) {
				response.Services[index].Locations = append(locations, location)
			}
		}
	}
	slices.SortFunc(response.Services, func(a, b types.DiscoveredService) int { return strings.Compare(a.Name, b.Name) })
	response.Partial = response.Partial || response.RelaysSkipped > 0
	return response
}

func (s *ServiceLookup) observe(ctx context.Context, relay string) serviceObservation {
	now := time.Now().UTC()
	s.mu.Lock()
	if cached, ok := s.cache[relay]; ok && cached.until.After(now) {
		s.mu.Unlock()
		return cached
	}
	select {
	case s.slots <- struct{}{}:
	default:
		s.mu.Unlock()
		return serviceObservation{failed: true}
	}
	// A short negative entry coalesces concurrent misses without waiting on an
	// unrelated visitor's request or adding another background lifecycle.
	if len(s.cache) >= serviceCacheLimit {
		var oldest string
		for key, entry := range s.cache {
			if oldest == "" || entry.until.Before(s.cache[oldest].until) {
				oldest = key
			}
		}
		delete(s.cache, oldest)
	}
	s.cache[relay] = serviceObservation{at: now, until: now.Add(serviceNegativeTTL), failed: true}
	s.mu.Unlock()
	defer func() { <-s.slots }()
	ctx, cancel := context.WithTimeout(ctx, serviceRelayTimeout)
	defer cancel()
	leases, err := s.fetch(ctx, relay)
	observed := time.Now().UTC()
	observation := serviceObservation{at: observed, until: observed.Add(serviceNegativeTTL), failed: true}
	if err == nil {
		observation = serviceObservation{leases: leases, at: observed, until: observed.Add(serviceCacheTTL)}
	}
	s.mu.Lock()
	if _, retained := s.cache[relay]; retained {
		s.cache[relay] = observation
	}
	s.mu.Unlock()
	return observation
}

func (s *ServiceLookup) fetch(ctx context.Context, relay string) ([]types.Lease, error) {
	if err := requirePublicRelayURL(relay); err != nil {
		return nil, err
	}
	base, err := url.Parse(relay)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, utils.ResolveAPIURL(base, types.PathState).String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > serviceResponseBytes {
		return nil, errors.New("service directory response rejected")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, serviceResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > serviceResponseBytes {
		return nil, errors.New("service directory response too large")
	}
	var envelope types.APIEnvelope[types.PublicStateResponse]
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	if !envelope.OK || len(envelope.Data.Leases) > serviceLeaseLimit {
		return nil, errors.New("service directory response rejected")
	}
	return slices.DeleteFunc(envelope.Data.Leases, func(lease types.Lease) bool { return lease.Metadata.Hide }), nil
}

func serviceLocation(relay string, lease types.Lease, id types.Identity, observed, until time.Time) (types.ServiceLocation, bool) {
	base, err := url.Parse(relay)
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil {
		return types.ServiceLocation{}, false
	}
	if lease.ExpiresAt.Before(until) {
		until = lease.ExpiresAt
	}
	location := types.ServiceLocation{RelayURL: relay, ObservedAt: observed, ExpiresAt: until, ReportedReady: lease.Ready > 0, Verification: "relay-reported"}
	endpoint := func(host string) string {
		authority := host
		if base.Port() != "" {
			authority += ":" + base.Port()
		}
		return (&url.URL{Scheme: "https", Host: authority, Path: "/"}).String()
	}
	if lease.Hostname != "" {
		expected, err := namespace.AliasHostname(id.Name, base.Hostname())
		if id.Name == "" || err != nil || expected != lease.Hostname {
			return types.ServiceLocation{}, false
		}
		location.AliasURL = endpoint(expected)
	}
	if lease.Namespace == types.LocalTLSNamespaceV1 {
		expected, err := namespace.LocalTLSHostname(id.Name, id.Address, base.Hostname())
		if err != nil || expected != lease.CanonicalHostname {
			return types.ServiceLocation{}, false
		}
		if lease.CanonicalReady {
			location.CanonicalURL = endpoint(expected)
		}
	} else if lease.Namespace != "" {
		return types.ServiceLocation{}, false
	}
	// Older one-label canonicals are intentionally not promoted to links.
	location.URL = location.CanonicalURL
	if location.URL == "" {
		location.URL = location.AliasURL
	}
	return location, location.AliasURL != "" || lease.Namespace == types.LocalTLSNamespaceV1 || lease.TCPEnabled || lease.UDPEnabled
}
