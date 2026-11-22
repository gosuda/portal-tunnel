package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
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
	serviceLookupLimit   = 8
	serviceCacheLimit    = 32
	serviceResultLimit   = 100
	serviceLeaseLimit    = 1000
	serviceResponseBytes = 1 << 20
	serviceLookupTimeout = 5 * time.Second
	serviceRelayTimeout  = 2 * time.Second
	serviceCacheTTL      = 30 * time.Second
	serviceNegativeTTL   = 10 * time.Second
)

var (
	errServiceLookupBusy                = errors.New("service directory is busy; try again shortly")
	errServiceDirectoryResponseRejected = errors.New("service directory response rejected")
	errServiceDirectoryResponseTooLarge = errors.New("service directory response too large")
)

type serviceObservation struct {
	leases     []types.Lease
	reputation map[string]*types.ObservedServiceReputation
	at         time.Time
	until      time.Time
	failed     bool
}

type serviceLookupCall struct {
	done        chan struct{}
	observation serviceObservation
}

// ServiceLookup owns bounded, request-driven public-directory observations.
// It neither discovers new relays nor changes their routing/health policy.
type ServiceLookup struct {
	relays         *RelaySet
	client         *http.Client
	slots          chan struct{}
	lookups        chan struct{}
	commentSlots   chan struct{}
	commentLookups chan struct{}
	mu             sync.Mutex
	cache          map[string]serviceObservation
	inflight       map[string]*serviceLookupCall
	nextTarget     int
}

func NewServiceLookup(relays *RelaySet) *ServiceLookup {
	return &ServiceLookup{
		relays:         relays,
		client:         newPublicRelayClient(),
		slots:          make(chan struct{}, serviceConcurrency),
		lookups:        make(chan struct{}, serviceLookupLimit),
		commentSlots:   make(chan struct{}, commentConcurrency),
		commentLookups: make(chan struct{}, commentLookupLimit),
		cache:          make(map[string]serviceObservation),
		inflight:       make(map[string]*serviceLookupCall),
	}
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
		unavailable := state.Banned || state.Dead || state.Trust != relayVerified
		missingDescriptor := !state.hasObservedDescriptor() || !state.Descriptor.ExpiresAt.After(now)
		if unavailable || missingDescriptor || state.suppressActiveUntil.After(now) {
			continue
		}
		if requirePublicRelayURL(state.Descriptor.APIHTTPSAddr) == nil {
			targets = append(targets, state.Descriptor.APIHTTPSAddr)
		}
	}
	slices.Sort(targets)
	return targets
}

// Lookup browses or filters the same relay observations. An empty address
// browses all observed identities; a nonempty address may narrow by name.
// Local entries are read directly and never depend on remote success.
func (s *ServiceLookup) Lookup(ctx context.Context, self string, local []types.Lease, address string, name *string) (types.ServiceDiscoveryResponse, error) {
	// Bound waiters as well as outbound requests. Admission never queues and
	// does not consume the registration/authentication pre-auth budget.
	select {
	case s.lookups <- struct{}{}:
		defer func() { <-s.lookups }()
	default:
		return types.ServiceDiscoveryResponse{}, errServiceLookupBusy
	}
	return s.lookup(ctx, self, local, address, name, s.slots, nil), nil
}

// slots is the outbound budget of the caller's admission class. Directory and
// comment reads share snapshots and in-flight work, but never each other's slots.
func (s *ServiceLookup) lookup(ctx context.Context, self string, local []types.Lease, address string, name *string, slots chan struct{}, commentSources map[string]commentSource) types.ServiceDiscoveryResponse {
	ctx, cancel := context.WithTimeout(ctx, serviceLookupTimeout)
	defer cancel()
	response := types.ServiceDiscoveryResponse{Services: []types.DiscoveredService{}, RelaysChecked: 1}
	now := time.Now().UTC()
	observations := map[string]serviceObservation{self: {leases: local, at: now, until: now.Add(serviceCacheTTL)}}
	targets := slices.DeleteFunc(s.relays.serviceTargets(now), func(target string) bool { return target == self })
	if len(targets) > 0 {
		s.mu.Lock()
		start := s.nextTarget % len(targets)
		count := min(len(targets), serviceRelayLimit)
		selected := make([]string, count)
		for i := range selected {
			selected[i] = targets[(start+i)%len(targets)]
		}
		s.nextTarget = (start + count) % len(targets)
		s.mu.Unlock()
		targets = selected
	}
	type result struct {
		relay       string
		observation serviceObservation
	}
	results := make(chan result, len(targets))
	var workers sync.WaitGroup
	for _, target := range targets {
		workers.Go(func() { results <- result{target, s.observe(ctx, target, slots)} })
	}
	workers.Wait()
	close(results)
	now = time.Now().UTC()
	eligible := slices.DeleteFunc(s.relays.serviceTargets(now), func(target string) bool { return target == self })
	// Keep valid cached locations outside this request's rotating refresh window.
	s.mu.Lock()
	for _, relay := range eligible {
		if cached, ok := s.cache[relay]; ok && !cached.failed && cached.until.After(now) {
			observations[relay] = cached
		}
	}
	s.mu.Unlock()
	for result := range results {
		if result.observation.failed || !result.observation.until.After(now) || !slices.Contains(eligible, result.relay) {
			continue
		}
		observations[result.relay] = result.observation
	}
	response.RelaysChecked = len(observations)
	response.RelaysSkipped = len(eligible) - (len(observations) - 1)
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
			invalidMetadata := lease.Metadata.Hide || lease.Metadata.Validate() != nil
			if invalidMetadata || !lease.ExpiresAt.After(now) {
				continue
			}
			id, err := identity.NormalizeIdentity(types.Identity{Name: lease.Name, Address: lease.Address})
			if err != nil || (address != "" && !strings.EqualFold(id.Address, address)) {
				continue
			}
			if name != nil && id.Name != *name {
				continue
			}
			location, valid := serviceLocation(relay, lease, id, observation.at, observation.until)
			if !valid {
				continue
			}
			location.CurrentRelay = relay == self
			if len(observation.reputation) != 0 {
				if tally := observedServiceReputation(relay, lease, id, observation.reputation); tally != nil {
					snapshot := *tally
					location.Reputation = &snapshot
				}
			}
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
			relayIndex := slices.IndexFunc(locations, func(existing types.ServiceLocation) bool { return existing.RelayURL == relay })
			if relayIndex < 0 {
				response.Services[index].Locations = append(locations, location)
				if commentSources != nil && !location.CurrentRelay {
					commentSources[relay] = commentSource{hostname: publicServiceCanonicalHostname(relay, lease, id), expiresAt: location.ExpiresAt}
				}
			} else if locations[relayIndex].URL == "" && location.URL != "" {
				locations[relayIndex] = location
				if commentSources != nil && !location.CurrentRelay {
					commentSources[relay] = commentSource{hostname: publicServiceCanonicalHostname(relay, lease, id), expiresAt: location.ExpiresAt}
				}
			} else {
				if locations[relayIndex].TCPAddr == "" && location.TCPAddr != "" {
					locations[relayIndex].TCPAddr = location.TCPAddr
				}
				if locations[relayIndex].UDPAddr == "" && location.UDPAddr != "" {
					locations[relayIndex].UDPAddr = location.UDPAddr
				}
			}
		}
	}
	slices.SortFunc(response.Services, func(a, b types.DiscoveredService) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return strings.Compare(a.Address, b.Address)
	})
	response.Partial = response.Partial || response.RelaysSkipped > 0
	return response
}

func (s *ServiceLookup) observe(ctx context.Context, relay string, slots chan struct{}) serviceObservation {
	var call *serviceLookupCall
	for {
		if ctx.Err() != nil {
			return serviceObservation{failed: true}
		}
		s.mu.Lock()
		if cached, ok := s.cache[relay]; ok && cached.until.After(time.Now()) {
			s.mu.Unlock()
			return cached
		}
		pendingCall, pending := s.inflight[relay]
		if !pending {
			call = &serviceLookupCall{done: make(chan struct{})}
			s.inflight[relay] = call
			s.mu.Unlock()
			break
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return serviceObservation{failed: true}
		case <-pendingCall.done:
			if !pendingCall.observation.at.IsZero() {
				return pendingCall.observation
			}
		}
	}

	observation := serviceObservation{failed: true}
	// Queue outside the cache lock. The remote timeout starts after slot
	// acquisition; waiting consumes only the caller's lookup deadline.
	select {
	case <-ctx.Done():
	case slots <- struct{}{}:
		fetchCtx, cancel := context.WithTimeout(ctx, serviceRelayTimeout)
		fetched, err := s.fetch(fetchCtx, relay)
		cancel()
		<-slots
		if ctx.Err() == nil {
			observed := time.Now().UTC()
			observation = serviceObservation{at: observed, until: observed.Add(serviceNegativeTTL), failed: true}
			if err == nil {
				observation = fetched
				observation.at = observed
				observation.until = observed.Add(serviceCacheTTL)
			}
		}
	}

	s.mu.Lock()
	// A canceled caller or queue wait is not a remote failure. Waiters can
	// retry a canceled leader's work within their own remaining deadline.
	cacheable := !observation.at.IsZero()
	_, exists := s.cache[relay]
	if cacheable && !exists && len(s.cache) >= serviceCacheLimit {
		var oldest string
		for key, entry := range s.cache {
			if oldest == "" || entry.until.Before(s.cache[oldest].until) {
				oldest = key
			}
		}
		delete(s.cache, oldest)
	}
	if cacheable {
		s.cache[relay] = observation
	}
	delete(s.inflight, relay)
	call.observation = observation
	close(call.done)
	s.mu.Unlock()
	return observation
}

func (s *ServiceLookup) fetch(ctx context.Context, relay string) (serviceObservation, error) {
	if err := requirePublicRelayURL(relay); err != nil {
		return serviceObservation{}, err
	}
	base, err := url.Parse(relay)
	if err != nil {
		return serviceObservation{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, utils.ResolveAPIURL(base, types.PathState).String(), nil)
	if err != nil {
		return serviceObservation{}, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return serviceObservation{}, err
	}
	defer resp.Body.Close()
	body, err := readServiceResponse(resp, serviceResponseBytes)
	if err != nil {
		return serviceObservation{}, err
	}
	var envelope types.APIEnvelope[struct {
		types.PublicStateResponse
		Reputation json.RawMessage `json:"reputation"`
	}]
	if err := json.Unmarshal(body, &envelope); err != nil {
		return serviceObservation{}, err
	}
	if !envelope.OK || len(envelope.Data.Leases) > serviceLeaseLimit {
		return serviceObservation{}, errServiceDirectoryResponseRejected
	}
	return serviceObservation{
		leases:     slices.DeleteFunc(envelope.Data.Leases, func(lease types.Lease) bool { return lease.Metadata.Hide }),
		reputation: parseObservedReputation(envelope.Data.Reputation),
	}, nil
}

// Parse reputation separately so broken or absent optional community data
// cannot make public services disappear from an otherwise usable snapshot.
func parseObservedReputation(raw json.RawMessage) map[string]*types.ObservedServiceReputation {
	var rows []json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil || len(rows) > serviceLeaseLimit {
		return nil
	}
	tallies := make(map[string]*types.ObservedServiceReputation, len(rows))
	for _, row := range rows {
		var report struct {
			Hostname string  `json:"hostname"`
			Up       *uint32 `json:"up"`
			Down     *uint32 `json:"down"`
			Total    *uint32 `json:"total"`
		}
		if err := json.Unmarshal(row, &report); err != nil || report.Up == nil || report.Down == nil || report.Total == nil ||
			uint64(*report.Up)+uint64(*report.Down) != uint64(*report.Total) {
			continue
		}
		hostname := utils.NormalizeHostname(report.Hostname)
		if hostname == "" {
			continue
		}
		if _, duplicate := tallies[hostname]; duplicate {
			tallies[hostname] = nil
			continue
		}
		tallies[hostname] = &types.ObservedServiceReputation{Up: *report.Up, Down: *report.Down}
	}
	return tallies
}

// A tally must match this relay's host for the advertised service identity.
func observedServiceReputation(relay string, lease types.Lease, id types.Identity, tallies map[string]*types.ObservedServiceReputation) *types.ObservedServiceReputation {
	if lease.CanonicalHostname == "" {
		return tallies[lease.Hostname]
	}
	return tallies[publicServiceCanonicalHostname(relay, lease, id)]
}

// Called only after serviceLocation validated the lease and source. Returns the
// verified canonical hostname if present, or the verified alias hostname for
// alias-only services, ensuring federated comments can be discovered.
func publicServiceCanonicalHostname(relay string, lease types.Lease, id types.Identity) string {
	if lease.Namespace == types.LocalTLSNamespaceV1 {
		return lease.CanonicalHostname
	}
	base, err := url.Parse(relay)
	if err != nil {
		return ""
	}
	if lease.CanonicalHostname != "" {
		expected, err := namespace.LocalTLSHostname(id.Name, id.Address, base.Hostname())
		if err == nil && expected == lease.CanonicalHostname {
			return expected
		}
	}
	if lease.Hostname != "" {
		expected, err := namespace.ServiceAliasHostname(id.Name, id.Address, base.Hostname())
		if err == nil && expected == lease.Hostname {
			return expected
		}
	}
	return ""
}

// relayTransportAddr keeps a reported transport address only when it names
// the reporting relay host and a valid port. A relay must not point visitors
// at another host.
func relayTransportAddr(addr, relayHost string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || !strings.EqualFold(host, relayHost) {
		return ""
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return ""
	}
	return addr
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
	location.TCPAddr = relayTransportAddr(lease.TCPAddr, base.Hostname())
	location.UDPAddr = relayTransportAddr(lease.UDPAddr, base.Hostname())
	endpoint := func(host string) string {
		authority := host
		if base.Port() != "" {
			authority += ":" + base.Port()
		}
		return (&url.URL{Scheme: "https", Host: authority, Path: "/"}).String()
	}
	if lease.Hostname != "" {
		expected, err := namespace.ServiceAliasHostname(id.Name, id.Address, base.Hostname())
		if err != nil || expected != lease.Hostname {
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
	// A public lease still identifies a service when an older relay reports
	// only a retired canonical hostname or no hostname at all.
	location.URL = location.CanonicalURL
	if location.URL == "" {
		location.URL = location.AliasURL
	}
	return location, true
}

// readServiceResponse applies the same bound to fixed-length and streamed bodies.
func readServiceResponse(resp *http.Response, limit int) ([]byte, error) {
	if resp.StatusCode != http.StatusOK || resp.ContentLength > int64(limit) {
		return nil, errServiceDirectoryResponseRejected
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, errServiceDirectoryResponseTooLarge
	}
	return body, nil
}
