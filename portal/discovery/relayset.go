package discovery

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// RelaySet owns the shared relay discovery view: configured bootstrap relay URLs,
// the latest validated descriptor seen for each relay, and local runtime state
// such as ban/failure tracking and observed discovery RTT.
//
// The relays map is keyed by APIHTTPSAddr (URL). The keyIndex map provides a
// reverse lookup from signing identity (the EVM address derived from the
// signing public key, lower-cased) to the most recent IssuedAt we have ever
// accepted for that identity, along with a tombstone TombstoneUntil that
// records how long the rollback anchor must be remembered. The keyIndex is
// the rollback-defense gate: any descriptor whose IssuedAt is strictly older
// than the recorded latest is rejected before reaching s.relays. Tracking by
// signing key (rather than URL) means a single relay rotating its
// APIHTTPSAddr cannot be tricked into accepting a stale rollback simply by
// submitting it under a new URL.
//
// The keyIndex lifetime is deliberately decoupled from s.relays: evicting the
// last URL slot for an identity (via LRU or explicit removal) MUST NOT forget
// the rollback anchor, otherwise a captured older-but-unexpired descriptor
// could be replayed after eviction. Tombstones expire once the replay window
// closes, i.e. once now > IssuedAt + AnnounceMaxValidity. By that time any
// descriptor whose IssuedAt is at or before the tombstoned value is expired and
// cannot pass the announce validity check regardless.
//
// Both maps must always be read and written under s.mu. Mutators come in two
// flavors: public methods that own the lock end-to-end, and *Locked methods
// that assume the caller already holds s.mu as a write lock and never re-
// acquire it themselves. This convention prevents nested-locking deadlocks
// (notably from ApplyRelayDiscoveryResponse, which holds the write lock for
// the entire batch).
type RelaySet struct {
	mu       sync.RWMutex
	relays   map[string]RelayState
	keyIndex map[string]keyIndexEntry

	// generation is incremented on every material change to the relay set or
	// its telemetry (descriptors, bans, RTT, load, confirmations). It lets
	// PlanRoutes skip redundant recomputation when the route state and the
	// set have not changed since the last plan.
	generation uint64
	lastPlan   *cachedPlan

	// activeRoutes holds the current route slice consumed by the runtime loop.
	// It is computed by PlanRoutes and atomically swapped by OptimizeRoutes.
	activeRoutes atomic.Pointer[[]Route]
}

// cachedPlan stores the last route plan together with the generation and
// route state that produced it. Only one entry is kept because RouteState is
// stable in normal operation.
type cachedPlan struct {
	routeState RouteState
	generation uint64
	routes     []Route
}

// keyIndexEntry records the rollback anchor for a signing identity.
// IssuedAt is the newest descriptor IssuedAt the set has ever accepted
// for this identity. TombstoneUntil is the wall-clock time at which the
// rollback anchor may safely be forgotten. After that point, any
// replayable descriptor with an older IssuedAt is itself expired.
type keyIndexEntry struct {
	IssuedAt       time.Time
	TombstoneUntil time.Time
}

type upsertResult int

const (
	upsertRejected upsertResult = iota
	upsertAccepted
	upsertIgnored
)

func NewRelaySet(bootstrapRelayURLs []string) *RelaySet {
	set := &RelaySet{
		relays:   make(map[string]RelayState),
		keyIndex: make(map[string]keyIndexEntry),
	}
	set.SetBootstrapRelayURLs(bootstrapRelayURLs)
	return set
}

// bumpGenerationLocked increments the relay-set generation. The caller must
// already hold s.mu as a write lock.
func (s *RelaySet) bumpGenerationLocked() {
	s.generation++
}

// matchCachedPlanLocked returns a copy of the cached route plan if the route
// state and generation match the current set. The caller must already hold
// s.mu as a read or write lock.
func (s *RelaySet) matchCachedPlanLocked(routeState RouteState) ([]Route, bool) {
	if s.lastPlan == nil || s.lastPlan.generation != s.generation {
		return nil, false
	}
	if !s.lastPlan.routeState.Equal(routeState) {
		return nil, false
	}
	routes := make([]Route, len(s.lastPlan.routes))
	copy(routes, s.lastPlan.routes)
	return routes, true
}

// storeCachedPlanLocked stores a route plan for the current generation. The
// caller must already hold s.mu as a write lock.
func (s *RelaySet) storeCachedPlanLocked(routeState RouteState, routes []Route) {
	s.lastPlan = &cachedPlan{
		routeState: routeState,
		generation: s.generation,
		routes:     routes,
	}
}

// currentRelayStates returns a copy of the set after expiring temporary pool bans.
func (s *RelaySet) currentRelayStates(now time.Time) []RelayState {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.clearExpiredPoolBansLocked(now)
	states := make([]RelayState, 0, len(s.relays))
	for _, state := range s.relays {
		states = append(states, state)
	}
	return states
}

// refreshCandidates returns relays worth directly polling after applying local
// pool-ban expiry. The refresher owns HTTP; RelaySet owns pool eligibility.
func (s *RelaySet) refreshCandidates(now time.Time) []RelayState {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	states := s.currentRelayStates(now)
	out := make([]RelayState, 0, len(states))
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
		if state.Descriptor.APIHTTPSAddr == "" {
			continue
		}
		out = append(out, state)
	}
	return out
}

func (s *RelaySet) clearExpiredPoolBansLocked(now time.Time) {
	changed := false
	for relayURL, state := range s.relays {
		if !state.Banned || state.suppressActiveUntil.IsZero() || state.suppressActiveUntil.After(now) {
			continue
		}
		if !state.Bootstrap {
			delete(s.relays, relayURL)
			changed = true
			continue
		}
		state.Banned = false
		state.suppressActiveUntil = time.Time{}
		state.unhealthySince = time.Time{}
		s.relays[relayURL] = state
		changed = true
	}
	if changed {
		s.bumpGenerationLocked()
	}
}

func (s *RelaySet) banFromPoolLocked(relayURL string, now time.Time) {
	if relayURL == "" {
		return
	}
	bootstrap := false
	state, ok := s.relays[relayURL]
	if ok {
		bootstrap = state.Bootstrap
	}
	state = newRelayState(relayURL)
	state.Bootstrap = bootstrap
	state.Banned = true
	state.suppressActiveUntil = now.Add(relayPoolBanTTL)
	s.relays[relayURL] = state
	s.bumpGenerationLocked()
}

func mergeLocalRelayState(record, existing RelayState) RelayState {
	record.Bootstrap = record.Bootstrap || existing.Bootstrap
	record.Confirmed = record.Confirmed || existing.Confirmed
	record.Banned = record.Banned || existing.Banned
	if record.discoveryFailures < existing.discoveryFailures {
		record.discoveryFailures = existing.discoveryFailures
	}
	if record.activeFailures < existing.activeFailures {
		record.activeFailures = existing.activeFailures
	}
	record.unhealthySince = existing.unhealthySince
	record.nextDiscoveryRefreshAt = existing.nextDiscoveryRefreshAt
	record.suppressActiveUntil = existing.suppressActiveUntil
	if record.DiscoveryRTTAt.IsZero() || (!existing.DiscoveryRTTAt.IsZero() && existing.DiscoveryRTTAt.After(record.DiscoveryRTTAt)) {
		record.DiscoveryRTT = existing.DiscoveryRTT
		record.DiscoveryRTTAt = existing.DiscoveryRTTAt
	}
	record.inheritAdaptiveTelemetry(existing)
	return record
}

func markDiscoveryConfirmed(state RelayState) RelayState {
	state.discoveryFailures = 0
	state.nextDiscoveryRefreshAt = time.Time{}
	state.unhealthySince = time.Time{}
	return state
}

// upsertDescriptorLocked applies a fully-merged RelayState to s.relays and
// updates the keyIndex. The caller MUST already hold s.mu as a write lock.
//
// The returned status indicates whether the descriptor was accepted, ignored
// as an already-superseded same-URL/same-identity announce, or rejected. The
// upsert is rejected when:
//
//  1. The signing identity has previously published a strictly newer
//     IssuedAt (rollback defense).
//  2. The URL slot is already held by a DIFFERENT signing identity whose
//     descriptor has not yet expired, and `allowCrossIdentityTakeover` is
//     false. This blocks third-party gossip/announce from hijacking a URL
//     binding established by direct authoritative contact.
//
// `allowCrossIdentityTakeover` MUST be true only when the caller has
// directly contacted the URL and verified the response is signed by the
// announced identity (i.e. authoritative refresh). Gossip propagation and
// the announce endpoint MUST pass false.
//
// Equal IssuedAt values (idempotent re-broadcast) are accepted because the
// only mutation is the merged local telemetry on the existing URL slot,
// which never contradicts the cryptographic identity of the descriptor.
func (s *RelaySet) upsertDescriptorLocked(record RelayState, now time.Time, allowCrossIdentityTakeover bool) upsertResult {
	relayURL := record.Descriptor.APIHTTPSAddr
	if relayURL == "" {
		return upsertRejected
	}
	if existing, ok := s.relays[relayURL]; ok && existing.Banned {
		return upsertRejected
	}
	address := strings.ToLower(strings.TrimSpace(record.Descriptor.Address))
	if address != "" {
		if prev, ok := s.keyIndex[address]; ok {
			// Stale tombstone: no replayable descriptor could still be
			// within its validity window, so drop the anchor and accept
			// the fresh descriptor as if first-seen.
			if !prev.TombstoneUntil.IsZero() && now.After(prev.TombstoneUntil) {
				delete(s.keyIndex, address)
			} else if record.Descriptor.IssuedAt.Before(prev.IssuedAt) {
				if existing, ok := s.relays[relayURL]; ok {
					existingAddress := strings.ToLower(strings.TrimSpace(existing.Descriptor.Address))
					if existingAddress == address && existing.Descriptor.ExpiresAt.After(now) &&
						!existing.Descriptor.IssuedAt.Before(record.Descriptor.IssuedAt) {
						return upsertIgnored
					}
				}
				return upsertRejected
			}
		}
	}
	if !allowCrossIdentityTakeover {
		if existing, ok := s.relays[relayURL]; ok {
			existingAddress := strings.ToLower(strings.TrimSpace(existing.Descriptor.Address))
			if existingAddress != "" && address != "" && existingAddress != address {
				if !existing.Descriptor.ExpiresAt.IsZero() && existing.Descriptor.ExpiresAt.After(now) {
					return upsertRejected
				}
			}
		}
	}
	s.relays[relayURL] = record
	s.bumpGenerationLocked()
	if address != "" {
		issuedAt := record.Descriptor.IssuedAt
		tombstoneUntil := issuedAt.Add(AnnounceMaxValidity)
		if prev, ok := s.keyIndex[address]; ok {
			if prev.IssuedAt.After(issuedAt) {
				issuedAt = prev.IssuedAt
			}
			if prev.TombstoneUntil.After(tombstoneUntil) {
				tombstoneUntil = prev.TombstoneUntil
			}
		}
		s.keyIndex[address] = keyIndexEntry{
			IssuedAt:       issuedAt,
			TombstoneUntil: tombstoneUntil,
		}
	}
	return upsertAccepted
}

func (s *RelaySet) SetBootstrapRelayURLs(inputs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	s.clearExpiredPoolBansLocked(now)

	keep := make(map[string]struct{}, len(inputs))
	for _, relayURL := range inputs {
		keep[relayURL] = struct{}{}
	}

	changed := false
	for key, state := range s.relays {
		_, bootstrap := keep[key]
		if state.Bootstrap == bootstrap {
			continue
		}
		state.Bootstrap = bootstrap
		if disposableRelayState(state) {
			delete(s.relays, key)
		} else {
			s.relays[key] = state
		}
		changed = true
	}

	for _, relayURL := range inputs {
		if state, ok := s.relays[relayURL]; ok {
			if !state.Bootstrap {
				state.Bootstrap = true
				s.relays[relayURL] = state
				changed = true
			}
			continue
		}

		state := newRelayState(relayURL)
		state.Bootstrap = true
		s.relays[relayURL] = state
		changed = true
	}
	if changed {
		s.bumpGenerationLocked()
	}
}

func (s *RelaySet) AddBootstrapRelayURL(relayURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if ok && state.Bootstrap {
		return
	}
	if !ok {
		state = newRelayState(relayURL)
	}
	state.Bootstrap = true
	s.relays[relayURL] = state
	s.bumpGenerationLocked()
}

func (s *RelaySet) RemoveBootstrapRelayURL(relayURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok || !state.Bootstrap {
		return
	}
	state.Bootstrap = false
	if disposableRelayState(state) {
		delete(s.relays, relayURL)
	} else {
		s.relays[relayURL] = state
	}
	s.bumpGenerationLocked()
}

func disposableRelayState(state RelayState) bool {
	return !state.Bootstrap && !state.hasObservedDescriptor() && !state.Banned &&
		state.discoveryFailures == 0 && state.activeFailures == 0 &&
		state.nextDiscoveryRefreshAt.IsZero() && state.suppressActiveUntil.IsZero()
}

func (s *RelaySet) AggregateRelays() []RelayState {
	return selectAggregate(s.currentRelayStates(time.Now().UTC()))
}

func (s *RelaySet) AllRelays() []RelayState {
	return s.currentRelayStates(time.Now().UTC())
}

func (s *RelaySet) ConfirmedRelays() []RelayState {
	return selectConfirmed(s.currentRelayStates(time.Now().UTC()))
}

type Route struct {
	path     []string
	explicit bool
}

func NewRoute(path []string, explicit bool) Route {
	return Route{
		path:     append([]string(nil), path...),
		explicit: explicit,
	}
}

func (r Route) Explicit() bool {
	return r.explicit
}

// ListenerRelayURL returns the entry relay URL for this route.
// For single-hop routes this is the sole relay; for multi-hop
// routes it is the first hop the local listener connects to.
func (r Route) ListenerRelayURL() string {
	if len(r.path) == 0 {
		return ""
	}
	return r.path[0]
}

// ExitRelayURL returns the final relay URL in the path.
func (r Route) ExitRelayURL() string {
	if len(r.path) == 0 {
		return ""
	}
	return r.path[len(r.path)-1]
}

func (r Route) MultiHop() []string {
	if len(r.path) <= 1 {
		return nil
	}
	return append([]string(nil), r.path...)
}

func (r Route) Equal(other Route) bool {
	return r.explicit == other.explicit && slices.Equal(r.path, other.path)
}

// WithListenerRelayURL returns a new Route with the entry relay URL
// replaced by the normalized value. This is used after URL normalization
// so the path and the listener target remain consistent.
func (r Route) WithListenerRelayURL(relayURL string) Route {
	if len(r.path) == 0 {
		return NewRoute([]string{relayURL}, r.explicit)
	}
	path := append([]string(nil), r.path...)
	path[0] = relayURL
	return Route{path: path, explicit: r.explicit}
}

func (s *RelaySet) PlanRoutes(explicitPath []string, routeState RouteState) ([]Route, error) {
	routes, err := s.planRoutesInternal(explicitPath, routeState)
	if err != nil {
		return nil, err
	}
	// Atomically publish the computed routes so the runtime loop and
	// OptimizeRoutes operate on the same canonical slice.
	s.activeRoutes.Store(&routes)
	return routes, nil
}

func (s *RelaySet) planRoutesInternal(explicitPath []string, routeState RouteState) ([]Route, error) {
	if len(explicitPath) > 0 {
		if len(explicitPath) == 1 {
			return nil, fmt.Errorf("multi-hop requires at least entry and exit relay urls")
		}
		return []Route{NewRoute(explicitPath, true)}, nil
	}

	s.mu.RLock()
	if cached, ok := s.matchCachedPlanLocked(routeState); ok {
		s.mu.RUnlock()
		return cached, nil
	}
	s.mu.RUnlock()

	now := time.Now().UTC()
	states := s.currentRelayStates(now)
	if len(routeState.ExplicitRelayURLs) > 0 {
		seen := make(map[string]struct{}, len(states))
		for _, state := range states {
			if relayURL := strings.TrimSpace(state.Descriptor.APIHTTPSAddr); relayURL != "" {
				seen[relayURL] = struct{}{}
			}
		}
		for _, relayURL := range routeState.ExplicitRelayURLs {
			relayURL = strings.TrimSpace(relayURL)
			if relayURL == "" {
				continue
			}
			if _, ok := seen[relayURL]; ok {
				continue
			}
			states = append(states, newRelayState(relayURL))
			seen[relayURL] = struct{}{}
		}
	}

	// Single unified MOLS flow: RankRelayPool is the sole scheduler for
	// both single-hop and multi-hop routing. Depth determines whether we
	// emit 1-length paths or sliding-window multi-hop paths.
	requireOverlay := routeState.MultiHopDepth > 1
	autoPool := filterCandidatePool(states, routeState, now, requireOverlay)
	ranked := RankRelayPool(autoPool, routeState.LocalAddress)

	depth := routeState.MultiHopDepth
	if depth <= 1 {
		maxActive := routeState.MaxActiveRelays
		if maxActive <= 0 {
			maxActive = defaultMaxActiveRelays
		}
		if len(ranked) > maxActive {
			ranked = ranked[:maxActive]
		}
		// Banned explicit relays must be dropped, matching the legacy
		// selectAggregate gate that filtered them before promotion.
		bannedSet := make(map[string]bool, len(states))
		for _, state := range states {
			if state.Banned {
				bannedSet[state.Descriptor.APIHTTPSAddr] = true
			}
		}
		routes := make([]Route, 0, len(ranked)+len(routeState.ExplicitRelayURLs))
		for _, relayURL := range routeState.ExplicitRelayURLs {
			if bannedSet[relayURL] {
				continue
			}
			routes = append(routes, NewRoute([]string{relayURL}, true))
		}
		for _, relayURL := range ranked {
			routes = append(routes, NewRoute([]string{relayURL}, false))
		}
		s.mu.Lock()
		s.storeCachedPlanLocked(routeState, routes)
		s.mu.Unlock()
		return routes, nil
	}

	routes, err := buildMOLSPaths(ranked, depth)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.storeCachedPlanLocked(routeState, routes)
	s.mu.Unlock()
	return routes, nil
}

// ActiveRoutes returns the currently active route slice. The returned slice
// is a copy, so callers can inspect it safely while the route set continues
// to optimize and swap paths in the background.
func (s *RelaySet) ActiveRoutes() []Route {
	ptr := s.activeRoutes.Load()
	if ptr == nil {
		return nil
	}
	routes := *ptr
	out := make([]Route, len(routes))
	copy(out, routes)
	return out
}

// OptimizeRoutes scans the active route slice for dirty paths — routes whose
// hops carry a saturated or heavily loaded RelayState — and transposes each
// dirty hop with the best available lighter candidate from a copied MOLS
// array. The entire route slice is replaced atomically; no per-route state
// flags or complex lifecycle machinery is introduced.
//
// If changedURLs is supplied, only routes that contain one or more of those
// URLs are considered. This lets callers react to load telemetry updates
// without re-scanning the entire active route table.
func (s *RelaySet) OptimizeRoutes(routeState RouteState, changedURLs ...string) (bool, error) {
	now := time.Now().UTC()
	states := s.currentRelayStates(now)

	currentPtr := s.activeRoutes.Load()
	if currentPtr == nil {
		return false, nil
	}
	current := *currentPtr
	if len(current) == 0 {
		return false, nil
	}

	changedSet := make(map[string]struct{}, len(changedURLs))
	for _, url := range changedURLs {
		if url != "" {
			changedSet[url] = struct{}{}
		}
	}

	// Infer overlay requirement from the currently active paths rather than
	// relying on an external configuration flag. Any multi-hop path means we
	// need overlay-capable candidates for transposition.
	requireOverlay := false
	for _, route := range current {
		if len(route.path) > 1 {
			requireOverlay = true
			break
		}
	}

	// Build the replacement pool using the same eligibility rules as path
	// generation, but excluding explicit relays (operator intent is fixed).
	pool := filterCandidatePool(states, routeState, now, requireOverlay)
	if len(pool) == 0 {
		return false, nil
	}

	// Copy the MOLS-ranked array so transposition does not mutate the canonical ranking.
	ranked := RankRelayPool(pool, routeState.LocalAddress)
	if len(ranked) == 0 {
		return false, nil
	}
	rankedCopy := append([]string(nil), ranked...)

	// Index relay state by URL for fast load lookup during dirty detection.
	stateByURL := make(map[string]RelayState, len(states))
	for _, state := range states {
		url := strings.TrimSpace(state.Descriptor.APIHTTPSAddr)
		if url != "" {
			stateByURL[url] = state
		}
	}

	newRoutes := make([]Route, len(current))
	copy(newRoutes, current)

	swapped := false
	for i, route := range current {
		path := route.path
		if len(path) == 0 {
			continue
		}
		// Explicit routes reflect operator intent; they are never auto-tuned.
		if route.explicit {
			continue
		}

		// When the caller tells us which URLs changed, skip routes that are
		// unrelated to the change.
		if len(changedSet) > 0 {
			relevant := false
			for _, hop := range path {
				if _, ok := changedSet[hop]; ok {
					relevant = true
					break
				}
			}
			if !relevant {
				continue
			}
		}

		// Detect the most heavily loaded (dirty) hop in this path.
		dirtyIdx := -1
		var dirtyLoad float64
		for j, hop := range path {
			state, ok := stateByURL[hop]
			if !ok {
				continue
			}
			if state.IsSaturated && state.LoadFactor > dirtyLoad {
				dirtyIdx = j
				dirtyLoad = state.LoadFactor
			}
		}
		if dirtyIdx == -1 {
			continue
		}

		// Find the highest-ranked replacement that is not already in the
		// path and is not itself saturated.
		used := make(map[string]struct{}, len(path))
		for _, hop := range path {
			used[hop] = struct{}{}
		}

		replacement := ""
		for _, candidate := range rankedCopy {
			if _, ok := used[candidate]; ok {
				continue
			}
			candState, ok := stateByURL[candidate]
			if !ok {
				continue
			}
			if candState.IsSaturated {
				continue
			}
			replacement = candidate
			break
		}
		if replacement == "" {
			continue
		}

		newPath := make([]string, len(path))
		copy(newPath, path)
		newPath[dirtyIdx] = replacement
		newRoutes[i] = NewRoute(newPath, route.explicit)
		swapped = true
	}

	if !swapped {
		return false, nil
	}

	// Atomic swap: the runtime loop sees the new slice in one stroke.
	s.activeRoutes.Store(&newRoutes)
	return true, nil
}

// filterCandidatePool returns the auto-selected relay pool eligible for MOLS
// ranking. When requireOverlay is true, only relays with observed descriptors,
// valid expiry, and overlay peer support are admitted.
func filterCandidatePool(states []RelayState, routeState RouteState, now time.Time, requireOverlay bool) []RelayState {
	pool := make([]RelayState, 0, len(states))
	for _, state := range states {
		if state.Banned {
			continue
		}
		relayURL := state.Descriptor.APIHTTPSAddr
		if slices.Contains(routeState.ExplicitRelayURLs, relayURL) {
			continue
		}
		if state.hasObservedDescriptor() {
			if !state.Descriptor.ExpiresAt.After(now) {
				continue
			}
			if routeState.RequireUDP && !state.Descriptor.SupportsUDP {
				continue
			}
			if routeState.RequireTCP && !state.Descriptor.SupportsTCP {
				continue
			}
			if requireOverlay && !state.Descriptor.HasOverlayPeer() {
				continue
			}
		} else if requireOverlay {
			continue
		}
		if !state.suppressActiveUntil.IsZero() && state.suppressActiveUntil.After(now) {
			continue
		}
		pool = append(pool, state)
	}
	return pool
}

// buildMOLSPaths constructs non-wrapping, loop-free multi-hop paths from a
// MOLS-ranked relay list using a sliding window of the given depth.
func buildMOLSPaths(ranked []string, depth int) ([]Route, error) {
	if len(ranked) < depth {
		return nil, fmt.Errorf("multi-hop-depth %d requires at least %d candidates, got %d", depth, depth, len(ranked))
	}
	n := len(ranked)
	routes := make([]Route, 0, n-depth+1)
	seen := make(map[string]bool, n-depth+1)
	for start := 0; start <= n-depth; start++ {
		path := make([]string, 0, depth)
		for i := 0; i < depth; i++ {
			path = append(path, ranked[start+i])
		}
		key := strings.Join(path, "|")
		if seen[key] {
			continue
		}
		seen[key] = true
		routes = append(routes, NewRoute(path, false))
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("no valid multi-hop paths could be constructed from %d candidates with depth %d", n, depth)
	}
	return routes, nil
}

func (s *RelaySet) overlayRefreshCandidates(now time.Time) []RelayState {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	states := s.overlayPeerRelayStates(now)
	out := make([]RelayState, 0, len(states))
	for _, state := range states {
		if !state.nextDiscoveryRefreshAt.IsZero() && state.nextDiscoveryRefreshAt.After(now) {
			continue
		}
		out = append(out, state)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *RelaySet) overlayPeerRelayStates(now time.Time) []RelayState {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	states := s.currentRelayStates(now)
	out := make([]RelayState, 0, len(states))
	for _, state := range states {
		if state.Banned || !state.hasObservedDescriptor() || !state.Descriptor.ExpiresAt.After(now) || !state.Descriptor.HasOverlayPeer() {
			continue
		}
		out = append(out, state)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *RelaySet) OverlayPeerDescriptor() []types.RelayDescriptor {
	states := s.overlayPeerRelayStates(time.Now().UTC())
	if len(states) == 0 {
		return nil
	}
	out := make([]types.RelayDescriptor, 0, len(states))
	for _, state := range states {
		out = append(out, state.Descriptor)
	}
	return out
}

func (s *RelaySet) OverlayRelayDescriptor(relayURL string, now time.Time) (types.RelayDescriptor, bool) {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	relayURL = strings.TrimSpace(relayURL)

	s.mu.RLock()
	state := s.relays[relayURL]
	s.mu.RUnlock()
	if state.Banned || !state.hasObservedDescriptor() || !state.Descriptor.ExpiresAt.After(now) || !state.Descriptor.HasOverlayPeer() {
		return types.RelayDescriptor{}, false
	}
	return state.Descriptor, true
}

// BootstrapRelayURLs returns configured bootstrap discovery endpoints that
// can receive this relay's periodic self-announce.
func (s *RelaySet) BootstrapRelayURLs() []string {
	states := s.currentRelayStates(time.Now().UTC())
	out := make([]string, 0, len(states))
	for _, state := range states {
		if state.Banned || !state.Bootstrap {
			continue
		}
		relayURL := strings.TrimSpace(state.Descriptor.APIHTTPSAddr)
		if relayURL == "" {
			continue
		}
		out = append(out, relayURL)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *RelaySet) Descriptors(self types.RelayDescriptor) []types.RelayDescriptor {
	now := time.Now().UTC()
	out := make([]types.RelayDescriptor, 0, 1)
	seen := make(map[string]struct{})
	add := func(desc types.RelayDescriptor) {
		relayURL := desc.APIHTTPSAddr
		if relayURL == "" {
			return
		}
		if _, ok := seen[relayURL]; ok {
			return
		}
		if !desc.ExpiresAt.After(now) {
			return
		}
		seen[relayURL] = struct{}{}
		out = append(out, desc)
	}

	if self.APIHTTPSAddr != "" && self.ExpiresAt.After(now) {
		add(self)
	}
	for _, state := range s.currentRelayStates(now) {
		if state.Banned || !state.hasObservedDescriptor() {
			continue
		}
		add(state.Descriptor)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *RelaySet) BanRelayURL(relayURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok {
		state = newRelayState(relayURL)
	}
	state.suppressActiveUntil = time.Time{}
	state.Banned = true
	s.relays[relayURL] = state
	s.bumpGenerationLocked()
}

func (s *RelaySet) DropRelayURLFromActivePool(relayURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	s.clearExpiredPoolBansLocked(now)
	state, ok := s.relays[relayURL]
	if !ok || state.Banned {
		return
	}
	state.Confirmed = false
	state.suppressActiveUntil = now.Add(activeDropTTL)
	s.relays[relayURL] = state
	s.bumpGenerationLocked()
}

func (s *RelaySet) AllowRelayURL(relayURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok {
		state = newRelayState(relayURL)
	}
	state.Banned = false
	state.suppressActiveUntil = time.Time{}
	state.unhealthySince = time.Time{}
	s.relays[relayURL] = state
	s.bumpGenerationLocked()
}

func (s *RelaySet) ConfirmRelayURL(relayURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	s.clearExpiredPoolBansLocked(now)
	state, ok := s.relays[relayURL]
	if !ok {
		state = newRelayState(relayURL)
	}
	if state.Banned {
		s.relays[relayURL] = state
		return
	}
	state.Confirmed = true
	state.activeFailures = 0
	state.suppressActiveUntil = time.Time{}
	s.relays[relayURL] = state
	s.bumpGenerationLocked()
}

func (s *RelaySet) UnconfirmRelayURL(relayURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok {
		return
	}
	state.Confirmed = false
	s.relays[relayURL] = state
	s.bumpGenerationLocked()
}

// DeactivateRelayURL drops a relay out of active selection while keeping its
// discovered descriptor as a candidate.
func (s *RelaySet) DeactivateRelayURL(relayURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok {
		return
	}
	state.Confirmed = false
	state.suppressActiveUntil = time.Now().Add(defaultDirectRecoveryBackoff)
	s.relays[relayURL] = state
	s.bumpGenerationLocked()
}

func (s *RelaySet) ApplyRelayDiscoveryResponse(targetURL string, resp types.DiscoveryResponse, now time.Time) (relaySetChanged bool, err error) {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	protocolMismatch := resp.ProtocolVersion != types.DiscoveryVersion
	authoritative := targetURL != ""

	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearExpiredPoolBansLocked(now)

	discoveredByURL := make(map[string]RelayState, len(resp.Relays))
	discoveredOrder := make([]string, 0, len(resp.Relays)+1)
	targetFound := false
	add := func(descriptor types.RelayDescriptor) {
		// Cryptographic gate: every gossiped descriptor must carry a valid
		// signature. Unsigned or invalid-signature descriptors are dropped
		// silently; they cannot poison the local relay set, and other peers
		// will reach the same verdict independently. This is the sole global
		// trust gate under unconditional propagation, so it is mandatory.
		verified, verifyErr := auth.VerifyRelayDescriptor(descriptor)
		if verifyErr != nil {
			return
		}
		if err := validateRelayDescriptorFreshness(verified, now); err != nil {
			return
		}
		relayState := RelayState{
			Descriptor: verified,
			LastSeenAt: now,
		}
		relayURL := verified.APIHTTPSAddr
		if relayURL == "" {
			return
		}
		if existing, ok := s.relays[relayURL]; ok && existing.Banned {
			return
		}
		if authoritative && relayURL == targetURL {
			targetFound = true
		}
		if _, ok := discoveredByURL[relayURL]; !ok {
			discoveredOrder = append(discoveredOrder, relayURL)
		}
		discoveredByURL[relayURL] = relayState
	}
	for _, descriptor := range resp.Relays {
		add(descriptor)
	}
	missingTarget := authoritative && !targetFound

	for _, relayURL := range discoveredOrder {
		record := discoveredByURL[relayURL]
		existingAtURL, hasExistingAtURL := s.relays[relayURL]
		record = mergeLocalRelayState(record, existingAtURL)

		isAuthoritativeTarget := !protocolMismatch && !missingTarget && authoritative && relayURL == targetURL
		if isAuthoritativeTarget {
			record = markDiscoveryConfirmed(record)
		}

		if upsert := s.upsertDescriptorLocked(record, now, isAuthoritativeTarget); upsert != upsertAccepted {
			// The monotonic-IssuedAt check rejected this descriptor as a
			// rollback, or ignored it because a newer same-identity descriptor
			// for this URL is already present. The cryptographic identity in
			// s.relays is unchanged, but if we successfully reached the
			// authoritative target we should still credit it as alive on its
			// existing URL slot.
			if isAuthoritativeTarget && hasExistingAtURL {
				if existingAtURL.discoveryFailures != 0 || !existingAtURL.nextDiscoveryRefreshAt.IsZero() || !existingAtURL.unhealthySince.IsZero() {
					existingAtURL = markDiscoveryConfirmed(existingAtURL)
					s.relays[relayURL] = existingAtURL
					relaySetChanged = true
				}
			}
			continue
		}

		if !hasExistingAtURL || !reflect.DeepEqual(existingAtURL, record) {
			relaySetChanged = true
		}
	}
	s.enforceCapLocked()
	if relaySetChanged {
		s.bumpGenerationLocked()
	}
	if missingTarget {
		return relaySetChanged, errors.New("target relay descriptor missing from relays")
	}
	if protocolMismatch && authoritative {
		return relaySetChanged, fmt.Errorf("relay discovery protocol version mismatch: relay=%q client=%q", resp.ProtocolVersion, types.DiscoveryVersion)
	}
	return relaySetChanged, nil
}

func (s *RelaySet) RecordDiscoveryRTT(relayURL string, rtt time.Duration, measuredAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok {
		return
	}

	state.DiscoveryRTT = rtt
	state.DiscoveryRTTAt = measuredAt
	s.relays[relayURL] = state
	s.bumpGenerationLocked()
}

func (s *RelaySet) RecordLoadFactor(relayURL string, loadFixed uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok {
		return
	}

	state.StoreLoadFactor(loadFixed)
	s.relays[relayURL] = state
	s.bumpGenerationLocked()
}

// InsertAnnounced ingests a single descriptor submitted via the announce
// endpoint. It is the only public mutator that is intended to be reachable
// from external (untrusted) callers. The full validation pipeline runs
// inline:
//
//  1. The descriptor signature is verified against the recovered public key
//     and matched to the descriptor's Address field.
//  2. The descriptor must be currently valid (ExpiresAt strictly in the
//     future) and not significantly clock-skewed (IssuedAt no further into
//     the future than AnnounceClockSkewTolerance, validity window no longer
//     than AnnounceMaxValidity).
//  3. Local merge preserves Bootstrap, Confirmed, Banned, discovery retry
//     state, active suppression state, and telemetry from any pre-existing
//     entry at the same URL.
//  4. The shared upsertDescriptorLocked method enforces the
//     monotonic-IssuedAt-per-key rollback guard and the cross-identity
//     URL-takeover guard. Announce never grants takeover authority; only
//     direct authoritative refresh can do that.
//  5. After a successful upsert, the LRU cap is enforced; bootstrap and
//     listener-confirmed entries are pinned.
//
// Returns nil iff the descriptor was stored, idempotently refreshed, or is an
// older same-URL/same-identity announce already superseded by local state.
func (s *RelaySet) InsertAnnounced(desc types.RelayDescriptor, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	normalized, err := auth.VerifyRelayDescriptor(desc)
	if err != nil {
		return err
	}
	if err := validateRelayDescriptorFreshness(normalized, now); err != nil {
		return err
	}

	record := RelayState{
		Descriptor: normalized,
		LastSeenAt: now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearExpiredPoolBansLocked(now)

	relayURL := record.Descriptor.APIHTTPSAddr
	if existing, ok := s.relays[relayURL]; ok && existing.Banned {
		return errors.New("relay banned from pool")
	}
	if existing, ok := s.relays[relayURL]; ok {
		record = mergeLocalRelayState(record, existing)
	}

	switch s.upsertDescriptorLocked(record, now, false) {
	case upsertAccepted:
		s.enforceCapLocked()
		return nil
	case upsertIgnored:
		return nil
	case upsertRejected:
		return errors.New("announced descriptor rejected by rollback or takeover guard")
	}
	return nil
}

func validateRelayDescriptorFreshness(desc types.RelayDescriptor, now time.Time) error {
	if desc.IssuedAt.IsZero() {
		return errors.New("relay descriptor missing issued_at")
	}
	if !desc.ExpiresAt.After(now) {
		return errors.New("relay descriptor already expired")
	}
	if desc.IssuedAt.After(now.Add(AnnounceClockSkewTolerance)) {
		return errors.New("relay descriptor is too far in the future")
	}
	if desc.ExpiresAt.Sub(desc.IssuedAt) > AnnounceMaxValidity {
		return errors.New("relay descriptor validity window exceeds maximum")
	}
	return nil
}

// enforceCapLocked trims s.relays back to MaxAnnouncedRelays using a
// two-tier eviction strategy: non-Bootstrap non-Confirmed entries are
// evicted first (oldest by LastSeenAt), then non-Bootstrap Confirmed
// entries as a last resort. Bootstrap entries are absolutely pinned.
// An operator misconfig that lists more than MaxAnnouncedRelays bootstraps
// is surfaced by the resulting overflow rather than silently violating
// operator intent. Tombstone keyIndex entries whose replay window has
// closed are swept opportunistically. The caller MUST already hold s.mu
// as a write lock.
func (s *RelaySet) enforceCapLocked() {
	now := time.Now().UTC()
	s.clearExpiredPoolBansLocked(now)
	for address, entry := range s.keyIndex {
		if !entry.TombstoneUntil.IsZero() && now.After(entry.TombstoneUntil) {
			delete(s.keyIndex, address)
		}
	}
	if len(s.relays) <= MaxAnnouncedRelays {
		return
	}
	type ageEntry struct {
		url       string
		confirmed bool
		seenAt    time.Time
	}
	candidates := make([]ageEntry, 0, len(s.relays))
	for url, state := range s.relays {
		if state.Bootstrap || state.Banned {
			continue
		}
		candidates = append(candidates, ageEntry{
			url:       url,
			confirmed: state.Confirmed,
			seenAt:    state.LastSeenAt,
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		// Non-confirmed entries evict first; confirmed is the last-resort
		// tier. Within each tier, oldest LastSeenAt evicts first.
		if candidates[i].confirmed != candidates[j].confirmed {
			return !candidates[i].confirmed
		}
		return candidates[i].seenAt.Before(candidates[j].seenAt)
	})
	for _, c := range candidates {
		if len(s.relays) <= MaxAnnouncedRelays {
			return
		}
		delete(s.relays, c.url)
		s.bumpGenerationLocked()
	}
}

func (s *RelaySet) RecordDiscoveryFailure(relayURL string, recoveryFailures int) (backedOff bool, backoffReason string, failureCount int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	s.clearExpiredPoolBansLocked(now)
	state, ok := s.relays[relayURL]
	if !ok || state.Banned {
		return false, "", 0
	}
	state.discoveryFailures++
	if state.unhealthySince.IsZero() {
		state.unhealthySince = now
	}
	if !state.unhealthySince.Add(AnnounceMaxValidity).After(now) {
		s.banFromPoolLocked(relayURL, now)
		return true, "unhealthy", state.discoveryFailures
	}

	if recoveryFailures <= 0 || state.discoveryFailures < recoveryFailures {
		s.relays[relayURL] = state
		s.bumpGenerationLocked()
		return false, "retry", state.discoveryFailures
	}
	failuresOverBudget := state.discoveryFailures - recoveryFailures
	backoff := defaultDirectRecoveryBackoff << min(failuresOverBudget, 3)
	if backoff > maxDirectRecoveryBackoff {
		backoff = maxDirectRecoveryBackoff
	}
	state.nextDiscoveryRefreshAt = now.Add(backoff)
	s.relays[relayURL] = state
	s.bumpGenerationLocked()
	return true, "discovery", state.discoveryFailures
}

func (s *RelaySet) RecordActiveFailure(relayURL string, recoveryFailures int) (backedOff bool, backoffReason string, failureCount int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	s.clearExpiredPoolBansLocked(now)
	state, ok := s.relays[relayURL]
	if !ok || state.Banned {
		return false, "", 0
	}
	state.activeFailures++

	if recoveryFailures <= 0 || state.activeFailures < recoveryFailures {
		s.relays[relayURL] = state
		s.bumpGenerationLocked()
		return false, "retry", state.activeFailures
	}
	failuresOverBudget := state.activeFailures - recoveryFailures
	backoff := defaultDirectRecoveryBackoff << min(failuresOverBudget, 3)
	if backoff > maxDirectRecoveryBackoff {
		backoff = maxDirectRecoveryBackoff
	}
	state.suppressActiveUntil = now.Add(backoff)
	s.relays[relayURL] = state
	s.bumpGenerationLocked()
	return true, "active", state.activeFailures
}
