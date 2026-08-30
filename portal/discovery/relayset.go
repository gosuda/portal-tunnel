package discovery

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
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

// NewRelaySet creates a new RelaySet initialized with the given bootstrap relay URLs.
func NewRelaySet(bootstrapRelayURLs []string) *RelaySet {
	set := &RelaySet{
		relays:   make(map[string]RelayState),
		keyIndex: make(map[string]keyIndexEntry),
	}
	set.SetBootstrapRelayURLs(bootstrapRelayURLs)
	return set
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
	for relayURL, state := range s.relays {
		if !state.Banned || state.suppressActiveUntil.IsZero() || state.suppressActiveUntil.After(now) {
			continue
		}
		if !state.Bootstrap {
			delete(s.relays, relayURL)
			continue
		}
		state.Banned = false
		state.suppressActiveUntil = time.Time{}
		state.unhealthySince = time.Time{}
		s.relays[relayURL] = state
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
}

func mergeLocalRelayState(record, existing RelayState) RelayState {
	record.Bootstrap = record.Bootstrap || existing.Bootstrap
	record.Confirmed = record.Confirmed || existing.Confirmed
	record.Banned = record.Banned || existing.Banned
	record.Dead = record.Dead || existing.Dead
	// Trust never transfers across an identity change on the same URL: a
	// takeover after descriptor expiry must start over as a candidate. A
	// genuine rotation re-verifies through the authoritative probe path.
	sameIdentity := strings.EqualFold(
		strings.TrimSpace(record.Descriptor.Address),
		strings.TrimSpace(existing.Descriptor.Address),
	)
	if sameIdentity && existing.Trust > record.Trust {
		record.Trust = existing.Trust
	}
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

func markDiscoveryVerified(state RelayState) RelayState {
	state.Trust = RelayVerified
	state.Dead = false
	state.discoveryFailures = 0
	state.nextDiscoveryRefreshAt = time.Time{}
	state.unhealthySince = time.Time{}
	return state
}

func (s *RelaySet) descriptorRollbackResultLocked(
	record RelayState,
	relayURL string,
	address string,
	now time.Time,
) (upsertResult, bool) {
	prev, ok := s.keyIndex[address]
	if !ok {
		return 0, false
	}
	// Stale tombstone: no replayable descriptor could still be within its
	// validity window, so drop the anchor and accept the fresh descriptor as
	// if first-seen.
	if !prev.TombstoneUntil.IsZero() && now.After(prev.TombstoneUntil) {
		delete(s.keyIndex, address)
		return 0, false
	}
	if !record.Descriptor.IssuedAt.Before(prev.IssuedAt) {
		return 0, false
	}

	existing, ok := s.relays[relayURL]
	if !ok {
		return upsertRejected, true
	}
	existingAddress := strings.ToLower(strings.TrimSpace(existing.Descriptor.Address))
	existingIsCurrent := !existing.Descriptor.IssuedAt.Before(record.Descriptor.IssuedAt)
	if existingAddress == address && existing.Descriptor.ExpiresAt.After(now) && existingIsCurrent {
		return upsertIgnored, true
	}
	return upsertRejected, true
}

func (s *RelaySet) crossIdentityTakeoverBlockedLocked(relayURL, address string, now time.Time) bool {
	existing, ok := s.relays[relayURL]
	if !ok {
		return false
	}
	existingAddress := strings.ToLower(strings.TrimSpace(existing.Descriptor.Address))
	differentIdentity := existingAddress != "" && address != "" && existingAddress != address
	unexpired := !existing.Descriptor.ExpiresAt.IsZero() && existing.Descriptor.ExpiresAt.After(now)
	return differentIdentity && unexpired
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
		if result, found := s.descriptorRollbackResultLocked(record, relayURL, address, now); found {
			return result
		}
	}
	if !allowCrossIdentityTakeover && s.crossIdentityTakeoverBlockedLocked(relayURL, address, now) {
		return upsertRejected
	}
	s.relays[relayURL] = record
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
	// Shared untrusted-ingestion invariant: whichever path admitted the
	// descriptor (announce, hop route, or gossiped discovery response), a
	// single signing identity never holds more unverified entries than the
	// per-identity cap. Confirmed entries are never evicted by this cap.
	s.enforceIdentityCapLocked(address)
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
	}

	for _, relayURL := range inputs {
		if state, ok := s.relays[relayURL]; ok {
			if !state.Bootstrap {
				state.Bootstrap = true
				s.relays[relayURL] = state
			}
			continue
		}

		state := newRelayState(relayURL)
		state.Bootstrap = true
		s.relays[relayURL] = state
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

// Route represents a planned relay path with optional multi-hop routing.
type Route struct {
	path     []string
	explicit bool
}

// NewRoute creates a new Route with the given path and explicit flag.
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
	if len(explicitPath) > 0 {
		if len(explicitPath) == 1 {
			return nil, fmt.Errorf("multi-hop requires at least entry and exit relay urls")
		}
		return []Route{NewRoute(explicitPath, true)}, nil
	}

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

	ranked := RankRelayPool(filterCandidatePool(states, routeState, now, routeState.MultiHopDepth > 1), routeState.LocalAddress)
	if routeState.MultiHopDepth > 1 {
		maxActive := routeState.MaxActiveRelays
		if maxActive <= 0 {
			maxActive = defaultMaxActiveRelays
		}
		return buildMOLSPaths(ranked, routeState.MultiHopDepth, maxActive)
	}

	maxActive := routeState.MaxActiveRelays
	if maxActive <= 0 {
		maxActive = defaultMaxActiveRelays
	}
	ranked = applyActiveStickiness(ranked, routeState.ActiveRelayURLs, maxActive)
	routes := make([]Route, 0, len(ranked)+len(routeState.ExplicitRelayURLs))
	for _, relayURL := range routeState.ExplicitRelayURLs {
		eligible := true
		for _, state := range states {
			if state.Descriptor.APIHTTPSAddr != relayURL {
				continue
			}
			unavailable := state.Banned || state.Dead || !state.supportsRequiredTransports(routeState, now)
			if unavailable {
				eligible = false
				break
			}
		}
		if !eligible {
			continue
		}
		routes = append(routes, NewRoute([]string{relayURL}, true))
	}
	for _, relayURL := range ranked {
		routes = append(routes, NewRoute([]string{relayURL}, false))
	}
	return routes, nil
}

// filterCandidatePool returns the auto-selected relay pool eligible for MOLS
// ranking. When requireOverlay is true, only relays with observed descriptors,
// valid expiry, and overlay peer support are admitted.
func filterCandidatePool(states []RelayState, routeState RouteState, now time.Time, requireOverlay bool) []RelayState {
	pool := make([]RelayState, 0, len(states))
	for _, state := range states {
		relayURL := state.Descriptor.APIHTTPSAddr
		if state.Trust != RelayVerified {
			// A bootstrap URL configured by the operator stays eligible as
			// a URL-only single-hop fallback until a direct probe verifies
			// it, but a descriptor squatted on a bootstrap URL by an
			// untrusted candidate is not eligible at all, and unverified
			// bootstrap entries never join multi-hop paths.
			if requireOverlay || !state.Bootstrap || state.hasObservedDescriptor() {
				continue
			}
		}
		if !requireOverlay && slices.Contains(routeState.ExplicitRelayURLs, relayURL) {
			continue
		}
		if requireOverlay {
			if !state.eligibleForMultiHop(routeState, now) {
				continue
			}
			pool = append(pool, state)
			continue
		}
		if state.Banned || state.Dead {
			continue
		}
		if state.hasObservedDescriptor() {
			if !state.Descriptor.ExpiresAt.After(now) {
				continue
			}
			if !state.supportsRequiredTransports(routeState, now) {
				continue
			}
		}
		if !state.suppressActiveUntil.IsZero() && state.suppressActiveUntil.After(now) {
			continue
		}
		pool = append(pool, state)
	}
	return pool
}

// buildMOLSPaths constructs loop-free paths from a ranked pool. Paths wrap
// around the whole pool, while maxEntries independently bounds listener and
// public-ingress fan-out.
func buildMOLSPaths(ranked []string, depth, maxEntries int) ([]Route, error) {
	if len(ranked) < depth {
		return nil, fmt.Errorf("multi-hop-depth %d requires at least %d candidates, got %d", depth, depth, len(ranked))
	}
	n := len(ranked)
	if maxEntries <= 0 || maxEntries > n {
		maxEntries = n
	}
	routes := make([]Route, 0, maxEntries)
	for start := 0; start < maxEntries; start++ {
		path := make([]string, 0, depth)
		for i := range depth {
			path = append(path, ranked[(start+i)%n])
		}
		routes = append(routes, NewRoute(path, false))
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
		if state.Banned || state.Dead || !state.hasObservedDescriptor() {
			continue
		}
		if state.Trust != RelayVerified {
			continue
		}
		add(state.Descriptor)
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
}

// discoveryRelayStateLocked is the cryptographic gate for every gossiped
// descriptor. The caller must hold s.mu for reading the URL ban state.
func (s *RelaySet) discoveryRelayStateLocked(
	descriptor types.RelayDescriptor,
	now time.Time,
) (RelayState, string, bool) {
	verified, err := verifyFreshRelayDescriptor(descriptor, now)
	if err != nil {
		return RelayState{}, "", false
	}
	relayURL := verified.APIHTTPSAddr
	if relayURL == "" {
		return RelayState{}, "", false
	}
	if existing, ok := s.relays[relayURL]; ok && existing.Banned {
		return RelayState{}, "", false
	}
	return RelayState{Descriptor: verified, LastSeenAt: now}, relayURL, true
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
	for _, descriptor := range resp.Relays {
		relayState, relayURL, ok := s.discoveryRelayStateLocked(descriptor, now)
		if !ok {
			continue
		}
		if authoritative && relayURL == targetURL {
			targetFound = true
		}
		if _, ok := discoveredByURL[relayURL]; !ok {
			discoveredOrder = append(discoveredOrder, relayURL)
		}
		discoveredByURL[relayURL] = relayState
	}
	missingTarget := authoritative && !targetFound

	for _, relayURL := range discoveredOrder {
		record := discoveredByURL[relayURL]
		existingAtURL, hasExistingAtURL := s.relays[relayURL]
		record = mergeLocalRelayState(record, existingAtURL)

		isAuthoritativeTarget := !protocolMismatch && !missingTarget && authoritative && relayURL == targetURL
		if isAuthoritativeTarget {
			record = markDiscoveryVerified(record)
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
					existingAtURL = markDiscoveryVerified(existingAtURL)
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

	state.UpdateEWMARTT(rtt)
	state.DiscoveryRTT = rtt
	state.DiscoveryRTTAt = measuredAt
	s.relays[relayURL] = state
}

func (s *RelaySet) RecordLoadFactor(relayURL string, loadFixed uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok {
		return
	}

	state.UpdateLoad(loadFixed)
	s.relays[relayURL] = state
}

// InsertCandidate ingests a single descriptor from untrusted input (/sdk/hop
// or the announce endpoint) as a RelayCandidate. The full validation
// pipeline runs inline:
//
//  1. The descriptor signature is verified against the recovered public key
//     and matched to the descriptor's Address field.
//  2. The descriptor must be currently valid (ExpiresAt strictly in the
//     future) and not significantly clock-skewed (IssuedAt no further into
//     the future than AnnounceClockSkewTolerance, validity window no longer
//     than AnnounceMaxValidity).
//  3. Local merge preserves Bootstrap, Confirmed, Banned, Trust, discovery
//     retry state, active suppression state, and telemetry from any
//     pre-existing entry at the same URL.
//  4. The shared upsertDescriptorLocked method enforces the
//     monotonic-IssuedAt-per-key rollback guard and the cross-identity
//     URL-takeover guard, plus the per-identity candidate cap shared by
//     every untrusted ingestion path.
//
// Candidates serve overlay routing for the hop route that brought them in
// and remain refresh-poll targets, but they stay out of Descriptors() and
// automatic route planning until a direct authoritative probe of that exact
// relay promotes them to RelayVerified via ApplyRelayDiscoveryResponse.
func (s *RelaySet) InsertCandidate(desc types.RelayDescriptor, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	normalized, err := verifyFreshRelayDescriptor(desc, now)
	if err != nil {
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

// enforceIdentityCapLocked bounds how many candidate entries a single
// signing identity holds in the set. Overflow evicts that identity's own
// oldest candidates by LastSeenAt, so a flooding identity recycles its own
// slots instead of displacing other relays through the global cap. Bootstrap,
// banned, verified, and listener-confirmed entries are never evicted here;
// the keyIndex rollback anchors survive eviction by design. The caller MUST
// already hold s.mu as a write lock.
func (s *RelaySet) enforceIdentityCapLocked(address string) {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" {
		return
	}
	type ownedEntry struct {
		url    string
		seenAt time.Time
	}
	owned := make([]ownedEntry, 0, MaxAnnouncedRelaysPerIdentity+1)
	for url, state := range s.relays {
		if state.Bootstrap || state.Banned || state.Confirmed || state.Trust == RelayVerified {
			continue
		}
		if strings.ToLower(strings.TrimSpace(state.Descriptor.Address)) != address {
			continue
		}
		owned = append(owned, ownedEntry{url: url, seenAt: state.LastSeenAt})
	}
	if len(owned) <= MaxAnnouncedRelaysPerIdentity {
		return
	}
	sort.Slice(owned, func(i, j int) bool { return owned[i].seenAt.Before(owned[j].seenAt) })
	for _, entry := range owned[:len(owned)-MaxAnnouncedRelaysPerIdentity] {
		delete(s.relays, entry.url)
	}
}

func verifyFreshRelayDescriptor(desc types.RelayDescriptor, now time.Time) (types.RelayDescriptor, error) {
	verified, err := auth.VerifyRelayDescriptor(desc)
	if err != nil {
		return types.RelayDescriptor{}, err
	}
	if err := validateRelayDescriptorFreshness(verified, now); err != nil {
		return types.RelayDescriptor{}, err
	}
	return verified, nil
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
		protected bool
		seenAt    time.Time
	}
	candidates := make([]ageEntry, 0, len(s.relays))
	for url, state := range s.relays {
		if state.Bootstrap || state.Banned {
			continue
		}
		candidates = append(candidates, ageEntry{
			url:       url,
			protected: state.Confirmed || state.Trust == RelayVerified,
			seenAt:    state.LastSeenAt,
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		// Candidate entries evict first; verified and listener-confirmed
		// entries are the last-resort tier. Within each tier, oldest
		// LastSeenAt evicts first.
		if candidates[i].protected != candidates[j].protected {
			return !candidates[i].protected
		}
		return candidates[i].seenAt.Before(candidates[j].seenAt)
	})
	for _, c := range candidates {
		if len(s.relays) <= MaxAnnouncedRelays {
			return
		}
		delete(s.relays, c.url)
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
		return false, "retry", state.discoveryFailures
	}
	failuresOverBudget := state.discoveryFailures - recoveryFailures
	backoff := min(defaultDirectRecoveryBackoff<<min(failuresOverBudget, 3), maxDirectRecoveryBackoff)
	state.Dead = true
	state.nextDiscoveryRefreshAt = now.Add(backoff)
	s.relays[relayURL] = state
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
		return false, "retry", state.activeFailures
	}
	failuresOverBudget := state.activeFailures - recoveryFailures
	backoff := min(defaultDirectRecoveryBackoff<<min(failuresOverBudget, 3), maxDirectRecoveryBackoff)
	state.suppressActiveUntil = now.Add(backoff)
	s.relays[relayURL] = state
	return true, "active", state.activeFailures
}
