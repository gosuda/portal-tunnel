package discovery

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

var (
	errTargetRelayDescriptorMissingRelays                 = errors.New("target relay descriptor missing from relays")
	errTargetRelayDescriptorConflictsRetainedSigned       = errors.New("target relay descriptor conflicts with retained signed contents at the same issued_at")
	errRelayBannedFromPool                                = errors.New("relay banned from pool")
	errAnnouncedDescriptorRejectedRollbackOrTakeover      = errors.New("announced descriptor rejected by rollback or takeover guard")
	errAnnouncedDescriptorConflictsRetainedSignedContents = errors.New("announced descriptor conflicts with retained signed contents at the same issued_at")
	errRelayDescriptorMissingIssuedAt                     = errors.New("relay descriptor missing issued_at")
	errRelayDescriptorAlreadyExpired                      = errors.New("relay descriptor already expired")
	errRelayDescriptorTooFarFuture                        = errors.New("relay descriptor is too far in the future")
	errRelayDescriptorValidityWindowExceedsMaximum        = errors.New("relay descriptor validity window exceeds maximum")
)

// RelaySet owns the shared relay discovery view, keyed by APIHTTPSAddr.
// The keyIndex tracks the newest IssuedAt accepted per signing identity and
// rejects older descriptors as rollbacks; anchors survive eviction until
// their replay window closes. Both maps are read and written under s.mu:
// public methods own the lock end-to-end, while *Locked methods assume the
// caller already holds it as a write lock.
type RelaySet struct {
	mu              sync.RWMutex
	relays          map[string]relayState
	keyIndex        map[string]keyIndexEntry
	incompatible    map[string]types.IncompatibleRelayEntry
	releaseVersions map[string]relayReleaseObservation
}

type keyIndexEntry struct {
	IssuedAt       time.Time
	TombstoneUntil time.Time
}

type relayReleaseObservation struct {
	releaseVersion string
	observedAt     time.Time
}

// ErrProtocolMismatch reports that a discovery response came from a relay
// whose discovery protocol version is incompatible with ours. The relay
// answered and is reachable; callers must not treat this as a health
// failure.
var ErrProtocolMismatch = errors.New("relay discovery protocol version mismatch")

type upsertResult int

const (
	upsertRejected upsertResult = iota
	upsertAccepted
	upsertIgnored
	upsertConflicting
)

func NewRelaySet(bootstrapRelayURLs []string) *RelaySet {
	set := &RelaySet{
		relays:          make(map[string]relayState),
		keyIndex:        make(map[string]keyIndexEntry),
		incompatible:    make(map[string]types.IncompatibleRelayEntry),
		releaseVersions: make(map[string]relayReleaseObservation),
	}
	for _, relayURL := range bootstrapRelayURLs {
		state := newRelayState(relayURL)
		state.Bootstrap = true
		set.relays[relayURL] = state
	}
	return set
}

func (s *RelaySet) currentRelayStates(now time.Time) []relayState {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.clearExpiredPoolBansLocked(now)
	states := make([]relayState, 0, len(s.relays))
	for _, state := range s.relays {
		states = append(states, state)
	}
	return states
}

func (s *RelaySet) refreshCandidates(now time.Time) []relayState {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	states := s.currentRelayStates(now)
	out := make([]relayState, 0, len(states))
	for _, state := range states {
		if state.Banned {
			continue
		}
		if !state.Bootstrap && (!state.hasObservedDescriptor() || state.nextDiscoveryRefreshAt.After(now)) {
			continue
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
	delete(s.incompatible, relayURL)
	delete(s.releaseVersions, relayURL)
}

func mergeLocalRelayState(record, existing relayState) relayState {
	record.Bootstrap = record.Bootstrap || existing.Bootstrap
	record.Banned = record.Banned || existing.Banned
	record.Dead = record.Dead || existing.Dead
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
	record.RTTTracker.samples = append(record.RTTTracker.samples, existing.RTTTracker.samples...)
	return record
}

func markDiscoveryVerified(state relayState) relayState {
	state.Trust = relayVerified
	state.Dead = false
	state.discoveryFailures = 0
	state.nextDiscoveryRefreshAt = time.Time{}
	state.unhealthySince = time.Time{}
	return state
}

func (s *RelaySet) descriptorRollbackResultLocked(
	record relayState,
	relayURL string,
	address string,
	now time.Time,
) (upsertResult, bool) {
	prev, ok := s.keyIndex[address]
	if !ok {
		return 0, false
	}
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

func (s *RelaySet) upsertDescriptorLockedConflicting(existing, record relayState) bool {
	oldContents, oldErr := canonicalRelayDescriptorBytes(existing.Descriptor)
	newContents, newErr := canonicalRelayDescriptorBytes(record.Descriptor)
	return oldErr != nil || newErr != nil || !bytes.Equal(oldContents, newContents)
}

func (s *RelaySet) trackDescriptorIdentityLocked(address string, issuedAt time.Time) {
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

func (s *RelaySet) upsertDescriptorLocked(record relayState, now time.Time, allowCrossIdentityTakeover bool) upsertResult {
	relayURL := record.Descriptor.APIHTTPSAddr
	if relayURL == "" {
		return upsertRejected
	}
	existing, hasExisting := s.relays[relayURL]
	if hasExisting && existing.Banned {
		return upsertRejected
	}
	if hasExisting && strings.EqualFold(existing.Descriptor.Address, record.Descriptor.Address) && existing.Descriptor.IssuedAt.Equal(record.Descriptor.IssuedAt) {
		if s.upsertDescriptorLockedConflicting(existing, record) {
			return upsertConflicting
		}
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
		s.trackDescriptorIdentityLocked(address, record.Descriptor.IssuedAt)
	}
	s.enforceIdentityCapLocked(address)
	return upsertAccepted
}

func (s *RelaySet) selectRelays(routeState routeState) []string {
	return selectPriority(s.currentRelayStates(time.Now().UTC()), routeState)
}

func filterCandidatePool(states []relayState, routeState routeState, now time.Time) []relayState {
	pool := make([]relayState, 0, len(states))
	for _, state := range states {
		relayURL := state.Descriptor.APIHTTPSAddr
		if state.Trust != relayVerified && (!state.Bootstrap || state.hasObservedDescriptor()) {
			continue
		}
		if slices.Contains(routeState.ExplicitRelayURLs, relayURL) {
			continue
		}
		if state.Banned || state.Dead {
			continue
		}
		if state.hasObservedDescriptor() && (!state.Descriptor.ExpiresAt.After(now) || !state.supportsRequiredTransports(routeState, now)) {
			continue
		}
		if !state.suppressActiveUntil.IsZero() && state.suppressActiveUntil.After(now) {
			continue
		}
		pool = append(pool, state)
	}
	return pool
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

func addDescriptorsRelaySet(seen map[string]struct{}, out []types.RelayDescriptor, desc types.RelayDescriptor, now time.Time) []types.RelayDescriptor {
	relayURL := desc.APIHTTPSAddr
	if relayURL == "" {
		return out
	}
	if _, ok := seen[relayURL]; ok {
		return out
	}
	if !desc.ExpiresAt.After(now) {
		return out
	}
	seen[relayURL] = struct{}{}
	return append(out, desc)
}

func (s *RelaySet) Descriptors(self types.RelayDescriptor) []types.RelayDescriptor {
	now := time.Now().UTC()
	out := make([]types.RelayDescriptor, 0, 1)
	seen := make(map[string]struct{})

	if self.APIHTTPSAddr != "" && self.ExpiresAt.After(now) {
		out = addDescriptorsRelaySet(seen, out, self, now)
	}
	for _, state := range s.currentRelayStates(now) {
		if state.Banned || state.Dead || !state.hasObservedDescriptor() || state.Trust != relayVerified {
			continue
		}
		out = addDescriptorsRelaySet(seen, out, state.Descriptor, now)
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
	delete(s.incompatible, relayURL)
	delete(s.releaseVersions, relayURL)
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

// DeactivateRelayURL drops a relay out of active selection while keeping its
// discovered descriptor as a candidate.
func (s *RelaySet) DeactivateRelayURL(relayURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok {
		return
	}
	state.suppressActiveUntil = time.Now().Add(defaultDirectRecoveryBackoff)
	s.relays[relayURL] = state
}

// EnsureRelayURL persists a candidate state for relayURL when none exists,
// leaving existing states untouched.
func (s *RelaySet) EnsureRelayURL(relayURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.relays[relayURL]; ok {
		return
	}
	s.relays[relayURL] = newRelayState(relayURL)
}
