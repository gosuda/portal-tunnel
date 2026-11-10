package discovery

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
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
		oldContents, oldErr := canonicalRelayDescriptorBytes(existing.Descriptor)
		newContents, newErr := canonicalRelayDescriptorBytes(record.Descriptor)
		if oldErr != nil || newErr != nil || !bytes.Equal(oldContents, newContents) {
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
		if state.Banned || state.Dead || !state.hasObservedDescriptor() || state.Trust != relayVerified {
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

func (s *RelaySet) discoveryRelayStateLocked(
	descriptor types.RelayDescriptor,
	now time.Time,
	targetURL string,
) (relayState, string, bool) {
	verified, err := verifyFreshRelayDescriptor(descriptor, now)
	if err != nil {
		return relayState{}, "", false
	}
	relayURL := verified.APIHTTPSAddr
	if err := requirePublicRelayURL(relayURL); err != nil {
		if relayURL != targetURL || !s.relays[relayURL].Bootstrap {
			return relayState{}, "", false
		}
	}
	if existing, ok := s.relays[relayURL]; ok && existing.Banned {
		return relayState{}, "", false
	}
	return relayState{Descriptor: verified, LastSeenAt: now}, relayURL, true
}

func (s *RelaySet) ApplyRelayDiscoveryResponse(targetURL string, resp types.DiscoveryResponse, now time.Time) (relaySetChanged bool, err error) {
	if len(resp.Relays) > MaxAnnouncedRelays+1 || len(resp.IncompatibleRelays) > MaxAnnouncedRelays || len(resp.RelayReleaseVersions) > MaxAnnouncedRelays {
		return false, fmt.Errorf("discovery response exceeds collection limits (relays: %d, metadata: %d)", MaxAnnouncedRelays+1, MaxAnnouncedRelays)
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	protocolMismatch := resp.ProtocolVersion != types.DiscoveryVersion
	authoritative := targetURL != ""

	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearExpiredPoolBansLocked(now)

	discoveredByURL := make(map[string]relayState, len(resp.Relays))
	discoveredOrder := make([]string, 0, len(resp.Relays)+1)
	targetFound := false
	for _, descriptor := range resp.Relays {
		relayState, relayURL, ok := s.discoveryRelayStateLocked(descriptor, now, targetURL)
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
	conflictingTarget := false

	if authoritative {
		s.recordReleaseObservationLocked(targetURL, resp.ReleaseVersion, now)
		if protocolMismatch {
			s.recordIncompatibleRelayLocked(targetURL, resp.ProtocolVersion, now)
		}
	}

	for _, relayURL := range discoveredOrder {
		record := discoveredByURL[relayURL]
		existingAtURL, hasExistingAtURL := s.relays[relayURL]
		record = mergeLocalRelayState(record, existingAtURL)

		isAuthoritativeTarget := !protocolMismatch && !missingTarget && authoritative && relayURL == targetURL
		if isAuthoritativeTarget {
			record = markDiscoveryVerified(record)
		}

		if upsert := s.upsertDescriptorLocked(record, now, isAuthoritativeTarget); upsert != upsertAccepted {
			if upsert == upsertConflicting {
				conflictingTarget = conflictingTarget || isAuthoritativeTarget
				continue
			}
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
	if protocolMismatch && authoritative {
		return relaySetChanged, fmt.Errorf("%w: relay=%q client=%q", ErrProtocolMismatch, resp.ProtocolVersion, types.DiscoveryVersion)
	}
	if missingTarget {
		return relaySetChanged, errTargetRelayDescriptorMissingRelays
	}
	if conflictingTarget {
		return relaySetChanged, errTargetRelayDescriptorConflictsRetainedSigned
	}
	if authoritative {
		delete(s.incompatible, targetURL)
	}
	return relaySetChanged, nil
}

func (s *RelaySet) recordIncompatibleRelayLocked(relayURL, protocolVersion string, now time.Time) {
	if relayURL == "" {
		return
	}
	if state, ok := s.relays[relayURL]; ok && state.Banned {
		delete(s.incompatible, relayURL)
		return
	}
	s.pruneIncompatibleLocked(now)
	if len(protocolVersion) > types.MaxDiscoveryVersionBytes {
		protocolVersion = ""
	}
	s.incompatible[relayURL] = types.IncompatibleRelayEntry{
		URL:             relayURL,
		ProtocolVersion: protocolVersion,
		LastSeenAt:      now,
	}
	if len(s.incompatible) > MaxAnnouncedRelays {
		var oldestURL string
		var oldestAt time.Time
		for url, observation := range s.incompatible {
			if olderObservation(url, observation.LastSeenAt, oldestURL, oldestAt) {
				oldestURL, oldestAt = url, observation.LastSeenAt
			}
		}
		delete(s.incompatible, oldestURL)
	}
}

func olderObservation(url string, observedAt time.Time, oldestURL string, oldestAt time.Time) bool {
	if oldestURL == "" {
		return true
	}
	if observedAt.Before(oldestAt) {
		return true
	}
	return observedAt.Equal(oldestAt) && url < oldestURL
}

func (s *RelaySet) pruneIncompatibleLocked(now time.Time) {
	for relayURL, entry := range s.incompatible {
		if now.Sub(entry.LastSeenAt) > AnnounceMaxValidity {
			delete(s.incompatible, relayURL)
		}
	}
}

func (s *RelaySet) pruneReleaseVersionsLocked(now time.Time) {
	for relayURL, observation := range s.releaseVersions {
		if now.Sub(observation.observedAt) > AnnounceMaxValidity {
			delete(s.releaseVersions, relayURL)
		}
	}
}

func (s *RelaySet) recordReleaseObservationLocked(relayURL, releaseVersion string, now time.Time) {
	if relayURL == "" {
		return
	}
	s.pruneReleaseVersionsLocked(now)
	releaseVersion = strings.TrimSpace(releaseVersion)
	if releaseVersion == "" || len(releaseVersion) > types.MaxDiscoveryVersionBytes {
		delete(s.releaseVersions, relayURL)
		return
	}
	s.releaseVersions[relayURL] = relayReleaseObservation{
		releaseVersion: releaseVersion,
		observedAt:     now,
	}
	if len(s.releaseVersions) > MaxAnnouncedRelays {
		var oldestURL string
		var oldestAt time.Time
		for url, observation := range s.releaseVersions {
			if olderObservation(url, observation.observedAt, oldestURL, oldestAt) {
				oldestURL, oldestAt = url, observation.observedAt
			}
		}
		delete(s.releaseVersions, oldestURL)
	}
}

// KnownIncompatibleRelays returns directly observed relays whose discovery
// protocol version is incompatible. Entries expire without a fresh
// observation and are suppressed while the relay is locally banned. They
// are informational only, never part of the routable set.
func (s *RelaySet) KnownIncompatibleRelays() []types.IncompatibleRelayEntry {
	return s.knownIncompatibleRelaysAt(time.Now().UTC())
}

func (s *RelaySet) knownIncompatibleRelaysAt(now time.Time) []types.IncompatibleRelayEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]types.IncompatibleRelayEntry, 0, len(s.incompatible))
	for relayURL, entry := range s.incompatible {
		if now.Sub(entry.LastSeenAt) > AnnounceMaxValidity {
			continue
		}
		if state, ok := s.relays[relayURL]; ok && state.Banned {
			continue
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// KnownRelayReleaseVersions returns peer release versions observed directly
// from relay /discovery responses. Entries expire without a fresh direct
// poll and are dropped outright by a local ban. They never participate in
// routing, trust, or compatibility decisions.
func (s *RelaySet) KnownRelayReleaseVersions() map[string]string {
	return s.knownRelayReleaseVersionsAt(time.Now().UTC())
}

func (s *RelaySet) knownRelayReleaseVersionsAt(now time.Time) map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]string, len(s.releaseVersions))
	for relayURL, observation := range s.releaseVersions {
		if now.Sub(observation.observedAt) > AnnounceMaxValidity {
			continue
		}
		out[relayURL] = observation.releaseVersion
	}
	return out
}

func (s *RelaySet) RecordDiscoveryRTT(relayURL string, rtt time.Duration, measuredAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok {
		return
	}

	state.RTTTracker.add(rtt)
	state.DiscoveryRTT = rtt
	state.DiscoveryRTTAt = measuredAt
	s.relays[relayURL] = state
}

// InsertCandidate ingests one descriptor from an announce or gossiped
// discovery response as a relayCandidate. It verifies the signature and
// freshness, merges local state, and applies the rollback, takeover, and
// identity-cap guards. Candidates stay out of Descriptors and route
// planning until a direct authoritative probe promotes them to verified.
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
	if err := requirePublicRelayURL(normalized.APIHTTPSAddr); err != nil {
		return err
	}

	record := relayState{
		Descriptor: normalized,
		LastSeenAt: now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearExpiredPoolBansLocked(now)

	relayURL := record.Descriptor.APIHTTPSAddr
	if existing, ok := s.relays[relayURL]; ok {
		if existing.Banned {
			return errRelayBannedFromPool
		}
		record = mergeLocalRelayState(record, existing)
	}

	switch s.upsertDescriptorLocked(record, now, false) {
	case upsertAccepted:
		s.enforceCapLocked()
		return nil
	case upsertIgnored:
		return nil
	case upsertRejected:
		return errAnnouncedDescriptorRejectedRollbackOrTakeover
	case upsertConflicting:
		return errAnnouncedDescriptorConflictsRetainedSignedContents
	}
	return nil
}

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
		if state.Bootstrap || state.Banned || state.Trust == relayVerified {
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
	verified, err := VerifyRelayDescriptor(desc)
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
		return errRelayDescriptorMissingIssuedAt
	}
	if !desc.ExpiresAt.After(now) {
		return errRelayDescriptorAlreadyExpired
	}
	if desc.IssuedAt.After(now.Add(AnnounceClockSkewTolerance)) {
		return errRelayDescriptorTooFarFuture
	}
	if desc.ExpiresAt.Sub(desc.IssuedAt) > AnnounceMaxValidity {
		return errRelayDescriptorValidityWindowExceedsMaximum
	}
	return nil
}

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
			protected: state.Trust == relayVerified,
			seenAt:    state.LastSeenAt,
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
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

// IsSuppressed reports whether relayURL is excluded from active selection
// by a prior active-listener failure backoff.
func (s *RelaySet) IsSuppressed(relayURL string, now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.relays[relayURL]
	if !ok {
		return false
	}
	return !state.suppressActiveUntil.IsZero() && state.suppressActiveUntil.After(now)
}
