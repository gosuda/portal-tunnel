package discovery

import (
	"errors"
	"fmt"
	"reflect"
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
	policy   RelayPolicy
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
		policy:   DefaultRelayPolicy{},
	}
	set.SetBootstrapRelayURLs(bootstrapRelayURLs)
	return set
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

func (s *RelaySet) SetRelayPolicy(policy RelayPolicy) {
	if policy == nil {
		policy = DefaultRelayPolicy{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = policy
}

func (s *RelaySet) SetBootstrapRelayURLs(inputs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keep := make(map[string]struct{}, len(inputs))
	for _, relayURL := range inputs {
		keep[relayURL] = struct{}{}
	}

	for key, state := range s.relays {
		_, bootstrap := keep[key]
		state.Bootstrap = bootstrap
		if !state.Bootstrap && !state.hasObservedDescriptor() && !state.Banned && state.consecutiveFailures == 0 {
			delete(s.relays, key)
			continue
		}

		s.relays[key] = state
	}

	for _, relayURL := range inputs {
		if _, ok := s.relays[relayURL]; ok {
			continue
		}

		state := newRelayState(relayURL)
		state.Bootstrap = true
		s.relays[relayURL] = state
	}
}

func (s *RelaySet) AggregateRelays() []RelayState {
	s.mu.RLock()
	states := make([]RelayState, 0, len(s.relays))
	for _, state := range s.relays {
		states = append(states, state)
	}
	policy := s.policy
	s.mu.RUnlock()

	return policy.SelectAggregate(states)
}

func (s *RelaySet) ConfirmedRelays() []RelayState {
	s.mu.RLock()
	states := make([]RelayState, 0, len(s.relays))
	for _, state := range s.relays {
		states = append(states, state)
	}
	policy := s.policy
	s.mu.RUnlock()

	return policy.SelectConfirmed(states)
}

func (s *RelaySet) PriorityRelays(clientState ClientState) []string {
	s.mu.RLock()
	states := make([]RelayState, 0, len(s.relays))
	for _, state := range s.relays {
		states = append(states, state)
	}
	policy := s.policy
	s.mu.RUnlock()

	return policy.SelectPriority(states, clientState)
}

func (s *RelaySet) OverlayPeerStates() []RelayState {
	now := time.Now().UTC()
	s.mu.RLock()
	out := make([]RelayState, 0, len(s.relays))
	for _, state := range s.relays {
		if state.Banned || !state.hasObservedDescriptor() || !state.Descriptor.ExpiresAt.After(now) || !state.Descriptor.SupportsOverlayPeer {
			continue
		}
		if state.Descriptor.WireGuardPublicKey == "" ||
			state.Descriptor.WireGuardEndpoint == "" ||
			state.Descriptor.OverlayIPv4 == "" {
			continue
		}
		out = append(out, state)
	}
	s.mu.RUnlock()
	if len(out) == 0 {
		return nil
	}
	return out
}

// BootstrapRelayURLs returns configured bootstrap discovery endpoints that
// can receive this relay's periodic self-announce.
func (s *RelaySet) BootstrapRelayURLs() []string {
	s.mu.RLock()
	out := make([]string, 0, len(s.relays))
	for _, state := range s.relays {
		if state.Banned || !state.Bootstrap {
			continue
		}
		if state.hasObservedDescriptor() && !state.Descriptor.Discovery {
			continue
		}
		relayURL := strings.TrimSpace(state.Descriptor.APIHTTPSAddr)
		if relayURL == "" {
			continue
		}
		out = append(out, relayURL)
	}
	s.mu.RUnlock()
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

	if self.APIHTTPSAddr != "" && self.Discovery && self.ExpiresAt.After(now) {
		add(self)
	}
	s.mu.RLock()
	for _, state := range s.relays {
		if state.Banned || !state.hasObservedDescriptor() || !state.Descriptor.Discovery {
			continue
		}
		add(state.Descriptor)
	}
	s.mu.RUnlock()
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
	state = s.policy.OnBanned(state)
	s.relays[relayURL] = state
}

func (s *RelaySet) ConfirmRelayURL(relayURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok {
		state = newRelayState(relayURL)
	}
	state = s.policy.OnConfirmed(state)
	s.relays[relayURL] = state
}

func (s *RelaySet) UnconfirmRelayURL(relayURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok {
		return
	}
	state = s.policy.OnUnconfirmed(state)
	s.relays[relayURL] = state
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
		record.Bootstrap = record.Bootstrap || existingAtURL.Bootstrap
		record.Confirmed = record.Confirmed || existingAtURL.Confirmed
		record.Banned = record.Banned || existingAtURL.Banned
		if record.consecutiveFailures < existingAtURL.consecutiveFailures {
			record.consecutiveFailures = existingAtURL.consecutiveFailures
		}
		record.nextDirectRefreshAt = existingAtURL.nextDirectRefreshAt
		if record.DiscoveryRTTAt.IsZero() || (!existingAtURL.DiscoveryRTTAt.IsZero() && existingAtURL.DiscoveryRTTAt.After(record.DiscoveryRTTAt)) {
			record.DiscoveryRTT = existingAtURL.DiscoveryRTT
			record.DiscoveryRTTAt = existingAtURL.DiscoveryRTTAt
		}

		isAuthoritativeTarget := !protocolMismatch && !missingTarget && authoritative && relayURL == targetURL
		if isAuthoritativeTarget {
			record.consecutiveFailures = 0
			record.nextDirectRefreshAt = time.Time{}
		}

		if upsert := s.upsertDescriptorLocked(record, now, isAuthoritativeTarget); upsert != upsertAccepted {
			// The monotonic-IssuedAt check rejected this descriptor as a
			// rollback, or ignored it because a newer same-identity descriptor
			// for this URL is already present. The cryptographic identity in
			// s.relays is unchanged, but if we successfully reached the
			// authoritative target we should still credit it as alive on its
			// existing URL slot.
			if isAuthoritativeTarget && hasExistingAtURL {
				if existingAtURL.consecutiveFailures != 0 || !existingAtURL.nextDirectRefreshAt.IsZero() {
					existingAtURL.consecutiveFailures = 0
					existingAtURL.nextDirectRefreshAt = time.Time{}
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

	state.DiscoveryRTT = rtt
	state.DiscoveryRTTAt = measuredAt
	s.relays[relayURL] = state
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
//  3. Local merge preserves Bootstrap, Confirmed, Banned, telemetry, and
//     direct-refresh retry state from any pre-existing entry at the same URL.
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

	relayURL := record.Descriptor.APIHTTPSAddr
	if existing, ok := s.relays[relayURL]; ok {
		record.Bootstrap = record.Bootstrap || existing.Bootstrap
		record.Confirmed = record.Confirmed || existing.Confirmed
		record.Banned = record.Banned || existing.Banned
		if record.consecutiveFailures < existing.consecutiveFailures {
			record.consecutiveFailures = existing.consecutiveFailures
		}
		record.nextDirectRefreshAt = existing.nextDirectRefreshAt
		if record.DiscoveryRTTAt.IsZero() || (!existing.DiscoveryRTTAt.IsZero() && existing.DiscoveryRTTAt.After(record.DiscoveryRTTAt)) {
			record.DiscoveryRTT = existing.DiscoveryRTT
			record.DiscoveryRTTAt = existing.DiscoveryRTTAt
		}
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
		if state.Bootstrap {
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
	}
}

func (s *RelaySet) RecordRelayFailure(relayURL string, err error, recoveryFailures int) (backedOff bool, backoffReason string, consecutiveFailures int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.relays[relayURL]
	if !ok {
		return false, "", 0
	}
	state, backedOff, backoffReason = s.policy.OnFailure(state, err, recoveryFailures)
	s.relays[relayURL] = state
	return backedOff, backoffReason, state.consecutiveFailures
}
