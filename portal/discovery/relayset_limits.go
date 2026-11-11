package discovery

import (
	"sort"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

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

type enforceCapLockedAge struct {
	url       string
	protected bool
	seenAt    time.Time
}

func (s *RelaySet) rankEvictionCandidatesLocked() []enforceCapLockedAge {
	candidates := make([]enforceCapLockedAge, 0, len(s.relays))
	for url, state := range s.relays {
		if state.Bootstrap || state.Banned {
			continue
		}
		candidates = append(candidates, enforceCapLockedAge{
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
	return candidates
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
	for _, c := range s.rankEvictionCandidatesLocked() {
		if len(s.relays) <= MaxAnnouncedRelays {
			return
		}
		delete(s.relays, c.url)
	}
}

func (s *RelaySet) applyDiscoveryBackoffLocked(relayURL string, state relayState, now time.Time, recoveryFailures int) (bool, string, int) {
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
	return s.applyDiscoveryBackoffLocked(relayURL, state, now, recoveryFailures)
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
