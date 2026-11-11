package discovery

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

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

func (s *RelaySet) collectDiscoveredRelaysLocked(resp types.DiscoveryResponse, targetURL string, now time.Time) (map[string]relayState, []string, bool) {
	discoveredByURL := make(map[string]relayState, len(resp.Relays))
	discoveredOrder := make([]string, 0, len(resp.Relays)+1)
	targetFound := false
	for _, descriptor := range resp.Relays {
		relayState, relayURL, ok := s.discoveryRelayStateLocked(descriptor, now, targetURL)
		if !ok {
			continue
		}
		if targetURL != "" && relayURL == targetURL {
			targetFound = true
		}
		if _, ok := discoveredByURL[relayURL]; !ok {
			discoveredOrder = append(discoveredOrder, relayURL)
		}
		discoveredByURL[relayURL] = relayState
	}
	return discoveredByURL, discoveredOrder, targetFound
}

func (s *RelaySet) mergeTargetRelayLocked(relayURL string, record relayState, now time.Time) (bool, bool) {
	existingAtURL, hasExistingAtURL := s.relays[relayURL]
	record = mergeLocalRelayState(record, existingAtURL)
	record = markDiscoveryVerified(record)
	if upsert := s.upsertDescriptorLocked(record, now, true); upsert != upsertAccepted {
		if upsert == upsertConflicting {
			return false, true
		}
		if hasExistingAtURL {
			if existingAtURL.discoveryFailures != 0 || !existingAtURL.nextDiscoveryRefreshAt.IsZero() || !existingAtURL.unhealthySince.IsZero() {
				existingAtURL = markDiscoveryVerified(existingAtURL)
				s.relays[relayURL] = existingAtURL
				return true, false
			}
		}
		return false, false
	}
	if !hasExistingAtURL || !reflect.DeepEqual(existingAtURL, record) {
		return true, false
	}
	return false, false
}

func (s *RelaySet) mergeGossipRelayLocked(relayURL string, record relayState, now time.Time) (bool, bool) {
	existingAtURL, hasExistingAtURL := s.relays[relayURL]
	record = mergeLocalRelayState(record, existingAtURL)
	if upsert := s.upsertDescriptorLocked(record, now, false); upsert != upsertAccepted {
		return false, false
	}
	if !hasExistingAtURL || !reflect.DeepEqual(existingAtURL, record) {
		return true, false
	}
	return false, false
}

func (s *RelaySet) recordTargetObservationsLocked(targetURL string, resp types.DiscoveryResponse, now time.Time) {
	if targetURL == "" {
		return
	}
	s.recordReleaseObservationLocked(targetURL, resp.ReleaseVersion, now)
	if resp.ProtocolVersion != types.DiscoveryVersion {
		s.recordIncompatibleRelayLocked(targetURL, resp.ProtocolVersion, now)
	}
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

	discoveredByURL, discoveredOrder, targetFound := s.collectDiscoveredRelaysLocked(resp, targetURL, now)
	missingTarget := authoritative && !targetFound
	conflictingTarget := false

	s.recordTargetObservationsLocked(targetURL, resp, now)

	for _, relayURL := range discoveredOrder {
		if !protocolMismatch && !missingTarget && authoritative && relayURL == targetURL {
			changed, conflicting := s.mergeTargetRelayLocked(relayURL, discoveredByURL[relayURL], now)
			relaySetChanged = relaySetChanged || changed
			conflictingTarget = conflictingTarget || conflicting
			continue
		}
		changed, conflicting := s.mergeGossipRelayLocked(relayURL, discoveredByURL[relayURL], now)
		relaySetChanged = relaySetChanged || changed
		conflictingTarget = conflictingTarget || conflicting
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
