package discovery

import (
	"testing"
	"time"
)

// driveUnhealthyPoolBan drives RecordDiscoveryFailure twice across the
// AnnounceMaxValidity unhealthy window so the second call lands in the
// unhealthy pool-ban path. RecordDiscoveryFailure reads time.Now(), so the
// stored unhealthySince is aged directly between the two calls.
func driveUnhealthyPoolBan(t *testing.T, set *RelaySet, relayURL string) (reason string, failureCount int) {
	t.Helper()
	set.RecordDiscoveryFailure(relayURL, 0)
	set.mu.Lock()
	state := set.relays[relayURL]
	state.unhealthySince = time.Now().UTC().Add(-AnnounceMaxValidity - time.Second)
	set.relays[relayURL] = state
	set.mu.Unlock()
	backedOff, reason, failureCount := set.RecordDiscoveryFailure(relayURL, 0)
	if !backedOff {
		t.Fatalf("RecordDiscoveryFailure() did not pool-ban %q", relayURL)
	}
	return reason, failureCount
}

// releaseSuppression ages a stored suppressActiveUntil (a 72h pool-ban TTL or
// an active-failure backoff) into the past so the next mutator's
// clearExpiredPoolBansLocked releases it. For retained entries (bootstrap
// and explicit relays, which the re-entry ratchet anchors on) the release
// keeps the entry and its pool-ban count.
func releaseSuppression(set *RelaySet, relayURL string) {
	set.mu.Lock()
	defer set.mu.Unlock()
	state := set.relays[relayURL]
	state.suppressActiveUntil = time.Now().UTC().Add(-time.Second)
	set.relays[relayURL] = state
}

func storedRelayState(t *testing.T, set *RelaySet, relayURL string) RelayState {
	t.Helper()
	set.mu.RLock()
	defer set.mu.RUnlock()
	return set.relays[relayURL]
}

// A relay that re-enters the pool-ban state after its TTL released flapped:
// the second ban is permanent (the BanRelayURL representation that
// clearExpiredPoolBansLocked skips), not another 72h TTL.
func TestPoolBanReEntryEscalatesToPermanentBan(t *testing.T) {
	relayURL := "https://relay-flap.example"
	set := NewRelaySet([]string{relayURL})

	if reason, _ := driveUnhealthyPoolBan(t, set, relayURL); reason != "unhealthy" {
		t.Fatalf("first pool-ban reason = %q, want %q", reason, "unhealthy")
	}
	state := storedRelayState(t, set, relayURL)
	if !state.Banned || state.suppressActiveUntil.IsZero() {
		t.Fatalf("first pool ban = %+v, want Banned with a TTL suppressActiveUntil", state)
	}
	if state.poolBans != 1 {
		t.Fatalf("poolBans after first ban = %d, want 1", state.poolBans)
	}

	releaseSuppression(set, relayURL)
	if reason, _ := driveUnhealthyPoolBan(t, set, relayURL); reason != "unhealthy" {
		t.Fatalf("re-entry pool-ban reason = %q, want %q", reason, "unhealthy")
	}
	state = storedRelayState(t, set, relayURL)
	if !state.Banned || !state.suppressActiveUntil.IsZero() {
		t.Fatalf("re-entry pool ban = %+v, want Banned with zero suppressActiveUntil (permanent)", state)
	}
	if state.poolBans != 2 {
		t.Fatalf("poolBans after re-entry = %d, want 2", state.poolBans)
	}
}

// Explicit operator trust resets the flap ratchet: after AllowRelayURL the
// next pool ban is a fresh TTL ban again, not an escalation to permanent.
func TestAllowRelayURLResetsPoolBanRatchet(t *testing.T) {
	relayURL := "https://relay-override.example"
	set := NewRelaySet([]string{relayURL})

	driveUnhealthyPoolBan(t, set, relayURL)
	set.AllowRelayURL(relayURL)
	if state := storedRelayState(t, set, relayURL); state.poolBans != 0 || state.activeSuppressions != 0 {
		t.Fatalf("AllowRelayURL() state = %+v, want both ratchet counters reset", state)
	}

	driveUnhealthyPoolBan(t, set, relayURL)
	state := storedRelayState(t, set, relayURL)
	if !state.Banned || state.suppressActiveUntil.IsZero() {
		t.Fatalf("pool ban after operator override = %+v, want Banned with a TTL suppressActiveUntil", state)
	}
	if state.poolBans != 1 {
		t.Fatalf("poolBans after operator override = %d, want 1", state.poolBans)
	}
}

// Active-failure suppression cycles escalate: once the accumulated
// suppression grants reach activeSuppressionPoolBanThreshold, the next grant
// becomes a pool ban instead of another backoff.
func TestActiveFailureEscalatesToPoolBan(t *testing.T) {
	relayURL := "https://relay-churn.example"
	set := NewRelaySet(nil)
	set.EnsureRelayURL(relayURL)

	for cycle := 1; cycle <= activeSuppressionPoolBanThreshold; cycle++ {
		backedOff, reason, failureCount := set.RecordActiveFailure(relayURL, 1)
		if !backedOff {
			t.Fatalf("RecordActiveFailure() cycle %d did not back off", cycle)
		}
		if cycle < activeSuppressionPoolBanThreshold {
			if reason != "active" {
				t.Fatalf("RecordActiveFailure() cycle %d reason = %q, want %q", cycle, reason, "active")
			}
			releaseSuppression(set, relayURL)
			continue
		}
		if reason != "pool_ban" {
			t.Fatalf("RecordActiveFailure() final reason = %q, want %q", reason, "pool_ban")
		}
		if failureCount != activeSuppressionPoolBanThreshold {
			t.Fatalf("RecordActiveFailure() final failure count = %d, want %d", failureCount, activeSuppressionPoolBanThreshold)
		}
	}

	state := storedRelayState(t, set, relayURL)
	if !state.Banned {
		t.Fatalf("state after escalation = %+v, want Banned", state)
	}
	if state.poolBans != 1 {
		t.Fatalf("poolBans after escalation = %d, want 1", state.poolBans)
	}
}

// A fresh direct verification is the healthy-confirmation reset for the
// suppression cycle, but it never forgives the pool-ban ratchet — only
// explicit operator trust does.
func TestMarkDiscoveryVerifiedResetsSuppressionsButNotPoolBans(t *testing.T) {
	state := RelayState{
		Trust:              RelayCandidate,
		discoveryFailures:  2,
		unhealthySince:     time.Now().UTC(),
		activeSuppressions: 2,
		poolBans:           2,
	}
	verified := markDiscoveryVerified(state)
	if verified.activeSuppressions != 0 {
		t.Fatalf("activeSuppressions after verification = %d, want 0", verified.activeSuppressions)
	}
	if verified.poolBans != 2 {
		t.Fatalf("poolBans after verification = %d, want 2 (operator override only)", verified.poolBans)
	}
}
