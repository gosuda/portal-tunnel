package discovery

import (
	"context"
	"testing"
	"time"
)

// TestMOLSSelectPrioritySkipsAutoRelayInBackoff verifies that a relay whose
// active-suppression window has not expired is excluded from priority selection.
// This test sets the unexported suppressActiveUntil field directly and therefore
// must live in package discovery rather than in the mols package.
func TestMOLSSelectPrioritySkipsAutoRelayInBackoff(t *testing.T) {
	backingOff := confirmedPolicyRelayState(t, "https://relay-backoff.example")
	backingOff.suppressActiveUntil = time.Now().UTC().Add(time.Minute)

	selected, _ := stubSelector{}.SelectPriority(context.Background(), []RelayState{backingOff}, ClientState{})
	if len(selected) != 0 {
		t.Fatalf("SelectPriority(backing off auto) = %v, want empty", selected)
	}
}

// TestMOLSSelectPriorityKeepsDiscoveryBackoffRelay verifies that a relay whose
// discovery retry timer is set (but not its active-suppression timer) is still
// eligible for active use. This test sets the unexported nextDiscoveryRefreshAt
// field directly and therefore must live in package discovery.
func TestMOLSSelectPriorityKeepsDiscoveryBackoffRelay(t *testing.T) {
	relayURL := "https://relay-discovery-backoff.example"
	backingOff := confirmedPolicyRelayState(t, relayURL)
	backingOff.nextDiscoveryRefreshAt = time.Now().UTC().Add(time.Minute)

	selected, _ := stubSelector{}.SelectPriority(context.Background(), []RelayState{backingOff}, ClientState{})
	if len(selected) != 1 || selected[0] != relayURL {
		t.Fatalf("SelectPriority(discovery backoff) = %v, want [%q]", selected, relayURL)
	}
}
