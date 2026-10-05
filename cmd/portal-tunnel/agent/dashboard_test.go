package agent

import "testing"

func TestAgentDashboardRelayKeyKeepsComponentsStructural(t *testing.T) {
	t.Parallel()

	first := agentDashboardRelayKey("tunnel\x00relay", "url")
	second := agentDashboardRelayKey("tunnel", "relay\x00url")
	if first == second {
		t.Fatal("distinct tunnel and relay components produced the same key")
	}
	if got := agentDashboardRelayKey(" ", "https://relay.example"); got != (relayAttemptKey{}) {
		t.Fatalf("empty tunnel key = %#v, want zero key", got)
	}
}
