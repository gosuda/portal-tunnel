package agent

import (
	"testing"

	"github.com/gosuda/portal-tunnel/v2/sdk"
)

func TestAgentRelayStatusAdvertisesAliasOnlyWhileReady(t *testing.T) {
	const publicURL = "https://app-0123456789012345678901234567890123456789.relay.example/"
	const aliasURL = "https://app.relay.example/"
	for _, test := range []struct {
		name       string
		state      sdk.RelayState
		deselected bool
		aliasURL   string
		wantAlias  string
	}{
		{name: "ready", state: sdk.RelayReady, aliasURL: aliasURL, wantAlias: aliasURL},
		{name: "canonical fallback", state: sdk.RelayReady},
		{name: "reconnecting", state: sdk.RelayConnecting, aliasURL: aliasURL},
		{name: "failed", state: sdk.RelayFailed, aliasURL: aliasURL},
		{name: "deselected", state: sdk.RelayReady, deselected: true, aliasURL: aliasURL},
	} {
		t.Run(test.name, func(t *testing.T) {
			statuses := agentRelayStatuses([]sdk.RelayStatus{{
				PublicURL:  publicURL,
				AliasURL:   test.aliasURL,
				State:      test.state,
				Deselected: test.deselected,
			}})
			if statuses[0].AliasURL != test.wantAlias || statuses[0].PublicURL != publicURL {
				t.Fatalf("URLs = (%q, %q), want (%q, %q)", statuses[0].AliasURL, statuses[0].PublicURL, test.wantAlias, publicURL)
			}
		})
	}
}

func TestStoppedTunnelSnapshotDoesNotAdvertiseCachedAlias(t *testing.T) {
	tunnel := &managedTunnel{relays: []AgentRelayStatus{{
		PublicURL: "https://identity.relay.example/",
		AliasURL:  "https://app.relay.example/",
	}}}
	status := tunnel.Snapshot()
	if status.Relays[0].AliasURL != "" {
		t.Fatalf("stopped tunnel advertises alias %q", status.Relays[0].AliasURL)
	}
}
