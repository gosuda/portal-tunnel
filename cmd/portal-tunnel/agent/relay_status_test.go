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
			}}, nil)
			if statuses[0].AliasURL != test.wantAlias || statuses[0].PublicURL != publicURL {
				t.Fatalf("URLs = (%q, %q), want (%q, %q)", statuses[0].AliasURL, statuses[0].PublicURL, test.wantAlias, publicURL)
			}
		})
	}
}

func TestAgentRelayStatusCarriesApproval(t *testing.T) {
	statuses := agentRelayStatuses([]sdk.RelayStatus{{State: sdk.RelayConnecting, Approval: sdk.RelayApprovalPending}}, nil)
	if statuses[0].Approval != sdk.RelayApprovalPending || statuses[0].State != sdk.RelayConnecting {
		t.Fatalf("status = %+v", statuses[0])
	}
}

func TestStoppedTunnelSnapshotDoesNotAdvertiseRelayEndpoints(t *testing.T) {
	tunnel := &managedTunnel{cfg: testTunnel("web")}
	status := tunnel.Snapshot()
	if status.State != "stopped" || len(status.Relays) != 0 {
		t.Fatalf("stopped tunnel advertises relay endpoints: state=%q relays=%+v", status.State, status.Relays)
	}
}

func TestAgentRelayStatusCarriesFailure(t *testing.T) {
	statuses := agentRelayStatuses([]sdk.RelayStatus{{State: sdk.RelayFailed, Failure: sdk.RelayFailureMITM}}, nil)
	if statuses[0].State != sdk.RelayFailed || statuses[0].Failure != sdk.RelayFailureMITM {
		t.Fatalf("status = %+v", statuses[0])
	}
}

// A configured relay that the running tunnel no longer uses stays in the
// status, so that a front end can connect it again after a disconnect.
func TestAgentRelayStatusKeepsDisconnectedConfiguredRelays(t *testing.T) {
	statuses := agentRelayStatuses(
		[]sdk.RelayStatus{{RelayURL: "https://one.example.com", State: sdk.RelayReady}},
		[]string{"https://one.example.com", "https://two.example.com"},
	)
	if len(statuses) != 2 || statuses[0].State != sdk.RelayReady ||
		statuses[1].RelayURL != "https://two.example.com" || statuses[1].State != RelayDisconnected {
		t.Fatalf("statuses = %+v", statuses)
	}
}
