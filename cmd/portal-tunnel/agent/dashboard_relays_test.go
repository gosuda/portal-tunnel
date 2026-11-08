package agent

import (
	"slices"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/gosuda/portal-tunnel/v2/sdk"
)

func TestRelayDashboardMode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		relay AgentRelayStatus
		want  string
	}{
		{name: "unknown", want: "-"},
		{name: "ready", relay: AgentRelayStatus{State: sdk.RelayReady, PublicURL: "https://app.example"}, want: "direct"},
		{name: "connecting", relay: AgentRelayStatus{State: sdk.RelayConnecting}, want: "connecting..."},
		{name: "waiting", relay: AgentRelayStatus{State: sdk.RelayConnecting, Approval: sdk.RelayApprovalPending}, want: "waiting"},
		{name: "refused", relay: AgentRelayStatus{State: sdk.RelayConnecting, Approval: sdk.RelayApprovalRefused}, want: "refused"},
		{name: "failed with retained URL", relay: AgentRelayStatus{State: sdk.RelayFailed, PublicURL: "https://app.example"}, want: "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := relayDashboardMode(tc.relay); got != tc.want {
				t.Fatalf("mode = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDashboardDisconnectFollowsMembershipRatherThanReadiness(t *testing.T) {
	for _, tunnelState := range []string{"running", "stopped", "retrying"} {
		for _, relayState := range []sdk.RelayState{sdk.RelayReady, sdk.RelayConnecting, sdk.RelayFailed} {
			t.Run(tunnelState+"/"+string(relayState), func(t *testing.T) {
				theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
				model := newAgentDashboardModel("config.toml", "state", theme)
				model.status = AgentStatusResponse{Tunnels: []AgentTunnelStatus{{
					ID: "web", State: tunnelState,
					Relays: []AgentRelayStatus{{RelayURL: "https://relay.example", State: relayState}},
				}}}
				_, command := model.disconnectSelectedRelay()
				want := tunnelState == "running"
				if (command != nil) != want {
					t.Fatalf("disconnect action available=%v, want %v", command != nil, want)
				}
				view := model.renderRelaysSection(100, 10)
				clickable := false
				for _, region := range view.regions {
					if region.action == agentDashboardActionDisconnectRelay {
						clickable = true
					}
				}
				if clickable != want {
					t.Fatalf("disconnect button available=%v, want %v", clickable, want)
				}
			})
		}
	}
}

func TestRelayDashboardVersion(t *testing.T) {
	if got := relayDashboardVersion(AgentRelayStatus{Version: " v2.4.1 "}); got != "v2.4.1" {
		t.Fatalf("version = %q, want the trimmed version", got)
	}
	if got := relayDashboardVersion(AgentRelayStatus{}); got != "-" {
		t.Fatalf("version = %q, want a dash when unknown", got)
	}
}

func TestRelayDashboardURL(t *testing.T) {
	tests := []struct {
		name  string
		relay AgentRelayStatus
		want  string
	}{
		{
			name:  "public URL is shown without credentials, query and fragment",
			relay: AgentRelayStatus{RelayURL: "https://relay.example.com", PublicURL: "https://user:secret@web.relay.example.com/app?token=1#frag"},
			want:  "https://web.relay.example.com/app",
		},
		{
			name:  "short URL is shown instead of the identity-bound URL",
			relay: AgentRelayStatus{RelayURL: "https://relay.example.com", PublicURL: "https://web-0x1234.relay.example.com/", AliasURL: "https://web.relay.example.com/"},
			want:  "https://web.relay.example.com/",
		},
		{
			name:  "relay host is shown while not connected",
			relay: AgentRelayStatus{RelayURL: "https://relay.example.com:8443/api/v1"},
			want:  "relay.example.com",
		},
		{name: "nothing known", relay: AgentRelayStatus{}, want: "-"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := relayDashboardURL(tt.relay)
			if got != tt.want {
				t.Fatalf("url = %q, want %q", got, tt.want)
			}
			if strings.Contains(got, "secret") {
				t.Fatalf("url %q leaks credentials", got)
			}
		})
	}
}

func TestAgentDashboardURLCell(t *testing.T) {
	const publicURL = "https://web.relay.example.com/app"
	tests := []struct {
		name  string
		value string
		width int
		want  string
	}{
		{name: "fits", value: publicURL, width: 40, want: publicURL},
		{name: "long URL becomes an open hint", value: publicURL, width: 30, want: "open web.relay.example.com"},
		{name: "hint is truncated when still too long", value: publicURL, width: 12, want: "open web.re~"},
		{name: "not a URL is truncated", value: "relay-name-without-scheme", width: 10, want: "relay-nam~"},
		{name: "empty", value: " ", width: 10, want: ""},
		{name: "no room", value: publicURL, width: 0, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := agentDashboardURLCell(tt.value, tt.width); got != tt.want {
				t.Fatalf("cell = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAgentDashboardRelayRowFitsAndDropsColumnsWhenNarrow(t *testing.T) {
	const publicURL = "https://web.relay.example.com/app"
	tests := []struct {
		width int
		want  []string
	}{
		{width: 27, want: nil},
		{width: 46, want: []string{"direct", "open", "web.relay.example.com"}},
		{width: 55, want: []string{"direct", publicURL}},
		{width: 120, want: []string{"direct", "v2.4.1", publicURL}},
	}
	for _, tt := range tests {
		row := agentDashboardRelayRow(tt.width, "direct", "v2.4.1", publicURL)
		if got := lipgloss.Width(row); got > tt.width {
			t.Fatalf("width %d: row %q is %d cells wide", tt.width, row, got)
		}
		if tt.want != nil && !slices.Equal(strings.Fields(row), tt.want) {
			t.Fatalf("width %d: columns = %q, want %q", tt.width, strings.Fields(row), tt.want)
		}
	}

	for width := 1; width <= 140; width++ {
		row := agentDashboardRelayRow(width, "connecting...", "v2.4.1", publicURL)
		if got := lipgloss.Width(row); got > width {
			t.Fatalf("width %d: row %q is %d cells wide", width, row, got)
		}
	}
}
