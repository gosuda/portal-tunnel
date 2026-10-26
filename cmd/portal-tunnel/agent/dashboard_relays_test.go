package agent

import (
	"slices"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestRelayDashboardMode(t *testing.T) {
	tunnel := AgentTunnelStatus{ID: "web"}
	relayURL := "https://relay.example.com"
	tests := []struct {
		name     string
		relay    AgentRelayStatus
		attempts map[relayAttemptKey]bool
		want     string
	}{
		{name: "idle", relay: AgentRelayStatus{RelayURL: relayURL}, want: "-"},
		{name: "connected", relay: AgentRelayStatus{RelayURL: relayURL, PublicURL: "https://web.relay.example.com"}, want: "direct"},
		{name: "connecting", relay: AgentRelayStatus{RelayURL: relayURL, Connecting: true}, want: "connecting..."},
		{
			name:     "connect requested and not reported yet",
			relay:    AgentRelayStatus{RelayURL: relayURL},
			attempts: map[relayAttemptKey]bool{{tunnelID: "web", relayURL: relayURL}: false},
			want:     "connecting...",
		},
		{
			name:     "connect attempt ended without a connection",
			relay:    AgentRelayStatus{RelayURL: relayURL},
			attempts: map[relayAttemptKey]bool{{tunnelID: "web", relayURL: relayURL}: true},
			want:     "failed",
		},
		{
			name:     "connected wins over a stale failed attempt",
			relay:    AgentRelayStatus{RelayURL: relayURL, PublicURL: "https://web.relay.example.com"},
			attempts: map[relayAttemptKey]bool{{tunnelID: "web", relayURL: relayURL}: true},
			want:     "direct",
		},
		{
			name:     "attempt for another relay does not apply",
			relay:    AgentRelayStatus{RelayURL: relayURL},
			attempts: map[relayAttemptKey]bool{{tunnelID: "web", relayURL: "https://other.example.com"}: true},
			want:     "-",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := agentDashboardModel{relayAttempts: tt.attempts}
			if got := model.relayDashboardMode(tunnel, tt.relay); got != tt.want {
				t.Fatalf("mode = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRelayDashboardFeaturesAndVersion(t *testing.T) {
	features := []struct {
		relay AgentRelayStatus
		want  string
	}{
		{relay: AgentRelayStatus{SupportsUDP: true, SupportsTCP: true}, want: "udp,tcp"},
		{relay: AgentRelayStatus{SupportsTCP: true}, want: "tcp"},
		{relay: AgentRelayStatus{SupportsUDP: true}, want: "udp"},
		{relay: AgentRelayStatus{}, want: "-"},
	}
	for _, tt := range features {
		if got := relayDashboardFeatures(tt.relay); got != tt.want {
			t.Fatalf("features(%+v) = %q, want %q", tt.relay, got, tt.want)
		}
	}

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
		{width: 120, want: []string{"direct", "v2.4.1", "udp,tcp", publicURL}},
	}
	for _, tt := range tests {
		row := agentDashboardRelayRow(tt.width, "direct", "v2.4.1", "udp,tcp", publicURL)
		if got := lipgloss.Width(row); got > tt.width {
			t.Fatalf("width %d: row %q is %d cells wide", tt.width, row, got)
		}
		if tt.want != nil && !slices.Equal(strings.Fields(row), tt.want) {
			t.Fatalf("width %d: columns = %q, want %q", tt.width, strings.Fields(row), tt.want)
		}
	}

	for width := 1; width <= 140; width++ {
		row := agentDashboardRelayRow(width, "connecting...", "v2.4.1", "udp,tcp", publicURL)
		if got := lipgloss.Width(row); got > width {
			t.Fatalf("width %d: row %q is %d cells wide", width, row, got)
		}
	}
}
