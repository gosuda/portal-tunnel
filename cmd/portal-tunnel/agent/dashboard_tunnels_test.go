package agent

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
)

func TestTunnelDashboardName(t *testing.T) {
	if got := tunnelDashboardName(AgentTunnelStatus{ID: "web-1", Name: "web"}); got != "web" {
		t.Fatalf("name = %q, want the public name", got)
	}
	if got := tunnelDashboardName(AgentTunnelStatus{ID: "web-1", Name: "  "}); got != "web-1" {
		t.Fatalf("name = %q, want the id when the name is blank", got)
	}
}

func TestTunnelDashboardTarget(t *testing.T) {
	routes := func(amounts ...string) []tunnel.HTTPRoute {
		out := make([]tunnel.HTTPRoute, 0, len(amounts))
		for _, amount := range amounts {
			out = append(out, tunnel.HTTPRoute{Prefix: "/", Upstream: "3000", Amount: amount})
		}
		return out
	}
	tests := []struct {
		name   string
		tunnel AgentTunnelStatus
		want   string
	}{
		{name: "target address", tunnel: AgentTunnelStatus{TargetAddr: " 127.0.0.1:3000 "}, want: "127.0.0.1:3000"},
		{name: "static site wins over the target", tunnel: AgentTunnelStatus{Serve: "./site", TargetAddr: "127.0.0.1:3000"}, want: "./site"},
		{name: "free routes", tunnel: AgentTunnelStatus{HTTPRoutes: routes("", "")}, want: "2 routes"},
		{name: "paid routes", tunnel: AgentTunnelStatus{HTTPRoutes: routes("", "0.01", "0.02")}, want: "3 routes, 2 paid"},
		{name: "nothing to show", tunnel: AgentTunnelStatus{}, want: "-"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tunnelDashboardTarget(tt.tunnel); got != tt.want {
				t.Fatalf("target = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAgentDashboardTunnelRowFitsAndKeepsName(t *testing.T) {
	for width := 3; width <= 140; width++ {
		row := agentDashboardTunnelRow(width, "running", "127.0.0.1:3000", "web")
		if got := lipgloss.Width(row); got > width {
			t.Fatalf("width %d: row %q is %d cells wide", width, row, got)
		}
		if fields := strings.Fields(row); fields[len(fields)-1] != "web" {
			t.Fatalf("width %d: row %q must end with the name", width, row)
		}
	}
}

func TestAgentDashboardTunnelRowTruncatesLongNames(t *testing.T) {
	name := "a-tunnel-name-that-is-much-longer-than-the-name-column-can-hold"
	row := agentDashboardTunnelRow(60, "running", "127.0.0.1:3000", name)
	if lipgloss.Width(row) > 60 {
		t.Fatalf("row %q is %d cells wide", row, lipgloss.Width(row))
	}
	if !strings.HasSuffix(row, "~") {
		t.Fatalf("row %q should end with the truncation marker", row)
	}
}

func TestAgentDashboardTunnelLookTellsStatesApartWithoutColor(t *testing.T) {
	theme, err := newAgentDashboardTheme("amber", agentDashboardTerminal{})
	if err != nil {
		t.Fatal(err)
	}
	leds := make(map[string]string)
	for _, state := range []string{"running", "starting", "error", "stopped"} {
		led, _ := agentDashboardTunnelLook(&theme, state)
		if other, ok := leds[led]; ok {
			t.Fatalf("states %q and %q share the LED %q", other, state, led)
		}
		leds[led] = state
	}
	if led, _ := agentDashboardTunnelLook(&theme, "unknown"); leds[led] != "stopped" {
		t.Fatalf("an unknown state must look idle, got LED %q", led)
	}
}
