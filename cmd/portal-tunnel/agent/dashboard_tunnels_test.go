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

func TestAgentDashboardTunnelRowFitsAndKeepsStateAndName(t *testing.T) {
	for _, width := range []int{1, 10, 27, 28, 40, 55, 56, 80, 120} {
		row := agentDashboardTunnelRow(width, "running", "127.0.0.1:3000", "web")
		if got := lipgloss.Width(row); got > width {
			t.Fatalf("width %d: row %q is %d cells wide", width, row, got)
		}
		if width < len("running web") {
			continue
		}
		fields := strings.Fields(row)
		if fields[0] != "running" || fields[len(fields)-1] != "web" {
			t.Fatalf("width %d: row %q must start with the state and end with the name", width, row)
		}
	}
}

func TestAgentDashboardTunnelRowTruncatesLongNames(t *testing.T) {
	name := "a-tunnel-name-that-is-much-longer-than-the-name-column-can-hold"
	row := agentDashboardTunnelRow(56, "running", "127.0.0.1:3000", name)
	if lipgloss.Width(row) > 56 {
		t.Fatalf("row %q is %d cells wide", row, lipgloss.Width(row))
	}
	if !strings.HasSuffix(row, "~") {
		t.Fatalf("row %q should end with the truncation marker", row)
	}
}

func TestAgentDashboardTunnelTableIsNeverWiderThanThePane(t *testing.T) {
	tables := [][]AgentTunnelStatus{
		nil,
		{{Name: strings.Repeat("n", 60), TargetAddr: "127.0.0.1:3000"}},
		{{Name: strings.Repeat("日", 40)}},
	}
	for _, tunnels := range tables {
		for width := 1; width <= 140; width++ {
			if got := agentDashboardTunnelTableWidth(width, tunnels); got > width {
				t.Fatalf("width %d: table is %d cells wide for %+v", width, got, tunnels)
			}
		}
	}
}
