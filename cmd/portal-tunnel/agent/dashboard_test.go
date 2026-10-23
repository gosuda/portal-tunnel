package agent

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func testDashboardStatus() AgentStatusResponse {
	relays := []AgentRelayStatus{
		{RelayURL: "https://relay-one.example.com", PublicURL: "https://web.relay-one.example.com", Version: "v2.4.1", SupportsTCP: true, SupportsUDP: true},
		{RelayURL: "https://relay-two.example.org:8443", Connecting: true, Version: "v2.4.0", SupportsTCP: true},
		{RelayURL: "https://relay-three.example.net"},
		{RelayURL: "https://banned.example.net", Banned: true},
	}
	return AgentStatusResponse{
		ConfigPath:    "/Users/someone/.config/portal/config.toml",
		ControlAddr:   "127.0.0.1:41873",
		WalletAddress: "0x52908400098527886E0F7030069857D2E4169EE7",
		Tunnels: []AgentTunnelStatus{
			{
				ID: "web", Name: "web", State: "running", TargetAddr: "127.0.0.1:3000", Discovery: true, MaxActiveRelays: 3,
				Metadata: types.LeaseMetadata{Description: "Main site", Tags: []string{"web", "prod"}, Owner: "me"},
				Relays:   relays,
			},
			{ID: "api", Name: "api-gateway-with-a-rather-long-name", State: "starting", TargetAddr: "127.0.0.1:8080", MaxActiveRelays: 2, Relays: relays[:2]},
			{
				ID: "paid", Name: "paid", State: "error", LastError: "relay handshake failed: connection refused by remote peer", MaxActiveRelays: 3,
				HTTPRoutes: []tunnel.HTTPRoute{{Prefix: "/paid", Upstream: "3001", Methods: []string{"GET"}, Amount: "0.01"}, {Prefix: "/", Upstream: "5173"}},
				Relays:     relays[:1],
			},
			{ID: "site", State: "running", Serve: "./public-site"},
			{ID: "wide", Name: "데모터널日本語", State: "stopped", MaxActiveRelays: 1, Relays: relays[2:]},
		},
	}
}

func newTestDashboard(width, height int) agentDashboardModel {
	var model tea.Model = newAgentDashboardModel("/etc/portal/config.toml", "/var/lib/portal")
	model, _ = model.Update(agentDashboardStatusMsg{status: testDashboardStatus()})
	model, _ = model.Update(tea.WindowSizeMsg{Width: width, Height: height})
	return model.(agentDashboardModel)
}

func sendKeys(model agentDashboardModel, keys ...tea.KeyMsg) agentDashboardModel {
	var next tea.Model = model
	for _, key := range keys {
		next, _ = next.Update(key)
	}
	return next.(agentDashboardModel)
}

func clickAction(t *testing.T, model agentDashboardModel, action agentDashboardAction) agentDashboardModel {
	t.Helper()
	for _, region := range model.layout().regions {
		if region.action != action {
			continue
		}
		next, _ := model.Update(tea.MouseMsg{X: region.x0, Y: region.y, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
		return next.(agentDashboardModel)
	}
	t.Fatalf("no clickable region for action %d", action)
	return model
}

func TestDashboardViewFitsTheTerminal(t *testing.T) {
	var (
		right = tea.KeyMsg{Type: tea.KeyRight}
		down  = tea.KeyMsg{Type: tea.KeyDown}
		long  = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(strings.Repeat("long value ", 20))}
	)
	longDescription := testDashboardStatus()
	longDescription.Tunnels[0].Metadata.Description = strings.Repeat("a long description ", 10)

	panes := []struct {
		name  string
		setup func(*testing.T, agentDashboardModel) agentDashboardModel
	}{
		{"tunnels", func(_ *testing.T, m agentDashboardModel) agentDashboardModel { return m }},
		{"settings", func(_ *testing.T, m agentDashboardModel) agentDashboardModel { return sendKeys(m, right) }},
		{"settings with a long value", func(_ *testing.T, m agentDashboardModel) agentDashboardModel { return sendKeys(m, right, down, long) }},
		{"settings resized from a wider terminal", func(_ *testing.T, m agentDashboardModel) agentDashboardModel {
			// The long value is loaded while the terminal is 200 columns wide, then it shrinks to m's size.
			var wide tea.Model = newAgentDashboardModel("/etc/portal/config.toml", "/var/lib/portal")
			for _, msg := range []tea.Msg{tea.WindowSizeMsg{Width: 200, Height: 50}, agentDashboardStatusMsg{status: longDescription}, right, tea.WindowSizeMsg{Width: m.width, Height: m.height}} {
				wide, _ = wide.Update(msg)
			}
			return wide.(agentDashboardModel)
		}},
		{"relays", func(_ *testing.T, m agentDashboardModel) agentDashboardModel { return sendKeys(m, right, right) }},
		{"add tunnel form", func(t *testing.T, m agentDashboardModel) agentDashboardModel {
			return sendKeys(clickAction(t, m, agentDashboardActionAddTunnel), long)
		}},
	}
	for _, pane := range panes {
		for _, size := range [][2]int{{80, 24}, {80, 40}, {100, 24}, {100, 40}, {132, 24}, {132, 40}} {
			width, height := size[0], size[1]
			t.Run(fmt.Sprintf("%s %dx%d", pane.name, width, height), func(t *testing.T) {
				view := pane.setup(t, newTestDashboard(width, height)).View()
				lines := strings.Split(view, "\n")
				if len(lines) != height {
					t.Fatalf("view has %d lines, want %d", len(lines), height)
				}
				for i, line := range lines {
					if got := lipgloss.Width(line); got > width {
						t.Fatalf("line %d is %d cells wide, terminal is %d: %q", i, got, width, line)
					}
				}
			})
		}
	}
}
