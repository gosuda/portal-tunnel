package agent

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
)

var (
	keyRight  = tea.KeyMsg{Type: tea.KeyRight}
	keyLeft   = tea.KeyMsg{Type: tea.KeyLeft}
	keyDown   = tea.KeyMsg{Type: tea.KeyDown}
	keyTab    = tea.KeyMsg{Type: tea.KeyTab}
	keyBackTb = tea.KeyMsg{Type: tea.KeyShiftTab}
	keyEsc    = tea.KeyMsg{Type: tea.KeyEsc}
	keyF2     = tea.KeyMsg{Type: tea.KeyF2}
	keyF8     = tea.KeyMsg{Type: tea.KeyF8}
	keyF10    = tea.KeyMsg{Type: tea.KeyF10}
	keyCtrlC  = tea.KeyMsg{Type: tea.KeyCtrlC}
	keyDelete = tea.KeyMsg{Type: tea.KeyDelete}
)

func keyRunes(text string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(text)}
}

func testDashboardStatus() AgentStatusResponse {
	relays := []AgentRelayStatus{
		{RelayURL: "https://relay-one.example.com", PublicURL: "https://web.relay-one.example.com", Version: "v2.4.1", State: sdk.RelayReady},
		{RelayURL: "https://relay-two.example.org:8443", State: sdk.RelayConnecting, Version: "v2.4.0"},
		{RelayURL: "https://relay-three.example.net"},
		{RelayURL: "https://failed.example.net", State: sdk.RelayFailed},
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
			{ID: "idle", Name: "idle", State: "stopped", MaxActiveRelays: 1},
		},
	}
}

type dashboardScenario struct {
	name  string
	steps []tea.Msg
}

func testDashboardScenarios() []dashboardScenario {
	load := agentDashboardStatusMsg{status: testDashboardStatus()}
	long := keyRunes(strings.Repeat("long value ", 20))

	longDescription := testDashboardStatus()
	longDescription.Tunnels[0].Metadata.Description = strings.Repeat("a long description ", 10)

	signIn := agentDashboardStatusMsg{status: testAccessStatus()}
	longAllowList := testAccessStatus()
	for i := range 12 {
		longAllowList.Tunnels[accessWeb].Allow = append(longAllowList.Tunnels[accessWeb].Allow, fmt.Sprintf("a-rather-long-address-%d@a-long-company-name.example.com", i))
	}
	openAccess := func(down int, keys ...tea.Msg) []tea.Msg {
		steps := []tea.Msg{signIn}
		for range down {
			steps = append(steps, keyDown)
		}
		return append(append(steps, keyF4), keys...)
	}

	return []dashboardScenario{
		{"tunnels", []tea.Msg{load}},
		{"settings", []tea.Msg{load, keyRight}},
		{"settings with OIDC sign-in", []tea.Msg{signIn, keyRight}},
		{"settings with wallet sign-in", []tea.Msg{signIn, keyDown, keyRight}},
		{"access", openAccess(accessWeb)},
		{"access with a long secret revealed", openAccess(accessWeb, keyUp, keyRunes(strings.Repeat("secret ", 20)), keyF3)},
		{"access with a long secret hidden", openAccess(accessWeb, keyUp, keyRunes(strings.Repeat("secret ", 20)))},
		{"access with an error", openAccess(accessWeb, keyUp, keyRunes("x"), keyF2, agentDashboardAccessMsg{tunnelID: "web", err: errors.New(strings.Repeat("invalid_request: something is wrong with the sign-in settings. ", 6))})},
		{"access of a wallet tunnel", openAccess(accessWallet)},
		{"access of an open tunnel", openAccess(accessOpen)},
		{"access with a long allow list", []tea.Msg{agentDashboardStatusMsg{status: longAllowList}, keyF4, keyDown, keyDown, keyDown, keyDown, keyDown}},
		{"settings with a long value", []tea.Msg{load, keyRight, keyDown, long}},
		{"settings resized from a wider terminal", []tea.Msg{tea.WindowSizeMsg{Width: 200, Height: 50}, agentDashboardStatusMsg{status: longDescription}, keyRight}},
		{"settings resized with the cursor at the start", []tea.Msg{tea.WindowSizeMsg{Width: 200, Height: 50}, agentDashboardStatusMsg{status: longDescription}, keyRight, keyDown, tea.KeyMsg{Type: tea.KeyHome}}},
		{"relays", []tea.Msg{load, keyRight, keyRight}},
		{"add tunnel form", []tea.Msg{load, keyRunes("a"), long}},
		{"tunnel with an error", []tea.Msg{load, keyDown, keyDown}},
		{"delete confirmation", []tea.Msg{load, keyF8}},
		{"error banner", []tea.Msg{load, agentDashboardActionMsg{err: errors.New("tunnel name is required")}}},
		{"agent unavailable", []tea.Msg{agentDashboardStatusMsg{err: errors.New("agent is not running")}}},
		{"no tunnels", []tea.Msg{agentDashboardStatusMsg{status: AgentStatusResponse{ControlAddr: "127.0.0.1:41873"}}}},
	}
}

func newTestDashboard(t *testing.T, theme agentDashboardTheme, width, height int, steps ...tea.Msg) agentDashboardModel {
	t.Helper()
	var model tea.Model = newAgentDashboardModel("/etc/portal/config.toml", "/var/lib/portal", theme)
	for _, step := range append(steps, tea.WindowSizeMsg{Width: width, Height: height}) {
		model, _ = model.Update(step)
	}
	return model.(agentDashboardModel)
}

func press(model agentDashboardModel, keys ...tea.KeyMsg) (agentDashboardModel, tea.Cmd) {
	var next tea.Model = model
	var cmd tea.Cmd
	for _, key := range keys {
		next, cmd = next.Update(key)
	}
	return next.(agentDashboardModel), cmd
}

func click(t *testing.T, model agentDashboardModel, match func(agentDashboardRegion) bool) (agentDashboardModel, tea.Cmd) {
	t.Helper()
	for _, region := range model.layout().regions {
		if match(region) {
			next, cmd := model.Update(tea.MouseMsg{X: region.x0, Y: region.y, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
			return next.(agentDashboardModel), cmd
		}
	}
	t.Fatal("no clickable region matches")
	return model, nil
}

func clickText(t *testing.T, model agentDashboardModel, text string, worked func(agentDashboardModel) bool) agentDashboardModel {
	t.Helper()
	for y, line := range strings.Split(model.View(), "\n") {
		index := strings.Index(line, text)
		if index < 0 {
			continue
		}
		first := lipgloss.Width(line[:index])
		var clicked agentDashboardModel
		for _, x := range []int{first, first + lipgloss.Width(text) - 1} {
			next, _ := model.Update(tea.MouseMsg{X: x, Y: y, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
			clicked = next.(agentDashboardModel)
			if !worked(clicked) {
				t.Errorf("clicking column %d of %q did nothing", x, text)
			}
		}
		return clicked
	}
	t.Fatalf("%q is not on screen", text)
	return model
}

func viewHas(substrings ...string) func(agentDashboardModel) bool {
	return func(m agentDashboardModel) bool {
		view := m.View()
		for _, substring := range substrings {
			if !strings.Contains(view, substring) {
				return false
			}
		}
		return true
	}
}

func clickAction(t *testing.T, model agentDashboardModel, action agentDashboardAction) (agentDashboardModel, tea.Cmd) {
	t.Helper()
	return click(t, model, func(r agentDashboardRegion) bool { return r.action == action })
}

func isQuit(cmd tea.Cmd) bool {
	return cmd != nil && cmd() == tea.QuitMsg{}
}

func lastLine(view string) string {
	lines := strings.Split(view, "\n")
	return lines[len(lines)-1]
}

func TestDashboardViewFitsTheTerminal(t *testing.T) {
	themes := []struct {
		name  string
		theme agentDashboardTheme
	}{
		{"amber", newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})},
		{"green", newAgentDashboardTheme("green", agentDashboardTerminal{unicode: true})},
		{"ascii", newAgentDashboardTheme("amber", agentDashboardTerminal{})},
	}
	wide := testDashboardStatus()
	wide.Tunnels = append(wide.Tunnels, AgentTunnelStatus{ID: "wide", Name: "데모터널日本語", State: "stopped", Relays: wide.Tunnels[0].Relays})
	scenarios := append(testDashboardScenarios(), dashboardScenario{"wide runes", []tea.Msg{agentDashboardStatusMsg{status: wide}, keyDown, keyDown, keyDown, keyDown, keyDown}})

	for _, th := range themes {
		for _, scenario := range scenarios {
			for _, size := range [][2]int{{80, 24}, {80, 40}, {100, 24}, {100, 40}, {132, 24}, {132, 40}} {
				width, height := size[0], size[1]
				t.Run(fmt.Sprintf("%s %s %dx%d", th.name, scenario.name, width, height), func(t *testing.T) {
					checkDashboardViewFits(t, th.theme, scenario, width, height)
				})
			}
		}
	}
}

func checkDashboardViewFits(t *testing.T, theme agentDashboardTheme, scenario dashboardScenario, width, height int) {
	t.Helper()
	view := newTestDashboard(t, theme, width, height, scenario.steps...).View()
	lines := strings.Split(view, "\n")
	if len(lines) != height {
		t.Fatalf("view has %d lines, want %d", len(lines), height)
	}
	for i, line := range lines {
		if got := lipgloss.Width(line); got > width {
			t.Fatalf("line %d is %d cells wide, terminal is %d: %q", i, got, width, line)
		}
	}
	if !strings.Contains(lines[height-1], "Quit") && scenario.name != "agent unavailable" {
		t.Fatalf("the key bar lost Quit: %q", lines[height-1])
	}
}

func TestDashboardASCIIFallbackDrawsOnlyASCII(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{})
	for _, scenario := range testDashboardScenarios() {
		for _, size := range [][2]int{{80, 24}, {132, 40}} {
			view := newTestDashboard(t, theme, size[0], size[1], scenario.steps...).View()
			for _, r := range view {
				if r >= 0x80 {
					t.Fatalf("%s at %dx%d: view contains %q (U+%04X); it must stay ASCII", scenario.name, size[0], size[1], r, r)
				}
			}
		}
	}
}

func TestDashboardActivePaneIsMarkedWithoutColor(t *testing.T) {
	plain := newAgentDashboardTheme("amber", agentDashboardTerminal{})
	model := newTestDashboard(t, plain, 100, 40, agentDashboardStatusMsg{status: testDashboardStatus()})
	for _, active := range []string{"TUNNELS", "SETTINGS", "RELAYS", "TUNNELS"} {
		view := model.View()
		for _, title := range []string{"TUNNELS", "SETTINGS", "RELAYS"} {
			if marked := strings.Contains(view, "[ "+title+" ]"); marked != (title == active) {
				t.Fatalf("active pane %s: title %s marked = %v", active, title, marked)
			}
		}
		model, _ = press(model, keyRight)
	}
}
