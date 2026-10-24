package agent

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
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

// testDashboardStatus is plain ASCII on purpose: the ASCII fallback is about the glyphs the
// dashboard draws, not about what users name their tunnels.
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
			{ID: "idle", Name: "idle", State: "stopped", MaxActiveRelays: 1, Relays: relays[2:]},
		},
	}
}

type dashboardScenario struct {
	name  string
	steps []tea.Msg
}

// testDashboardScenarios are the states of the dashboard a terminal has to be able to show.
func testDashboardScenarios() []dashboardScenario {
	load := agentDashboardStatusMsg{status: testDashboardStatus()}
	long := keyRunes(strings.Repeat("long value ", 20))

	longDescription := testDashboardStatus()
	longDescription.Tunnels[0].Metadata.Description = strings.Repeat("a long description ", 10)

	return []dashboardScenario{
		{"tunnels", []tea.Msg{load}},
		{"settings", []tea.Msg{load, keyRight}},
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

func newTestTheme(t *testing.T, name string, term agentDashboardTerminal) agentDashboardTheme {
	t.Helper()
	theme, err := newAgentDashboardTheme(name, term)
	if err != nil {
		t.Fatal(err)
	}
	return theme
}

// newTestDashboard replays steps on a new model and then sizes the terminal.
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

// clickText presses the left mouse button on the first and on the last cell of text as it is
// drawn, and requires that both presses had the effect.
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

// forceColor makes lipgloss emit escape sequences even though the test output is not a terminal.
func forceColor(t *testing.T) {
	t.Helper()
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })
}

func TestDashboardViewFitsTheTerminal(t *testing.T) {
	themes := []struct {
		name  string
		theme agentDashboardTheme
	}{
		{"amber", newTestTheme(t, "amber", agentDashboardTerminal{unicode: true, color: true})},
		{"green", newTestTheme(t, "green", agentDashboardTerminal{unicode: true, color: true})},
		{"ascii", newTestTheme(t, "amber", agentDashboardTerminal{color: true})},
	}
	wide := testDashboardStatus()
	wide.Tunnels = append(wide.Tunnels, AgentTunnelStatus{ID: "wide", Name: "데모터널日本語", State: "stopped", Relays: wide.Tunnels[0].Relays})
	scenarios := append(testDashboardScenarios(), dashboardScenario{"wide runes", []tea.Msg{agentDashboardStatusMsg{status: wide}, keyDown, keyDown, keyDown, keyDown, keyDown}})

	for _, th := range themes {
		for _, scenario := range scenarios {
			for _, size := range [][2]int{{80, 24}, {80, 40}, {100, 24}, {100, 40}, {132, 24}, {132, 40}} {
				width, height := size[0], size[1]
				t.Run(fmt.Sprintf("%s %s %dx%d", th.name, scenario.name, width, height), func(t *testing.T) {
					view := newTestDashboard(t, th.theme, width, height, scenario.steps...).View()
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
				})
			}
		}
	}
}

func TestDashboardASCIIFallbackDrawsOnlyASCII(t *testing.T) {
	forceColor(t)
	theme := newTestTheme(t, "amber", agentDashboardTerminal{color: true})
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

func TestDashboardWithoutColorEmitsNoEscapeSequences(t *testing.T) {
	forceColor(t)
	colored := newTestTheme(t, "amber", agentDashboardTerminal{unicode: true, color: true})
	plain := newTestTheme(t, "amber", agentDashboardTerminal{unicode: true})
	for _, scenario := range testDashboardScenarios() {
		if !strings.Contains(newTestDashboard(t, colored, 100, 40, scenario.steps...).View(), "\x1b[") {
			t.Fatalf("%s: the colored theme emitted no escape sequence, so this test would prove nothing", scenario.name)
		}
		if view := newTestDashboard(t, plain, 100, 40, scenario.steps...).View(); strings.Contains(view, "\x1b") {
			t.Fatalf("%s: a colorless theme emitted an escape sequence", scenario.name)
		}
	}
}

func TestDashboardActivePaneIsMarkedWithoutColor(t *testing.T) {
	plain := newTestTheme(t, "amber", agentDashboardTerminal{})
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

func TestDashboardKeyBarListsTheBindingsInUse(t *testing.T) {
	theme := newTestTheme(t, "amber", agentDashboardTerminal{unicode: true})
	load := agentDashboardStatusMsg{status: testDashboardStatus()}
	tests := []struct {
		name  string
		steps []tea.Msg
		want  []string
		not   []string
	}{
		{"tunnels", []tea.Msg{load}, []string{"F2/a Add", "F8/Del Delete", "↑/↓ Select", "Tab/→ Pane", "F10/q Quit"}, []string{"Create", "Apply", "Esc"}},
		{"add tunnel form", []tea.Msg{load, keyF2}, []string{"F2/Enter Create", "Esc Cancel", "Tab/S-Tab Field", "F10/^C Quit"}, []string{"F2/a Add", "Delete"}},
		{"settings", []tea.Msg{load, keyRight}, []string{"Enter Apply", "Tab/S-Tab Field", "F2 Add", "Esc Back", "F10/^C Quit"}, []string{"F2/a Add", "Delete"}},
		{"relays", []tea.Msg{load, keyRight, keyRight}, []string{"Enter/c Connect", "d/Del Disconnect", "o Open", "Esc Back", "F10/q Quit"}, []string{"Delete tunnel"}},
		{"delete confirmation", []tea.Msg{load, keyF8}, []string{"y Yes", "n/Esc No", "F10/^C Quit"}, []string{"Add", "Pane"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bar := lastLine(newTestDashboard(t, theme, 140, 40, tt.steps...).View())
			for _, want := range tt.want {
				if !strings.Contains(bar, want) {
					t.Errorf("key bar %q lacks %q", bar, want)
				}
			}
			for _, not := range tt.not {
				if strings.Contains(bar, not) {
					t.Errorf("key bar %q must not list %q here", bar, not)
				}
			}
		})
	}
}

func TestDashboardAddTunnelByKey(t *testing.T) {
	theme := newTestTheme(t, "amber", agentDashboardTerminal{unicode: true})
	model := newTestDashboard(t, theme, 100, 40, agentDashboardStatusMsg{status: testDashboardStatus()})
	for _, key := range []tea.KeyMsg{keyRunes("a"), keyF2} {
		opened, _ := press(model, key)
		if !strings.Contains(opened.View(), "Name:") {
			t.Fatalf("%s should open the add form", key)
		}
		if closed, _ := press(opened, keyEsc); strings.Contains(closed.View(), "Name:") {
			t.Fatal("esc should cancel the add form")
		}
	}
}

func TestDashboardQuitKeys(t *testing.T) {
	theme := newTestTheme(t, "amber", agentDashboardTerminal{unicode: true})
	load := agentDashboardStatusMsg{status: testDashboardStatus()}
	contexts := []struct {
		name      string
		steps     []tea.Msg
		qIsText   bool
		textEntry func(agentDashboardModel) string
	}{
		{"tunnels", []tea.Msg{load}, false, nil},
		{"relays", []tea.Msg{load, keyRight, keyRight}, false, nil},
		{"settings", []tea.Msg{load, keyRight}, true, func(m agentDashboardModel) string { return m.settingsMaxRelays.Value() }},
		{"add tunnel form", []tea.Msg{load, keyRunes("a")}, true, func(m agentDashboardModel) string { return m.addName.Value() }},
	}
	for _, ctx := range contexts {
		t.Run(ctx.name, func(t *testing.T) {
			model := newTestDashboard(t, theme, 100, 40, ctx.steps...)
			for _, key := range []tea.KeyMsg{keyF10, keyCtrlC} {
				if _, cmd := press(model, key); !isQuit(cmd) {
					t.Errorf("%s should quit", key)
				}
			}
			typed, cmd := press(model, keyRunes("q"))
			if ctx.qIsText {
				if isQuit(cmd) || !strings.HasSuffix(ctx.textEntry(typed), "q") {
					t.Errorf("q belongs to the focused input here, quit = %v, input = %q", isQuit(cmd), ctx.textEntry(typed))
				}
			} else if !isQuit(cmd) {
				t.Error("q should quit")
			}
		})
	}
}

func TestDashboardPaneKeys(t *testing.T) {
	theme := newTestTheme(t, "amber", agentDashboardTerminal{unicode: true})
	model := newTestDashboard(t, theme, 100, 40, agentDashboardStatusMsg{status: testDashboardStatus()})
	active := func(m agentDashboardModel) string {
		for _, title := range []string{"TUNNELS", "SETTINGS", "RELAYS"} {
			if strings.Contains(m.View(), "[ "+title+" ]") {
				return title
			}
		}
		return ""
	}
	tests := []struct {
		keys []tea.KeyMsg
		want string
	}{
		{[]tea.KeyMsg{keyTab}, "SETTINGS"},
		{[]tea.KeyMsg{keyBackTb}, "RELAYS"},
		{[]tea.KeyMsg{keyRight}, "SETTINGS"},
		{[]tea.KeyMsg{keyLeft}, "RELAYS"},
		{[]tea.KeyMsg{keyRight, keyRight}, "RELAYS"},
		{[]tea.KeyMsg{keyRight, keyRight, keyTab}, "TUNNELS"},
		{[]tea.KeyMsg{keyRight, keyRight, keyBackTb}, "SETTINGS"},
		{[]tea.KeyMsg{keyRight, keyEsc}, "TUNNELS"},
		// Settings is a form: tab and shift+tab move between its fields, and only left and right leave it.
		{[]tea.KeyMsg{keyTab, keyTab}, "SETTINGS"},
		{[]tea.KeyMsg{keyTab, keyBackTb}, "SETTINGS"},
		{[]tea.KeyMsg{keyTab, keyRight}, "RELAYS"},
		{[]tea.KeyMsg{keyTab, keyLeft}, "TUNNELS"},
	}
	for _, tt := range tests {
		if pressed, _ := press(model, tt.keys...); active(pressed) != tt.want {
			t.Errorf("after %v the active pane is %q, want %q", tt.keys, active(pressed), tt.want)
		}
	}
}

func TestDashboardTunnelRowsShowWhatEachTunnelServes(t *testing.T) {
	theme := newTestTheme(t, "amber", agentDashboardTerminal{unicode: true})
	view := newTestDashboard(t, theme, 100, 40, agentDashboardStatusMsg{status: testDashboardStatus()}).View()
	for _, want := range []string{"[*] 127.0.0.1:3000", "[~] 127.0.0.1:8080", "[!] 2 routes, 1 paid", "[*] ./public-site"} {
		if !strings.Contains(view, want) {
			t.Errorf("the tunnel rows lack %q", want)
		}
	}
}

func TestDashboardEscClearsTheError(t *testing.T) {
	theme := newTestTheme(t, "amber", agentDashboardTerminal{unicode: true})
	model := newTestDashboard(t, theme, 100, 40, agentDashboardStatusMsg{status: testDashboardStatus()},
		agentDashboardActionMsg{err: errors.New("tunnel name is required")})
	if !strings.Contains(model.View(), "Error: tunnel name is required") {
		t.Fatal("the error should be shown")
	}
	if cleared, _ := press(model, keyEsc); strings.Contains(cleared.View(), "Error:") {
		t.Fatal("esc should clear the error")
	}
}

func TestDashboardDeleteAsksBeforeDeleting(t *testing.T) {
	theme := newTestTheme(t, "amber", agentDashboardTerminal{unicode: true})
	model := newTestDashboard(t, theme, 100, 40, agentDashboardStatusMsg{status: testDashboardStatus()})
	const prompt = `Delete tunnel "web"?`

	for _, key := range []tea.KeyMsg{keyF8, keyDelete} {
		asked, cmd := press(model, key)
		if cmd != nil || !strings.Contains(asked.View(), prompt) {
			t.Fatalf("%s should only ask: cmd = %v, view asks = %v", key, cmd != nil, strings.Contains(asked.View(), prompt))
		}
		for _, answer := range []tea.KeyMsg{keyRunes("n"), keyEsc, keyRunes("q")} {
			declined, cmd := press(asked, answer)
			if cmd != nil || strings.Contains(declined.View(), prompt) {
				t.Fatalf("%s should decline without deleting or quitting", answer)
			}
		}
		confirmed, cmd := press(asked, keyRunes("y"))
		if cmd == nil || strings.Contains(confirmed.View(), prompt) {
			t.Fatalf("y should delete the tunnel: cmd = %v", cmd != nil)
		}
		if _, cmd := press(asked, keyRunes("x"), keyTab, keyF2); cmd != nil {
			t.Fatal("other keys must not answer the question")
		}
	}

	// The Delete button asks too, and its answers are buttons as well.
	asked, cmd := clickAction(t, model, agentDashboardActionDeleteTunnel)
	if cmd != nil || !strings.Contains(asked.View(), prompt) {
		t.Fatal("the Delete button should only ask")
	}
	if declined, cmd := clickAction(t, asked, agentDashboardActionCancelDelete); cmd != nil || strings.Contains(declined.View(), prompt) {
		t.Fatal("the No button should decline without deleting")
	}
	if confirmed, cmd := clickAction(t, asked, agentDashboardActionConfirmDelete); cmd == nil || strings.Contains(confirmed.View(), prompt) {
		t.Fatal("the Yes button should delete the tunnel")
	}
}

func TestDashboardMouseStillWorks(t *testing.T) {
	theme := newTestTheme(t, "amber", agentDashboardTerminal{unicode: true})
	model := newTestDashboard(t, theme, 100, 40, agentDashboardStatusMsg{status: testDashboardStatus()})

	clickText(t, model, "[ Add Tunnel ]", viewHas("Name:"))
	clickText(t, model, "RELAYS", viewHas("[ RELAYS ]"))
	clickText(t, model, "[~]", viewHas(">[~]"))
	clickText(t, model, "[ Delete ]", viewHas(`Delete tunnel "web"?`))

	settings := clickText(t, model, "SETTINGS", viewHas("[ SETTINGS ]"))
	focused := regexp.MustCompile(`Owner:\s+> me`)
	clickText(t, settings, "Owner:", func(m agentDashboardModel) bool { return focused.MatchString(m.View()) })
}

func TestAgentDashboardPaneRows(t *testing.T) {
	for _, want := range [][agentDashboardPaneCount]int{{8, 8, 8}, {20, 9, 7}, {2, 30, 4}, {5, 5, 40}, {1, 1, 1}} {
		for active := range agentDashboardPaneCount {
			t.Run(fmt.Sprintf("want %v active %d", want, active), func(t *testing.T) {
				for height := 18; height <= 80; height++ {
					checkPaneRows(t, height, want, active)
				}
			})
		}
	}

	if rows := agentDashboardPaneRows(0, [agentDashboardPaneCount]int{7, 8, 9}, agentDashboardPaneSettings); rows != [agentDashboardPaneCount]int{7, 8, 9} {
		t.Errorf("an unknown height must keep every pane at its natural size, got %v", rows)
	}
}

// checkPaneRows requires that the panes and their frames fill the body, that no pane drops below
// its minimum, and that no other pane grows before the active one has all the rows it wants.
func checkPaneRows(t *testing.T, height int, want [agentDashboardPaneCount]int, active agentDashboardPane) {
	t.Helper()
	rows := agentDashboardPaneRows(height, want, active)
	total := agentDashboardFrameHeight * int(agentDashboardPaneCount)
	grewEarly := false
	for pane, n := range rows {
		total += n
		floor := min(want[pane], agentDashboardMinPaneRows)
		if n < floor {
			t.Fatalf("height %d: pane %d is down to %d rows: %v", height, pane, n, rows)
		}
		grewEarly = grewEarly || (agentDashboardPane(pane) != active && n > floor)
	}
	if total != height {
		t.Fatalf("height %d: rows %v do not fill the body", height, rows)
	}
	if grewEarly && rows[active] < want[active] {
		t.Fatalf("height %d: a pane grew before the active pane was full: %v", height, rows)
	}
}

func TestNewAgentDashboardTheme(t *testing.T) {
	for _, name := range []string{"", "amber", "AMBER", " green "} {
		if _, err := newAgentDashboardTheme(name, agentDashboardTerminal{}); err != nil {
			t.Errorf("theme %q: %v", name, err)
		}
	}
	_, err := newAgentDashboardTheme("purple", agentDashboardTerminal{})
	if err == nil {
		t.Fatal("an unknown theme must be rejected")
	}
	for _, want := range []string{"purple", "amber", "green"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}

	amber := newTestTheme(t, "amber", agentDashboardTerminal{color: true})
	green := newTestTheme(t, "green", agentDashboardTerminal{color: true})
	if amber.text.GetForeground() == green.text.GetForeground() {
		t.Error("the palettes must differ")
	}
}

func TestDetectAgentDashboardTerminal(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want agentDashboardTerminal
	}{
		{"UTF-8 xterm", map[string]string{"TERM": "xterm-256color", "LANG": "en_US.UTF-8"}, agentDashboardTerminal{unicode: true, color: true}},
		{"no TERM is not a reason to fall back", map[string]string{"LANG": "C.UTF-8"}, agentDashboardTerminal{unicode: true, color: true}},
		{"dumb terminal", map[string]string{"TERM": "dumb", "LANG": "en_US.UTF-8"}, agentDashboardTerminal{color: true}},
		{"Linux console", map[string]string{"TERM": "linux", "LANG": "en_US.UTF-8"}, agentDashboardTerminal{color: true}},
		{"C locale", map[string]string{"TERM": "xterm", "LANG": "C"}, agentDashboardTerminal{color: true}},
		{"locale not set", map[string]string{"TERM": "xterm"}, agentDashboardTerminal{color: true}},
		{"LC_ALL beats LANG", map[string]string{"TERM": "xterm", "LC_ALL": "C", "LANG": "en_US.UTF-8"}, agentDashboardTerminal{color: true}},
		{"LC_ALL says UTF-8", map[string]string{"TERM": "xterm", "LC_ALL": "en_US.utf8", "LANG": "C"}, agentDashboardTerminal{unicode: true, color: true}},
		{"LC_CTYPE beats LANG", map[string]string{"TERM": "xterm", "LC_CTYPE": "C.UTF-8", "LANG": "C"}, agentDashboardTerminal{unicode: true, color: true}},
		{"NO_COLOR", map[string]string{"TERM": "xterm", "LANG": "en_US.UTF-8", "NO_COLOR": "1"}, agentDashboardTerminal{unicode: true}},
		{"empty NO_COLOR is ignored", map[string]string{"TERM": "xterm", "LANG": "en_US.UTF-8", "NO_COLOR": ""}, agentDashboardTerminal{unicode: true, color: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, name := range []string{"TERM", "LC_ALL", "LC_CTYPE", "LANG", "NO_COLOR"} {
				t.Setenv(name, tt.env[name])
			}
			if got := detectAgentDashboardTerminal(); got != tt.want {
				t.Fatalf("detectAgentDashboardTerminal() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
