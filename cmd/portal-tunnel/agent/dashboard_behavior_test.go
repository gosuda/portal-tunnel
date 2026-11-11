package agent

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/gosuda/portal-tunnel/v2/sdk"
)

func TestDashboardKeyBarListsTheBindingsInUse(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
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
		{"delete confirmation", []tea.Msg{load, keyF8}, []string{"y Yes", "n/Esc No", "^C Quit"}, []string{"Add", "Pane", "F10"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bar := lastLine(newTestDashboard(t, theme, 140, 40, tt.steps...).View())
			checkKeyBarLists(t, bar, tt.want)
			checkKeyBarOmits(t, bar, tt.not)
		})
	}
}

type dashboardQuitContext struct {
	name      string
	steps     []tea.Msg
	qIsText   bool
	textEntry func(agentDashboardModel) string
}

func TestDashboardAddTunnelByKey(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
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
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	load := agentDashboardStatusMsg{status: testDashboardStatus()}
	contexts := []dashboardQuitContext{
		{"tunnels", []tea.Msg{load}, false, nil},
		{"relays", []tea.Msg{load, keyRight, keyRight}, false, nil},
		{"settings", []tea.Msg{load, keyRight}, true, func(m agentDashboardModel) string { return m.settingsMaxRelays.Value() }},
		{"add tunnel form", []tea.Msg{load, keyRunes("a")}, true, func(m agentDashboardModel) string { return m.addName.Value() }},
	}
	for _, ctx := range contexts {
		t.Run(ctx.name, func(t *testing.T) {
			checkQuitKeysContext(t, theme, ctx)
		})
	}
}

func checkQuitKeysContext(t *testing.T, theme agentDashboardTheme, ctx dashboardQuitContext) {
	t.Helper()
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
}
func TestDashboardAsksBeforeStoppingTheAgent(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	load := agentDashboardStatusMsg{status: testDashboardStatus()}
	const prompt = "Stop the agent?"
	contexts := []struct {
		name  string
		steps []tea.Msg
		keys  []tea.KeyMsg
	}{
		{"tunnels", []tea.Msg{load}, []tea.KeyMsg{keyF10, keyRunes("q")}},
		{"relays", []tea.Msg{load, keyRight, keyRight}, []tea.KeyMsg{keyF10, keyRunes("q")}},
		{"settings", []tea.Msg{load, keyRight}, []tea.KeyMsg{keyF10}},
	}
	for _, ctx := range contexts {
		t.Run(ctx.name, func(t *testing.T) {
			checkStopAgentQuestions(t, theme, ctx.steps, ctx.keys, prompt)
		})
	}
	checkStopAgentDeleteDecline(t, theme, load)
	checkStopAgentButtons(t, theme, load, prompt)
	checkStopAgentKeyBar(t, theme, load)
}

func newStoppingDashboard(t *testing.T, theme agentDashboardTheme, steps ...tea.Msg) agentDashboardModel {
	t.Helper()
	model := newTestDashboard(t, theme, 100, 40, steps...)
	model.stopsAgent = true
	return model
}

func checkStopAgentQuestions(t *testing.T, theme agentDashboardTheme, steps []tea.Msg, keys []tea.KeyMsg, prompt string) {
	t.Helper()
	model := newStoppingDashboard(t, theme, steps...)
	for _, key := range keys {
		asked, cmd := press(model, key)
		if cmd != nil || !strings.Contains(asked.View(), prompt) {
			t.Fatalf("%s should only ask: cmd = %v, view asks = %v", key, cmd != nil, strings.Contains(asked.View(), prompt))
		}
		for _, answer := range []tea.KeyMsg{keyRunes("n"), keyEsc, keyRunes("q"), keyF10} {
			if declined, cmd := press(asked, answer); cmd != nil || strings.Contains(declined.View(), prompt) {
				t.Fatalf("%s should keep the agent running", answer)
			}
		}
		if _, cmd := press(asked, keyRunes("y")); !isQuit(cmd) {
			t.Fatal("y should stop the agent")
		}
	}
	if _, cmd := press(model, keyCtrlC); !isQuit(cmd) {
		t.Error("ctrl+c should stop the agent at once")
	}
}

func checkStopAgentDeleteDecline(t *testing.T, theme agentDashboardTheme, load agentDashboardStatusMsg) {
	t.Helper()
	deleting, _ := press(newStoppingDashboard(t, theme, load), keyF8)
	if declined, cmd := press(deleting, keyF10); cmd != nil || strings.Contains(declined.View(), `Delete tunnel "web"?`) {
		t.Fatalf("F10 during a delete question should decline it, not stop the agent: cmd = %v", cmd != nil)
	}
}

func checkStopAgentButtons(t *testing.T, theme agentDashboardTheme, load agentDashboardStatusMsg, prompt string) {
	t.Helper()
	asked, _ := press(newStoppingDashboard(t, theme, load), keyF10)
	if declined, cmd := clickAction(t, asked, agentDashboardActionAnswerNo); cmd != nil || strings.Contains(declined.View(), prompt) {
		t.Fatal("the No button should keep the agent running")
	}
	if _, cmd := clickAction(t, asked, agentDashboardActionAnswerYes); !isQuit(cmd) {
		t.Fatal("the Yes button should stop the agent")
	}
}

func checkStopAgentKeyBar(t *testing.T, theme agentDashboardTheme, load agentDashboardStatusMsg) {
	t.Helper()
	for _, steps := range [][]tea.Msg{{load}, {load, keyRight, keyRight}} {
		model := newTestDashboard(t, theme, 80, 24, steps...)
		model.stopsAgent = true
		if bar := lastLine(model.View()); !strings.HasSuffix(strings.TrimRight(bar, " "), "F10/q Stop agent") || strings.Contains(bar, "Quit") {
			t.Errorf("key bar %q should end with F10/q Stop agent and offer no plain Quit", bar)
		}
	}
}

func TestDashboardPaneKeys(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	model := newTestDashboard(t, theme, 100, 40, agentDashboardStatusMsg{status: testDashboardStatus()})
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
		{[]tea.KeyMsg{keyTab, keyTab}, "SETTINGS"},
		{[]tea.KeyMsg{keyTab, keyBackTb}, "SETTINGS"},
		{[]tea.KeyMsg{keyTab, keyRight}, "RELAYS"},
		{[]tea.KeyMsg{keyTab, keyLeft}, "TUNNELS"},
	}
	for _, tt := range tests {
		if pressed, _ := press(model, tt.keys...); activeDashboardPane(pressed) != tt.want {
			t.Errorf("after %v the active pane is %q, want %q", tt.keys, activeDashboardPane(pressed), tt.want)
		}
	}
}

func activeDashboardPane(m agentDashboardModel) string {
	for _, title := range []string{"TUNNELS", "SETTINGS", "RELAYS"} {
		if strings.Contains(m.View(), "[ "+title+" ]") {
			return title
		}
	}
	return ""
}

func TestDashboardTunnelRowsShowWhatEachTunnelServes(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	view := newTestDashboard(t, theme, 100, 40, agentDashboardStatusMsg{status: testDashboardStatus()}).View()
	for _, want := range []string{"[*] 127.0.0.1:3000", "[~] 127.0.0.1:8080", "[!] 2 routes, 1 paid", "[*] ./public-site"} {
		if !strings.Contains(view, want) {
			t.Errorf("the tunnel rows lack %q", want)
		}
	}
}

func TestDashboardEscClearsTheError(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	model := newTestDashboard(t, theme, 100, 40, agentDashboardStatusMsg{status: testDashboardStatus()},
		agentDashboardActionMsg{err: errors.New("tunnel name is required")})
	if !strings.Contains(model.View(), "Error: tunnel name is required") {
		t.Fatal("the error should be shown")
	}
	if cleared, _ := press(model, keyEsc); strings.Contains(cleared.View(), "Error:") {
		t.Fatal("esc should clear the error")
	}
}
func TestDashboardKeepsAnActionErrorAcrossPolls(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	healthy := agentDashboardStatusMsg{status: testDashboardStatus()}
	refused := errors.New("tunnel name is required")

	t.Run("the poll after a refused action", func(t *testing.T) {
		checkRefusedActionPoll(t, theme, healthy, refused)
	})

	t.Run("a failed poll", func(t *testing.T) {
		checkFailedPollReplacesRefusal(t, theme, healthy, refused)
	})
}

func checkRefusedActionPoll(t *testing.T, theme agentDashboardTheme, healthy agentDashboardStatusMsg, refused error) {
	t.Helper()
	model := newTestDashboard(t, theme, 100, 40, healthy, agentDashboardActionMsg{err: refused}, healthy, healthy)
	if !strings.Contains(model.View(), "Error: "+refused.Error()) {
		t.Fatalf("the refusal must stay on screen after the polls that follow it:\n%s", model.View())
	}
	if cleared, _ := press(model, keyEsc); strings.Contains(cleared.View(), "Error:") {
		t.Fatal("esc should still dismiss it")
	}
	if worked := send(model, agentDashboardActionMsg{}); strings.Contains(worked.View(), "Error:") {
		t.Fatal("an action that works should replace the refusal of the one before")
	}
}

func checkFailedPollReplacesRefusal(t *testing.T, theme agentDashboardTheme, healthy agentDashboardStatusMsg, refused error) {
	t.Helper()
	unreachable := agentDashboardStatusMsg{err: errors.New("agent not reachable")}
	model := newTestDashboard(t, theme, 100, 40, healthy, agentDashboardActionMsg{err: refused}, unreachable)
	if view := model.View(); !strings.Contains(view, "Error: agent not reachable") || strings.Contains(view, refused.Error()) {
		t.Fatalf("a failed poll says more than an older refusal:\n%s", view)
	}
	if view := send(model, healthy).View(); !strings.Contains(view, "Error: "+refused.Error()) || strings.Contains(view, "not reachable") {
		t.Fatalf("once the poll works again the refusal is what is left:\n%s", view)
	}
	if view := send(newTestDashboard(t, theme, 100, 40, healthy, unreachable), healthy).View(); strings.Contains(view, "Error:") {
		t.Fatalf("a poll that works must clear the failure of the one before:\n%s", view)
	}
}

func TestDashboardDeleteAsksBeforeDeleting(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	model := newTestDashboard(t, theme, 100, 40, agentDashboardStatusMsg{status: testDashboardStatus()})
	const prompt = `Delete tunnel "web"?`

	for _, key := range []tea.KeyMsg{keyF8, keyDelete} {
		t.Run(key.String(), func(t *testing.T) {
			checkDeleteAsksFirst(t, model, key, prompt)
		})
	}

	asked, cmd := clickAction(t, model, agentDashboardActionDeleteTunnel)
	if cmd != nil || !strings.Contains(asked.View(), prompt) {
		t.Fatal("the Delete button should only ask")
	}
	if declined, cmd := clickAction(t, asked, agentDashboardActionAnswerNo); cmd != nil || strings.Contains(declined.View(), prompt) {
		t.Fatal("the No button should decline without deleting")
	}
	if confirmed, cmd := clickAction(t, asked, agentDashboardActionAnswerYes); cmd == nil || strings.Contains(confirmed.View(), prompt) {
		t.Fatal("the Yes button should delete the tunnel")
	}
}

func checkDeleteAsksFirst(t *testing.T, model agentDashboardModel, key tea.KeyMsg, prompt string) {
	t.Helper()
	asked, cmd := press(model, key)
	if cmd != nil || !strings.Contains(asked.View(), prompt) {
		t.Fatalf("%s should only ask: cmd = %v, view asks = %v", key, cmd != nil, strings.Contains(asked.View(), prompt))
	}
	for _, answer := range []tea.KeyMsg{keyRunes("n"), keyEsc, keyRunes("q"), keyF10} {
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

func TestDashboardDeleteQuestionIgnoresOtherClicks(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	status := testDashboardStatus()
	status.Tunnels[0].Relays = []AgentRelayStatus{{RelayURL: "https://failed.example.net", State: sdk.RelayFailed}}
	model := newTestDashboard(t, theme, 100, 40, agentDashboardStatusMsg{status: status})
	asked, _ := press(model, keyF8)
	if !strings.Contains(asked.View(), `Delete tunnel "web"?`) {
		t.Fatal("F8 should ask before deleting the web tunnel")
	}

	clicked := make(map[agentDashboardAction]bool)
	for _, region := range asked.layout().regions {
		if region.action == agentDashboardActionAnswerYes || region.action == agentDashboardActionAnswerNo {
			continue
		}
		next, cmd := asked.Update(tea.MouseMsg{X: region.x0, Y: region.y, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
		if cmd != nil || next.View() != asked.View() {
			t.Errorf("clicking %+v while the question is open changed the dashboard", region)
		}
		clicked[region.action] = true
	}
	for _, action := range []agentDashboardAction{agentDashboardActionSelectPane, agentDashboardActionConnectRelay} {
		if !clicked[action] {
			t.Fatalf("action %d has no clickable region, so this test would not cover it", action)
		}
	}
}

func TestDashboardMouseStillWorks(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
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

func TestDashboardThemes(t *testing.T) {
	for _, name := range []string{DefaultDashboardTheme, "amber", "green"} {
		if err := ValidateDashboardTheme(name); err != nil {
			t.Errorf("theme %q: %v", name, err)
		}
	}
	for _, name := range []string{"purple", ""} {
		checkDashboardThemeRejected(t, name)
	}

	amber := newAgentDashboardTheme("amber", agentDashboardTerminal{})
	green := newAgentDashboardTheme("green", agentDashboardTerminal{})
	if amber.text.GetForeground() == green.text.GetForeground() {
		t.Error("the palettes must differ")
	}
}

func checkDashboardThemeRejected(t *testing.T, name string) {
	t.Helper()
	err := ValidateDashboardTheme(name)
	if err == nil {
		t.Fatalf("theme %q must be rejected", name)
	}
	for _, want := range []string{fmt.Sprintf("%q", name), "amber", "green"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %s", err, want)
		}
	}
}

func TestDetectAgentDashboardTerminal(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want agentDashboardTerminal
	}{
		{"UTF-8 xterm", map[string]string{"TERM": "xterm-256color", "LANG": "en_US.UTF-8"}, agentDashboardTerminal{unicode: true}},
		{"no TERM is not a reason to fall back", map[string]string{"LANG": "C.UTF-8"}, agentDashboardTerminal{unicode: true}},
		{"dumb terminal", map[string]string{"TERM": "dumb", "LANG": "en_US.UTF-8"}, agentDashboardTerminal{}},
		{"Linux console", map[string]string{"TERM": "linux", "LANG": "en_US.UTF-8"}, agentDashboardTerminal{}},
		{"C locale", map[string]string{"TERM": "xterm", "LANG": "C"}, agentDashboardTerminal{}},
		{"locale not set", map[string]string{"TERM": "xterm"}, agentDashboardTerminal{}},
		{"LC_ALL beats LANG", map[string]string{"TERM": "xterm", "LC_ALL": "C", "LANG": "en_US.UTF-8"}, agentDashboardTerminal{}},
		{"LC_ALL says UTF-8", map[string]string{"TERM": "xterm", "LC_ALL": "en_US.utf8", "LANG": "C"}, agentDashboardTerminal{unicode: true}},
		{"LC_CTYPE beats LANG", map[string]string{"TERM": "xterm", "LC_CTYPE": "C.UTF-8", "LANG": "C"}, agentDashboardTerminal{unicode: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, name := range []string{"TERM", "LC_ALL", "LC_CTYPE", "LANG"} {
				t.Setenv(name, tt.env[name])
			}
			if got := detectAgentDashboardTerminal(); got != tt.want {
				t.Fatalf("detectAgentDashboardTerminal() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
