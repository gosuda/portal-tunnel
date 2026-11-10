package agent

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestDashboardAccessDropsTheSecretWhenItsJobIsDone(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	status := testAccessStatus()
	typeIt := []tea.Msg{keyUp, keyRunes(fakeSecret), keyF3}

	t.Run("after a successful apply", func(t *testing.T) {
		checkSecretDroppedAfterApply(t, theme, status, typeIt)
	})

	t.Run("after cancel", func(t *testing.T) {
		checkSecretDroppedAfterCancel(t, theme, status, typeIt)
	})

	t.Run("when the tunnel goes away", func(t *testing.T) {
		checkSecretDroppedAfterTunnelGone(t, theme, status, typeIt)
	})

	t.Run("when the mode changes back to the stored one", func(t *testing.T) {
		model := accessScreen(t, theme, status, accessWeb, typeIt...)
		checkAccessSecretNowhere(t, press1(model, keyDown, keyLeft, keyRight))
	})

	t.Run("when the mode changes between two others", func(t *testing.T) {
		model := accessScreen(t, theme, status, accessOpen, keyRight, keyRight, keyRight, keyUp, keyRunes(fakeSecret), keyF3)
		checkAccessSecretNowhere(t, press1(model, keyDown, keyLeft, keyRight))
	})
}

func accessSecretShown(model agentDashboardModel) string {
	return press1(model, keyF4, keyUp, keyF3).View()
}

func checkAccessSecretNowhere(t *testing.T, model agentDashboardModel) {
	t.Helper()
	model = press1(model, keyUp)
	for _, view := range []string{model.View(), press1(model, keyF3).View()} {
		if strings.Contains(view, fakeSecret) {
			t.Fatalf("the secret survived a change of mode:\n%s", view)
		}
	}
}

func checkSecretDroppedAfterApply(t *testing.T, theme agentDashboardTheme, status AgentStatusResponse, typeIt []tea.Msg) {
	t.Helper()
	model := send(press1(accessScreen(t, theme, status, accessWeb, typeIt...), keyF2), agentDashboardAccessMsg{tunnelID: "web"})
	if view := model.View(); strings.Contains(view, fakeSecret) || strings.Contains(view, "Secret (shown)") || !strings.Contains(view, "set; type to replace") {
		t.Fatalf("the secret and the reveal should be gone after a successful apply:\n%s", view)
	}
	if view := press1(model, keyF3).View(); strings.Contains(view, fakeSecret) {
		t.Fatalf("revealing after an apply must not bring the secret back:\n%s", view)
	}
}

func checkSecretDroppedAfterCancel(t *testing.T, theme agentDashboardTheme, status AgentStatusResponse, typeIt []tea.Msg) {
	t.Helper()
	model := press1(accessScreen(t, theme, status, accessWeb, typeIt...), keyEsc)
	if strings.Contains(model.View(), "ACCESS:") {
		t.Fatal("esc should close the screen")
	}
	if model.access.secret.Value() != "" {
		t.Fatal("the secret must be gone as soon as the screen closes, not only when it opens again")
	}
	if view := accessSecretShown(model); strings.Contains(view, fakeSecret) {
		t.Fatalf("the secret survived a cancel:\n%s", view)
	}
	if view := press1(model, keyF4, keyUp, keyRunes("typed-after-cancel")).View(); strings.Contains(view, "typed-after-cancel") {
		t.Fatalf("a cancel must end the reveal:\n%s", view)
	}
}

func checkSecretDroppedAfterTunnelGone(t *testing.T, theme agentDashboardTheme, status AgentStatusResponse, typeIt []tea.Msg) {
	t.Helper()
	model := accessScreen(t, theme, status, accessWeb, typeIt...)
	gone := testAccessStatus()
	gone.Tunnels = gone.Tunnels[1:]
	model = send(model, agentDashboardStatusMsg{status: gone})
	if strings.Contains(model.View(), "ACCESS:") {
		t.Fatal("the screen of a tunnel that no longer exists must close")
	}
	if model.access.secret.Value() != "" {
		t.Fatal("the secret must be gone as soon as the screen closes")
	}
	model = send(model, agentDashboardStatusMsg{status: status})
	if view := accessSecretShown(model); strings.Contains(view, fakeSecret) {
		t.Fatalf("the secret survived the tunnel going away:\n%s", view)
	}
}

func TestDashboardAccessKeyBar(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	load := agentDashboardStatusMsg{status: testAccessStatus()}
	opened := func(keys ...tea.Msg) []tea.Msg { return append([]tea.Msg{load, keyF4}, keys...) }
	tests := []struct {
		name  string
		width int
		steps []tea.Msg
		want  []string
		not   []string
	}{
		{"tunnels", 140, []tea.Msg{load}, []string{"F4/s Access"}, nil},
		{"settings", 140, []tea.Msg{load, keyRight}, []string{"F4 Access"}, []string{"F4/s"}},
		{"relays", 140, []tea.Msg{load, keyRight, keyRight}, []string{"F4/s Access"}, nil},
		{"add tunnel form", 140, []tea.Msg{load, keyF2}, nil, []string{"Access"}},
		{"access, mode row", 140, opened(), []string{"F2/Enter Apply", "Esc Cancel", "Tab/S-Tab Field", "←/→ Change", "F10/^C Quit"}, []string{"Show", "Remove", "Clear", "Add entry", "Pane"}},
		{"access, entry row", 140, opened(keyDown), []string{"Del/Bksp Remove", "F2/Enter Apply"}, []string{"Change", "Show"}},
		{"access, entry input", 140, opened(downs(4)...), []string{"Enter Add entry", "F2 Apply"}, []string{"Enter/F2", "F2/Enter", "Remove"}},
		{"access, headers row", 140, opened(downs(5)...), []string{"←/→ Change"}, []string{"Show"}},
		{"access, secret row with a stored secret", 140, opened(keyUp), []string{"F3/^R Show", "F6/^X Clear", "Tab/S-Tab Field"}, []string{"Change"}},
		{"access, secret row at 80 columns", 80, opened(keyUp), []string{"F2/Enter Apply", "Esc Cancel", "F3/^R Show", "F6/^X Clear", "F10/^C Quit"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bar := lastLine(newTestDashboard(t, theme, tt.width, 40, tt.steps...).View())
			checkKeyBarLists(t, bar, tt.want)
			checkKeyBarOmits(t, bar, tt.not)
		})
	}
	checkKeyBarHidesClear(t, theme)
}

func checkKeyBarLists(t *testing.T, bar string, want []string) {
	t.Helper()
	for _, want := range want {
		if !strings.Contains(bar, want) {
			t.Errorf("key bar %q lacks %q", bar, want)
		}
	}
}

func checkKeyBarOmits(t *testing.T, bar string, not []string) {
	t.Helper()
	for _, not := range not {
		if strings.Contains(bar, not) {
			t.Errorf("key bar %q must not list %q here", bar, not)
		}
	}
}

func checkKeyBarHidesClear(t *testing.T, theme agentDashboardTheme) {
	t.Helper()
	if bar := lastLine(accessScreen(t, theme, testAccessStatus(), accessIdle, keyUp).View()); strings.Contains(bar, "Clear") {
		t.Errorf("key bar %q offers to clear a secret that is not stored", bar)
	}
}

func TestDashboardAccessKeys(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	load := agentDashboardStatusMsg{status: testAccessStatus()}

	for _, tt := range []struct {
		pane  string
		steps []tea.Msg
		keys  []tea.KeyMsg
	}{
		{"tunnels", []tea.Msg{load}, []tea.KeyMsg{keyF4, keyRunes("s")}},
		{"relays", []tea.Msg{load, keyRight, keyRight}, []tea.KeyMsg{keyF4, keyRunes("s")}},
		{"settings", []tea.Msg{load, keyRight}, []tea.KeyMsg{keyF4}},
	} {
		checkAccessOpensFromPane(t, theme, tt.pane, tt.steps, tt.keys)
	}
	settings := newTestDashboard(t, theme, 100, 40, load, keyRight)
	if typed := press1(settings, keyRunes("s")); strings.Contains(typed.View(), "ACCESS:") {
		t.Error("s in the Settings pane must be typed, not open the Access screen")
	}

	model := accessScreen(t, theme, testAccessStatus(), accessWeb)
	checkAccessKeysStayOnScreen(t, model)
	checkAccessKeysQuit(t, model)

	typing := accessScreen(t, theme, testAccessStatus(), accessWeb, keyUp, keyRunes("qs"))
	if _, cmd := press(typing, keyRunes("q")); isQuit(cmd) {
		t.Error("q belongs to the focused input on the Access screen")
	}
}

func checkAccessOpensFromPane(t *testing.T, theme agentDashboardTheme, pane string, steps []tea.Msg, keys []tea.KeyMsg) {
	t.Helper()
	for _, key := range keys {
		model := newTestDashboard(t, theme, 100, 40, steps...)
		if opened := press1(model, key); !strings.Contains(opened.View(), "ACCESS: web") {
			t.Errorf("%s should open the Access screen from the %s pane", key, pane)
		}
	}
}

func checkAccessKeysStayOnScreen(t *testing.T, model agentDashboardModel) {
	t.Helper()
	for _, key := range []tea.KeyMsg{keyRunes("q"), keyRunes("a"), keyRunes("s"), keyTab, keyRight, keyF8} {
		pressed, cmd := press(model, key)
		if isQuit(cmd) || !strings.Contains(pressed.View(), "ACCESS:") || strings.Contains(pressed.View(), "Name:") || strings.Contains(pressed.View(), "Delete tunnel") {
			t.Errorf("%s must stay on the Access screen", key)
		}
	}
}

func checkAccessKeysQuit(t *testing.T, model agentDashboardModel) {
	t.Helper()
	for _, key := range []tea.KeyMsg{keyF10, keyCtrlC} {
		if _, cmd := press(model, key); !isQuit(cmd) {
			t.Errorf("%s should still quit", key)
		}
	}
}

func TestDashboardAccessMouse(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	settings := newTestDashboard(t, theme, 100, 40, agentDashboardStatusMsg{status: testAccessStatus()}, keyRight)
	opened := clickText(t, settings, "[ Access ]", viewHas("ACCESS: web"))

	focused := clickText(t, opened, "Client secret:", viewHas("Client secret:  > "))
	if got := accessBody(t, press1(focused, keyRunes(fakeSecret))); got != `{"auth_oidc_client_secret":"`+fakeSecret+`"}` {
		t.Fatalf("typing after a click on the secret row should go into the secret input, body = %s", got)
	}

	wheeled := send(opened, tea.MouseMsg{Button: tea.MouseButtonWheelDown, Action: tea.MouseActionPress})
	if wheeled.selectedRelayURL != opened.selectedRelayURL {
		t.Fatalf("the wheel on the Access screen moved the hidden relay selection to %q", wheeled.selectedRelayURL)
	}
}

func TestDashboardAccessFollowsTheFocusInALongList(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	status := testAccessStatus()
	entries := make([]string, 30)
	for i := range entries {
		entries[i] = fmt.Sprintf("user%02d@example.com", i)
	}
	status.Tunnels[accessWeb].Allow = entries

	for _, size := range [][2]int{{80, 24}, {100, 30}} {
		model := newTestDashboard(t, theme, size[0], size[1], agentDashboardStatusMsg{status: status}, keyF4)
		for i, entry := range entries {
			model = press1(model, keyDown)
			if view := model.View(); !strings.Contains(view, ">"+entry) {
				t.Fatalf("%dx%d: entry %d is focused but not in sight:\n%s", size[0], size[1], i, view)
			}
		}
		if view := press1(model, keyDown).View(); !strings.Contains(view, "Add entry:      > ") {
			t.Fatalf("%dx%d: the entry input is focused but not in sight:\n%s", size[0], size[1], view)
		}
		if view := press1(model, keyDown, keyDown, keyDown, keyDown, keyDown).View(); !strings.Contains(view, "Client secret:  > ") {
			t.Fatalf("%dx%d: the secret row is focused but not in sight:\n%s", size[0], size[1], view)
		}
	}
}

func TestDashboardAccessRequestsAreWhatTheControlAPIStores(t *testing.T) {
	const storedSecret = "stored-fake-secret"
	app := oidcTunnel("app", unreachableIssuer, storedSecret)
	app.IdentityHeaders = true
	m, path := testManager(t, app, testTunnel("site"))
	startManager(t, m)
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	runAccessRequestSteps(t, theme, m, path, accessRequestSteps())
}

type accessRequestStep struct {
	name  string
	down  int
	keys  []tea.Msg
	check func(t *testing.T, saved TunnelConfig)
}

func accessRequestSteps() []accessRequestStep {
	const wallet = "0x52908400098527886E0F7030069857D2E4169EE7"
	typed := func(text string) tea.Msg { return keyRunes(text) }
	return []accessRequestStep{
		{"remove the stored secret and add an entry", 0, []tea.Msg{keyUp, keyF6, keyDown, keyDown, keyDown, typed("carol@example.com"), keyEnter},
			checkSavedAllowAndClearedSecret},
		{"type a secret and turn the identity headers off", 0, []tea.Msg{keyUp, typed("replacement-fake-secret"), keyUp, keyUp, keyUp, keyLeft},
			checkSavedReplacementNoHeaders},
		{"leave the stored secret alone while the issuer changes", 0, []tea.Msg{keyUp, keyUp, keyUp, typed("/")},
			checkSavedSecretIssuerChange},
		{"remove the secret", 0, []tea.Msg{keyUp, keyF6},
			checkSavedSecretRemoved},
		{"OIDC to wallet", 0, []tea.Msg{keyLeft, keyDown, typed(wallet), keyEnter},
			checkSavedWalletSwitch},
		{"wallet to credential", 0, []tea.Msg{keyLeft},
			checkSavedCredentialSwitch},
		{"credential to open", 0, []tea.Msg{keyLeft},
			checkSavedOpenSwitch},
		{"open to OIDC", 1, []tea.Msg{keyRight, keyRight, keyRight, keyDown, typed("bob@example.com"), keyEnter, keyDown, keyDown, typed(unreachableIssuer), keyDown, typed("client-1"), keyDown, typed("first-fake-secret")},
			checkSavedBackToOIDC},
	}
}

func checkSavedAllowAndClearedSecret(t *testing.T, saved TunnelConfig) {
	t.Helper()
	if !slices.Equal(saved.Allow, []string{"alice@example.com", "carol@example.com"}) || saved.OIDCClientSecret != "" {
		t.Fatalf("saved = %+v", saved)
	}
}

func checkSavedReplacementNoHeaders(t *testing.T, saved TunnelConfig) {
	t.Helper()
	if saved.OIDCClientSecret != "replacement-fake-secret" || saved.IdentityHeaders {
		t.Fatalf("saved = %+v", saved)
	}
}

func checkSavedSecretIssuerChange(t *testing.T, saved TunnelConfig) {
	t.Helper()
	if saved.OIDCClientSecret != "replacement-fake-secret" || saved.OIDCIssuerURL != unreachableIssuer+"/" {
		t.Fatalf("saved = %+v", saved)
	}
}

func checkSavedSecretRemoved(t *testing.T, saved TunnelConfig) {
	t.Helper()
	if saved.OIDCClientSecret != "" || saved.Provider != "oidc" {
		t.Fatalf("saved = %+v", saved)
	}
}

func checkSavedWalletSwitch(t *testing.T, saved TunnelConfig) {
	t.Helper()
	if saved.Provider != "siwe" || len(saved.Allow) != 1 || saved.OIDCIssuerURL != "" || saved.OIDCClientID != "" || saved.OIDCClientSecret != "" {
		t.Fatalf("saved = %+v", saved)
	}
}

func checkSavedCredentialSwitch(t *testing.T, saved TunnelConfig) {
	t.Helper()
	if saved.Provider != "credential" || len(saved.Allow) != 0 {
		t.Fatalf("saved = %+v", saved)
	}
}

func checkSavedOpenSwitch(t *testing.T, saved TunnelConfig) {
	t.Helper()
	if auth := saved.AuthConfig; !auth.IsZero() {
		t.Fatalf("saved = %+v", saved)
	}
}

func checkSavedBackToOIDC(t *testing.T, saved TunnelConfig) {
	t.Helper()
	if saved.Provider != "oidc" || saved.OIDCIssuerURL != unreachableIssuer || saved.OIDCClientID != "client-1" || saved.OIDCClientSecret != "first-fake-secret" {
		t.Fatalf("saved = %+v", saved)
	}
}

func runAccessRequestSteps(t *testing.T, theme agentDashboardTheme, m *manager, path string, steps []accessRequestStep) {
	t.Helper()
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			checkAccessRequestStep(t, theme, m, path, step)
		})
	}
}

func checkAccessRequestStep(t *testing.T, theme agentDashboardTheme, m *manager, path string, step accessRequestStep) {
	t.Helper()
	model := accessScreen(t, theme, m.Snapshot(), step.down, step.keys...)
	tunnel, _ := model.accessTunnel()
	code, resp := callControl(t, m, http.MethodPatch, types.PathAgentTunnelsPrefix+tunnel.ID, accessBody(t, model))
	if code != http.StatusAccepted {
		t.Fatalf("the control API answered %d: %s", code, resp)
	}
	step.check(t, savedTunnel(t, path, tunnel.ID))
	model = send(press1(model, keyF2), agentDashboardAccessMsg{tunnelID: tunnel.ID})
	if req := model.access.request(tunnelStatus(t, m, tunnel.ID)); !req.Empty() {
		body, _ := json.Marshal(req)
		t.Fatalf("what the agent stored differs from the draft in %s", body)
	}
	model = send(model, agentDashboardStatusMsg{status: m.Snapshot()})
	if view := model.View(); !strings.Contains(view, "ACCESS: "+tunnel.ID) || !strings.Contains(view, "( Applied )") {
		t.Fatalf("after the poll the screen should stay open and say Applied:\n%s", view)
	}
}

func TestDashboardAccessAsksBeforeStoppingTheAgent(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	model := accessScreen(t, theme, testAccessStatus(), 0, keyUp, keyRunes(fakeSecret))
	model.stopsAgent = true
	typed := accessBody(t, model)

	asked, cmd := press(model, keyF10)
	if view := asked.View(); cmd != nil || !strings.Contains(view, agentDashboardStopQuestion) || strings.Contains(view, "[ Cancel ]") {
		t.Fatalf("F10 should only ask, in place of Apply and Cancel: cmd = %v\n%s", cmd != nil, view)
	}
	for _, answer := range []tea.KeyMsg{keyRunes("n"), keyEsc, keyRunes("q"), keyF10} {
		declined, cmd := press(asked, answer)
		if cmd != nil || strings.Contains(declined.View(), agentDashboardStopQuestion) || !declined.accessing() {
			t.Fatalf("%s should keep the agent running and the Access screen open", answer)
		}
		if got := accessBody(t, declined); got != typed {
			t.Fatalf("answering %s changed what the screen would apply: %s, want %s", answer, got, typed)
		}
	}
	if _, cmd := press(asked, keyRunes("y")); !isQuit(cmd) {
		t.Fatal("y should stop the agent")
	}
	if _, cmd := press(model, keyCtrlC); !isQuit(cmd) {
		t.Fatal("ctrl+c should stop the agent at once")
	}
}
