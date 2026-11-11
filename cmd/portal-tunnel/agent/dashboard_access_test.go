package agent

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
)

var (
	keyUp    = tea.KeyMsg{Type: tea.KeyUp}
	keyEnter = tea.KeyMsg{Type: tea.KeyEnter}
	keyF3    = tea.KeyMsg{Type: tea.KeyF3}
	keyF4    = tea.KeyMsg{Type: tea.KeyF4}
	keyF6    = tea.KeyMsg{Type: tea.KeyF6}
	keyCtrlR = tea.KeyMsg{Type: tea.KeyCtrlR}
	keyCtrlX = tea.KeyMsg{Type: tea.KeyCtrlX}
	keyBksp  = tea.KeyMsg{Type: tea.KeyBackspace}
)

const fakeSecret = "not-a-real-secret-0123"

func testAccessStatus() AgentStatusResponse {
	status := testDashboardStatus()
	web, api, paid, idle := &status.Tunnels[0], &status.Tunnels[1], &status.Tunnels[2], &status.Tunnels[4]
	web.Provider = appauth.ProviderOIDC
	web.Allow = []string{"alice@example.com", "@corp.example.com", "sub:4f2a9c"}
	web.IdentityHeaders = true
	web.OIDCIssuerURL = "https://accounts.example.com"
	web.OIDCClientID = "portal-web"
	web.AuthOIDCClientSecretSet = true
	web.AuthProviderChecked = true
	web.AuthProviderError = "fetch oidc discovery: no such host"
	api.Provider = appauth.ProviderSIWE
	api.Allow = []string{"0x52908400098527886E0F7030069857D2E4169EE7"}
	paid.Provider = appauth.ProviderCredential
	idle.Provider = appauth.ProviderOIDC
	idle.Allow = []string{"bob@example.com"}
	idle.OIDCIssuerURL = "https://login.example.org"
	idle.OIDCClientID = "portal-idle"
	return status
}

func TestDashboardAccessStoredEmailPassword(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	typed := func(text string) tea.Msg { return keyRunes(text) }
	status := testAccessStatus()
	mail := &status.Tunnels[accessOpen]
	mail.Provider = appauth.ProviderEmail
	mail.EmailList = []string{"alice@example.com"}
	mail.EmailConfig = appauth.EmailConfig{SMTPAddr: "smtp.example.com:587", SMTPUsername: "portal", SMTPFrom: "login@example.com"}
	mail.AuthSMTPPasswordSet = true

	for _, step := range storedEmailPasswordCases(typed) {
		t.Run(step.name, func(t *testing.T) {
			checkStoredEmailPasswordCase(t, theme, status, step)
		})
	}
}

type storedEmailPasswordCase struct {
	name string
	keys []tea.Msg
	want string
}

func storedEmailPasswordCases(typed func(string) tea.Msg) []storedEmailPasswordCase {
	return []storedEmailPasswordCase{
		{"nothing touched", nil, `{}`},
		{"a blank password leaves the stored one alone", []tea.Msg{keyUp, keyUp, typed("   ")}, `{}`},
		{"a typed password replaces the stored one", []tea.Msg{keyUp, keyUp, typed(fakeSecret)}, `{"auth_smtp_password":"` + fakeSecret + `"}`},
		{"F6 removes the stored password", []tea.Msg{keyUp, keyUp, keyF6}, `{"auth_smtp_username":"","auth_smtp_password":""}`},
		{"F6 again takes the mark back", []tea.Msg{keyUp, keyUp, keyF6, keyF6}, `{}`},
		{"a typed password takes the mark back", []tea.Msg{keyUp, keyUp, keyF6, typed(fakeSecret)}, `{"auth_smtp_password":"` + fakeSecret + `"}`},
		{"a username typed after the mark stays", []tea.Msg{keyUp, keyUp, keyF6, keyUp, typed("bob"), keyDown, typed(fakeSecret)},
			`{"auth_smtp_username":"bob","auth_smtp_password":"` + fakeSecret + `"}`},
		{"an allow list change keeps the list key", []tea.Msg{keyDown, keyDown, typed("bob@example.com"), keyEnter},
			`{"auth_email_list":["alice@example.com","bob@example.com"]}`},
		{"leaving email clears its settings and the password", []tea.Msg{keyLeft},
			`{"auth":"saml","auth_email_list":[],"auth_smtp_addr":"","auth_smtp_username":"","auth_smtp_password":"","auth_smtp_from":""}`},
		{"turning sign-in off sends only auth", []tea.Msg{keyRight}, `{"auth":""}`},
	}
}

func checkStoredEmailPasswordCase(t *testing.T, theme agentDashboardTheme, status AgentStatusResponse, step storedEmailPasswordCase) {
	t.Helper()
	if got := accessBody(t, accessScreen(t, theme, status, accessOpen, step.keys...)); !sameJSON(t, got, step.want) {
		t.Fatalf("request body = %s\nwant           %s", got, step.want)
	}
}

func settingsOf(t *testing.T, status AgentStatusResponse, down int) string {
	t.Helper()
	steps := []tea.Msg{agentDashboardStatusMsg{status: status}}
	for range down {
		steps = append(steps, keyDown)
	}
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	return newTestDashboard(t, theme, 120, 40, append(steps, keyRight)...).View()
}

func TestDashboardSettingsShowHowEachTunnelIsProtected(t *testing.T) {
	tests := []struct {
		name string
		down int
		want []string
		not  []string
	}{
		{"OIDC", 0,
			[]string{"Access:", "OIDC", "alice@example.com", "@corp.example.com", "sub:4f2a9c", "Headers:", "on (X-Portal-User)",
				"https://accounts.example.com", "portal-web", "Client secret:", "set", "[!] failed: fetch oidc discovery: no such host"},
			[]string{"not set", "open to anyone"}},
		{"wallet", 1,
			[]string{"wallet (siwe)", "0x52908400098527886E0F7030069857D2E4169EE7", "Headers:", "off"},
			[]string{"Issuer:", "Client secret:", "Provider check:"}},
		{"credential without an allow list", 2,
			[]string{"credential", "Allowed:", "any valid credential"},
			[]string{"Issuer:"}},
		{"open", 3,
			[]string{"Access:", "open to anyone"},
			[]string{"Allowed:", "Headers:", "Issuer:"}},
		{"OIDC that is not running", 4,
			[]string{"login.example.org", "portal-idle", "not set", "[ ] not checked"},
			[]string{"failed", "checking"}},
	}
	status := testAccessStatus()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkTunnelProtectedView(t, status, tt.down, tt.want, tt.not)
		})
	}
}

func checkTunnelProtectedView(t *testing.T, status AgentStatusResponse, down int, want, not []string) {
	t.Helper()
	view := settingsOf(t, status, down)
	for _, want := range want {
		if !strings.Contains(view, want) {
			t.Errorf("the Settings pane lacks %q:\n%s", want, view)
		}
	}
	for _, not := range not {
		if strings.Contains(view, not) {
			t.Errorf("the Settings pane must not show %q:\n%s", not, view)
		}
	}
}

func TestDashboardSettingsKeepAFailedProviderCheckInSight(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	view := newTestDashboard(t, theme, 80, 24, agentDashboardStatusMsg{status: testAccessStatus()}, keyRight).View()
	if !strings.Contains(view, "OIDC [!] check failed") {
		t.Fatalf("at 80x24 the Access line must say that the provider check failed:\n%s", view)
	}
}

func TestDashboardSettingsListOnlyTheFirstEntriesOfALongAllowList(t *testing.T) {
	status := testAccessStatus()
	var entries []string
	for _, name := range []string{"a", "b", "c", "d", "e", "f"} {
		entries = append(entries, name+"@example.com")
	}
	status.Tunnels[0].Allow = entries
	view := settingsOf(t, status, 0)
	if !strings.Contains(view, "d@example.com") || strings.Contains(view, "e@example.com") || !strings.Contains(view, "+2 more") {
		t.Fatalf("the allow list should list four entries and count the rest:\n%s", view)
	}
}

func TestSettingsFocusLeavesExactlyOneInputFocused(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	model := newTestDashboard(t, theme, 100, 40, agentDashboardStatusMsg{status: testAccessStatus()}, keyRight)
	focused := func() int {
		n := 0
		for _, input := range []*textinput.Model{
			&model.settingsMaxRelays,
			&model.metadataDescription,
			&model.metadataTags,
			&model.metadataOwner,
			&model.metadataThumbnail,
			&model.metadataHide,
		} {
			if input.Focused() {
				n++
			}
		}
		return n
	}
	for i := 0; i <= agentDashboardSettingsFieldCount; i++ {
		model = press1(model, keyTab)
		if got := focused(); got != 1 {
			t.Fatalf("after %d tabs %d settings inputs hold focus, want exactly one", i+1, got)
		}
	}
}

func TestAgentDashboardProviderCheckTellsTheStatesApart(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{})
	tests := []struct {
		name   string
		tunnel AgentTunnelStatus
		want   string
	}{
		{"usable", AgentTunnelStatus{State: "running", AuthProviderChecked: true}, "[*] ok"},
		{"unusable", AgentTunnelStatus{State: "running", AuthProviderChecked: true, AuthProviderError: "no such host"}, "[!] failed"},
		{"still checking", AgentTunnelStatus{State: "running"}, "[~] checking..."},
		{"tunnel starting", AgentTunnelStatus{State: "starting"}, "[~] checking..."},
		{"tunnel not running", AgentTunnelStatus{State: "stopped"}, "[ ] not checked"},
	}
	for _, tt := range tests {
		if got, _ := agentDashboardProviderCheck(&theme, tt.tunnel); got != tt.want {
			t.Errorf("%s: check = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestAgentDashboardAllowedHintFollowsTheGatewayRules(t *testing.T) {
	for _, provider := range []string{appauth.ProviderCredential, appauth.ProviderSIWE, appauth.ProviderOIDC} {
		cfg := appauth.Config{Provider: provider}
		if provider == appauth.ProviderOIDC {
			cfg.OIDCIssuerURL, cfg.OIDCClientID = "https://accounts.example.com", "portal-web"
		}
		emptyAllowed := appauth.Validate(cfg) == nil
		hint := agentDashboardAllowedHint(provider)
		switch {
		case emptyAllowed && !strings.HasPrefix(hint, "any "):
			t.Errorf("the gateway accepts an empty %s allow list, but the hint %q does not say that anyone valid signs in", provider, hint)
		case !emptyAllowed && hint != "needs one entry":
			t.Errorf("the gateway refuses an empty %s allow list, but the hint is %q", provider, hint)
		}
		if !emptyAllowed {
			cfg.Allow = []string{"alice@example.com"}
			if err := appauth.Validate(cfg); err != nil {
				t.Fatalf("%s with one entry: %v", provider, err)
			}
		}
	}
}

const (
	accessWeb    = 0
	accessWallet = 1
	accessOpen   = 3
	accessIdle   = 4
)

func accessScreen(t *testing.T, theme agentDashboardTheme, status AgentStatusResponse, down int, keys ...tea.Msg) agentDashboardModel {
	t.Helper()
	steps := []tea.Msg{agentDashboardStatusMsg{status: status}}
	for range down {
		steps = append(steps, keyDown)
	}
	return newTestDashboard(t, theme, 100, 40, append(append(steps, keyF4), keys...)...)
}

func send(model agentDashboardModel, msg tea.Msg) agentDashboardModel {
	next, _ := model.Update(msg)
	return next.(agentDashboardModel)
}

func press1(model agentDashboardModel, keys ...tea.KeyMsg) agentDashboardModel {
	model, _ = press(model, keys...)
	return model
}

func downs(n int) []tea.Msg {
	keys := make([]tea.Msg, n)
	for i := range keys {
		keys[i] = keyDown
	}
	return keys
}

func accessBody(t *testing.T, model agentDashboardModel) string {
	t.Helper()
	tunnel, ok := model.accessTunnel()
	if !ok {
		t.Fatal("the Access screen is not open")
	}
	body, err := json.Marshal(model.access.request(tunnel))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func sameJSON(t *testing.T, a, b string) bool {
	t.Helper()
	var x, y map[string]any
	if err := json.Unmarshal([]byte(a), &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(b), &y); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(x, y)
}
