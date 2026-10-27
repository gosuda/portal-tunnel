package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/types"
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

// fakeSecret is an obviously made-up client secret; no test uses a real one.
const fakeSecret = "not-a-real-secret-0123"

// testAccessStatus is testDashboardStatus with a sign-in setting on four of its tunnels:
// web (OIDC, provider unusable), api (wallet), paid (credential, no allow list) and idle
// (OIDC that never started). site stays open. The secret exists only as a flag, as in the API.
func testAccessStatus() AgentStatusResponse {
	status := testDashboardStatus()
	web, api, paid, idle := &status.Tunnels[0], &status.Tunnels[1], &status.Tunnels[2], &status.Tunnels[4]
	web.Auth = gateway.ApplicationAuthProviderOIDC
	web.AuthAllowedWallets = []string{"alice@example.com", "@corp.example.com", "sub:4f2a9c"}
	web.AuthIdentityHeaders = true
	web.AuthOIDCIssuer = "https://accounts.example.com"
	web.AuthOIDCClientID = "portal-web"
	web.AuthOIDCClientSecretSet = true
	web.AuthOIDCProviderChecked = true
	web.AuthOIDCProviderError = "fetch oidc discovery: no such host"
	api.Auth = gateway.ApplicationAuthProviderSIWE
	api.AuthAllowedWallets = []string{"0x52908400098527886E0F7030069857D2E4169EE7"}
	paid.Auth = gateway.ApplicationAuthProviderCredential
	idle.Auth = gateway.ApplicationAuthProviderOIDC
	idle.AuthAllowedWallets = []string{"bob@example.com"}
	idle.AuthOIDCIssuer = "https://login.example.org"
	idle.AuthOIDCClientID = "portal-idle"
	return status
}

// settingsOf shows the Settings pane of the tunnel that is down tunnels from the first one.
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
			view := settingsOf(t, status, tt.down)
			for _, want := range tt.want {
				if !strings.Contains(view, want) {
					t.Errorf("the Settings pane lacks %q:\n%s", want, view)
				}
			}
			for _, not := range tt.not {
				if strings.Contains(view, not) {
					t.Errorf("the Settings pane must not show %q:\n%s", not, view)
				}
			}
		})
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
	status.Tunnels[0].AuthAllowedWallets = entries
	view := settingsOf(t, status, 0)
	if !strings.Contains(view, "d@example.com") || strings.Contains(view, "e@example.com") || !strings.Contains(view, "+2 more") {
		t.Fatalf("the allow list should list four entries and count the rest:\n%s", view)
	}
}

func TestAgentDashboardProviderCheckTellsTheStatesApart(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{})
	tests := []struct {
		name   string
		tunnel AgentTunnelStatus
		want   string
	}{
		{"usable", AgentTunnelStatus{State: "running", AuthOIDCProviderChecked: true}, "[*] ok"},
		{"unusable", AgentTunnelStatus{State: "running", AuthOIDCProviderChecked: true, AuthOIDCProviderError: "no such host"}, "[!] failed"},
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

// The wording of an empty allow list repeats a rule of the gateway, so it is checked against the
// gateway's own validator.
func TestAgentDashboardAllowedHintFollowsTheGatewayRules(t *testing.T) {
	for _, provider := range []string{gateway.ApplicationAuthProviderCredential, gateway.ApplicationAuthProviderSIWE, gateway.ApplicationAuthProviderOIDC} {
		cfg := gateway.ApplicationAuthConfig{Provider: provider}
		if provider == gateway.ApplicationAuthProviderOIDC {
			cfg.OIDCIssuerURL, cfg.OIDCClientID = "https://accounts.example.com", "portal-web"
		}
		emptyAllowed := gateway.ValidateApplicationAuthConfig(cfg) == nil
		hint := agentDashboardAllowedHint(provider)
		switch {
		case emptyAllowed && !strings.HasPrefix(hint, "any "):
			t.Errorf("the gateway accepts an empty %s allow list, but the hint %q does not say that anyone valid signs in", provider, hint)
		case !emptyAllowed && hint != "needs one entry":
			t.Errorf("the gateway refuses an empty %s allow list, but the hint is %q", provider, hint)
		}
		if !emptyAllowed {
			// The refusal must be about the empty list and nothing else.
			cfg.AllowedWallets = []string{"alice@example.com"}
			if err := gateway.ValidateApplicationAuthConfig(cfg); err != nil {
				t.Fatalf("%s with one entry: %v", provider, err)
			}
		}
	}
}

// The tunnels of testAccessStatus, by their distance from the first one.
const (
	accessWeb    = 0 // OIDC with three entries and a stored secret; the focus ring is mode, entries 1-3, add 4, headers 5, issuer 6, client ID 7, secret 8
	accessWallet = 1
	accessOpen   = 3
	accessIdle   = 4 // OIDC without a stored secret
)

// accessScreen opens the Access screen of the tunnel that is down tunnels from the first one and
// then replays keys on it.
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

// press1 is press without the command.
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

// accessBody is the JSON body of the PATCH that applying the open Access screen sends.
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

func TestNewSecretInputMasksByDefault(t *testing.T) {
	for _, tt := range []struct {
		term agentDashboardTerminal
		mask string
	}{
		{agentDashboardTerminal{unicode: true}, "•"},
		{agentDashboardTerminal{}, "*"},
	} {
		theme := newAgentDashboardTheme("amber", tt.term)
		input := theme.newSecretInput()
		input.SetValue(fakeSecret)
		if view := input.View(); strings.Contains(view, fakeSecret) || !strings.Contains(view, strings.Repeat(tt.mask, len(fakeSecret))) {
			t.Fatalf("a new secret input must mask what it holds with %q: %q", tt.mask, view)
		}
	}
}

// A secret usually arrives by paste, which the terminal delivers as one key message.
func TestDashboardAccessMasksAPastedSecret(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	paste := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(fakeSecret), Paste: true}
	model := accessScreen(t, theme, testAccessStatus(), accessWeb, keyUp, paste)
	if view := model.View(); strings.Contains(view, fakeSecret) || !strings.Contains(view, strings.Repeat("•", len(fakeSecret))) {
		t.Fatalf("a pasted secret must be masked:\n%s", view)
	}
	if got := accessBody(t, model); got != `{"auth_oidc_client_secret":"`+fakeSecret+`"}` {
		t.Fatalf("request body = %s", got)
	}
}

func TestDashboardAccessSecretIsMaskedUntilRevealed(t *testing.T) {
	for _, tt := range []struct {
		name string
		term agentDashboardTerminal
		mask string
	}{
		{"unicode", agentDashboardTerminal{unicode: true}, "•"},
		{"ascii fallback", agentDashboardTerminal{}, "*"},
	} {
		for _, reveal := range []tea.KeyMsg{keyF3, keyCtrlR} {
			t.Run(tt.name+" "+reveal.String(), func(t *testing.T) {
				theme := newAgentDashboardTheme("amber", tt.term)
				model := accessScreen(t, theme, testAccessStatus(), accessWeb, keyUp, keyRunes(fakeSecret))
				if view := model.View(); strings.Contains(view, fakeSecret) || !strings.Contains(view, strings.Repeat(tt.mask, len(fakeSecret))) {
					t.Fatalf("the secret must show as %d mask glyphs and nothing else:\n%s", len(fakeSecret), view)
				}

				model = press1(model, reveal)
				if view := model.View(); !strings.Contains(view, fakeSecret) || !strings.Contains(view, "Secret (shown)") {
					t.Fatalf("%s should reveal what was typed:\n%s", reveal, view)
				}

				model = press1(model, reveal)
				if view := model.View(); strings.Contains(view, fakeSecret) || strings.Contains(view, "Secret (shown)") {
					t.Fatalf("%s again should hide the secret:\n%s", reveal, view)
				}
			})
		}
	}
}

func TestDashboardAccessShowsAStoredSecretOnlyAsSet(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	withSecret := accessScreen(t, theme, testAccessStatus(), accessWeb, keyUp)
	for _, model := range []agentDashboardModel{withSecret, press1(withSecret, keyF3)} {
		if view := model.View(); !strings.Contains(view, "set; type to replace") || strings.Contains(view, "not set") {
			t.Fatalf("a stored secret must show as set, revealed or not:\n%s", view)
		}
	}
	if view := press1(withSecret, keyF6).View(); !strings.Contains(view, "will be removed") {
		t.Fatalf("a stored secret marked for removal must say so:\n%s", view)
	}
	if view := accessScreen(t, theme, testAccessStatus(), accessIdle, keyUp).View(); !strings.Contains(view, "not set") {
		t.Fatalf("a tunnel without a secret must show it as not set:\n%s", view)
	}
}

func TestDashboardAccessShowsWhyTheProviderCheckFailed(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	view := accessScreen(t, theme, testAccessStatus(), accessWeb).View()
	for _, want := range []string{"Provider check:", "[!] failed", "fetch oidc discovery: no such host", "restarts this tunnel"} {
		if !strings.Contains(view, want) {
			t.Fatalf("the Access screen lacks %q:\n%s", want, view)
		}
	}
	if view := accessScreen(t, theme, testAccessStatus(), accessIdle).View(); !strings.Contains(view, "[ ] not checked") {
		t.Fatalf("a tunnel that has not been checked says so:\n%s", view)
	}
}

func TestDashboardAccessRequestNamesOnlyWhatChanged(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	typed := func(text string) tea.Msg { return keyRunes(text) }
	tests := []struct {
		name string
		down int
		keys []tea.Msg
		want string
	}{
		{"nothing touched", accessWeb, nil, `{}`},
		{"only the secret", accessWeb, []tea.Msg{keyUp, typed(fakeSecret)}, `{"auth_oidc_client_secret":"` + fakeSecret + `"}`},
		{"a blank secret leaves the stored one alone", accessWeb, []tea.Msg{keyUp, typed("   ")}, `{}`},
		{"an empty secret input leaves the stored secret out of an allow list change", accessWeb,
			append(downs(4), typed("Carol@Example.com"), keyEnter),
			`{"auth_allowed_wallets":["alice@example.com","@corp.example.com","sub:4f2a9c","carol@example.com"]}`},
		{"first entry removed", accessWeb, []tea.Msg{keyDown, keyDelete}, `{"auth_allowed_wallets":["@corp.example.com","sub:4f2a9c"]}`},
		{"every entry removed is an empty list, not null", accessWeb, []tea.Msg{keyDown, keyDelete, keyBksp, keyDelete}, `{"auth_allowed_wallets":[]}`},
		{"identity headers turned off", accessWeb, append(downs(5), keyLeft), `{"auth_identity_headers":false}`},
		{"client ID edited", accessWeb, append(downs(7), typed("-2")), `{"auth_oidc_client_id":"portal-web-2"}`},
		{"stored secret removed", accessWeb, []tea.Msg{keyUp, keyF6}, `{"auth_oidc_client_secret":""}`},
		{"stored secret removed with ctrl+x", accessWeb, []tea.Msg{keyUp, keyCtrlX}, `{"auth_oidc_client_secret":""}`},
		{"a typed secret replaces a removal", accessWeb, []tea.Msg{keyUp, keyF6, typed(fakeSecret)}, `{"auth_oidc_client_secret":"` + fakeSecret + `"}`},
		{"typing takes the removal back, and so does erasing what was typed", accessWeb, []tea.Msg{keyUp, keyF6, typed("x"), keyBksp}, `{}`},
		{"a removal drops the secret typed before it", accessWeb, []tea.Msg{keyUp, typed(fakeSecret), keyF6}, `{"auth_oidc_client_secret":""}`},
		{"a removal that is asked for twice is off", accessWeb, []tea.Msg{keyUp, keyF6, keyF6}, `{}`},
		{"a round trip through another provider restores what is stored", accessWeb, []tea.Msg{keyLeft, keyRight}, `{}`},
		{"OIDC to wallet clears the OIDC settings and the allow list", accessWeb, []tea.Msg{keyLeft},
			`{"auth":"siwe","auth_allowed_wallets":[],"auth_oidc_issuer":"","auth_oidc_client_id":"","auth_oidc_client_secret":""}`},
		{"leaving OIDC without a stored secret does not name it", accessIdle, []tea.Msg{keyLeft},
			`{"auth":"siwe","auth_allowed_wallets":[],"auth_oidc_issuer":"","auth_oidc_client_id":""}`},
		{"OIDC to open sends only auth", accessWeb, []tea.Msg{keyRight}, `{"auth":""}`},
		{"open to credential", accessOpen, []tea.Msg{keyRight}, `{"auth":"credential"}`},
		{"wallet to OIDC", accessWallet,
			[]tea.Msg{keyRight, keyDown, typed("carol@example.com"), keyEnter, keyDown, keyDown, typed("https://idp.example.org"), keyDown, typed("client-1"), keyDown, typed(fakeSecret)},
			`{"auth":"oidc","auth_allowed_wallets":["carol@example.com"],"auth_oidc_issuer":"https://idp.example.org","auth_oidc_client_id":"client-1","auth_oidc_client_secret":"` + fakeSecret + `"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := accessScreen(t, theme, testAccessStatus(), tt.down, tt.keys...)
			if got := accessBody(t, model); got != tt.want {
				t.Fatalf("request body = %s\nwant           %s", got, tt.want)
			}
			applied, cmd := press(model, keyF2)
			if (cmd != nil) != (tt.want != `{}`) {
				t.Fatalf("F2 sent a request = %v for the body %s", cmd != nil, tt.want)
			}
			if strings.Contains(applied.View(), "Error:") {
				t.Fatalf("applying must not fail before it is sent:\n%s", applied.View())
			}
		})
	}
}

func TestDashboardAccessEntries(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})

	t.Run("an entry is normalized, a duplicate is not added twice", func(t *testing.T) {
		model := accessScreen(t, theme, testAccessStatus(), accessWeb, append(downs(4), keyRunes("Carol@Example.COM"), keyEnter, keyRunes("CAROL@example.com"), keyEnter)...)
		if view := model.View(); !strings.Contains(view, "carol@example.com") || !strings.Contains(view, "4 entries") {
			t.Fatalf("the entry should be added once, in its normal form:\n%s", view)
		}
	})

	t.Run("a wrong entry is refused on the spot and stays typed", func(t *testing.T) {
		model := accessScreen(t, theme, testAccessStatus(), accessWallet, keyDown, keyDown, keyRunes("nope"), keyEnter)
		view := model.View()
		if !strings.Contains(view, "address must start with 0x") || !strings.Contains(view, "1 entry") || !strings.Contains(view, "nope") {
			t.Fatalf("the gateway's refusal should show, the list stay as it is and the text stay typed:\n%s", view)
		}
	})

	t.Run("an emptied list says what that means for the provider", func(t *testing.T) {
		if view := accessScreen(t, theme, testAccessStatus(), accessWeb, keyDown, keyDelete, keyDelete, keyDelete).View(); !strings.Contains(view, "needs one entry") {
			t.Fatalf("an OIDC tunnel without entries should say it needs one:\n%s", view)
		}
		if view := accessScreen(t, theme, testAccessStatus(), accessWallet, keyDown, keyDelete).View(); !strings.Contains(view, "any wallet") {
			t.Fatalf("a wallet tunnel without entries should say any wallet signs in:\n%s", view)
		}
	})

	t.Run("enter on the entry input adds and never applies, F2 applies", func(t *testing.T) {
		model := accessScreen(t, theme, testAccessStatus(), accessWeb, append(downs(4), keyRunes("carol@example.com"))...)
		for _, key := range []tea.KeyMsg{keyEnter, keyEnter} {
			var cmd tea.Cmd
			if model, cmd = press(model, key); cmd != nil {
				t.Fatal("enter on the entry input must not send a request")
			}
		}
		if _, cmd := press(model, keyF2); cmd == nil {
			t.Fatal("F2 should apply the added entry")
		}
	})
}

func TestDashboardAccessApply(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	untouched := accessScreen(t, theme, testAccessStatus(), accessWeb)
	for _, key := range []tea.KeyMsg{keyF2, keyEnter} {
		if _, cmd := press(untouched, key); cmd != nil {
			t.Fatalf("%s with nothing changed must not send a request", key)
		}
	}
	// Nothing has been applied on a screen that was just opened, so its disabled button
	// does not claim that.
	if view := untouched.View(); !strings.Contains(view, "( Apply )") || strings.Contains(view, "Applied") {
		t.Fatalf("an untouched draft shows a disabled Apply button:\n%s", view)
	}

	changed := press1(untouched, keyUp, keyRunes(fakeSecret))
	for _, key := range []tea.KeyMsg{keyF2, keyEnter} {
		if _, cmd := press(changed, key); cmd == nil {
			t.Fatalf("%s should send the request", key)
		}
	}
	if _, cmd := clickAction(t, changed, agentDashboardActionApplyAccess); cmd == nil {
		t.Fatal("the Apply button should send the request")
	}
	if closed, _ := clickAction(t, changed, agentDashboardActionCancelAccess); strings.Contains(closed.View(), "ACCESS:") {
		t.Fatal("the Cancel button should close the screen")
	}
}

func TestDashboardAccessSaysAppliedOnceThePollShowsTheNewSettings(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	added := testAccessStatus()
	added.Tunnels[accessWeb].AuthAllowedWallets = append(added.Tunnels[accessWeb].AuthAllowedWallets, "carol@example.com")

	model := accessScreen(t, theme, testAccessStatus(), accessWeb, append(downs(4), keyRunes("carol@example.com"), keyEnter)...)
	model = send(model, agentDashboardAccessMsg{tunnelID: "web"})
	if view := model.View(); !strings.Contains(view, "[ Apply ]") || strings.Contains(view, "Applied") {
		t.Fatalf("before the poll brings the new settings the draft still differs from what is stored:\n%s", view)
	}
	model = send(model, agentDashboardStatusMsg{status: added})
	view := model.View()
	if !strings.Contains(view, "( Applied )") || !strings.Contains(view, "carol@example.com") || strings.Contains(view, "Error:") {
		t.Fatalf("once the poll brings the new settings the screen says Applied and keeps them:\n%s", view)
	}

	// What was just applied is the new base: a further edit survives the polls that follow.
	model = press1(model, keyRunes("erin@example.com"), keyEnter)
	view = send(model, agentDashboardStatusMsg{status: added}).View()
	if !strings.Contains(view, "erin@example.com") || strings.Contains(view, "changed elsewhere") {
		t.Fatalf("an edit made after an apply must survive the next poll:\n%s", view)
	}
}

// The PATCH names what differs from the stored settings, so a draft that went stale would put
// its old values back over a change made through config.toml, the CLI or another dashboard.
func TestDashboardAccessShowsAChangeMadeElsewhere(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	elsewhere := testAccessStatus()
	elsewhere.Tunnels[accessWeb].AuthAllowedWallets = []string{"alice@example.com", "dave@example.com"}
	elsewhere.Tunnels[accessWeb].AuthOIDCClientID = "portal-web-2"

	for _, tt := range []struct {
		name string
		keys []tea.Msg
	}{
		{"an untouched draft", nil},
		{"an edited draft", append(downs(4), keyRunes("carol@example.com"), keyEnter)},
		{"a typed secret", []tea.Msg{keyUp, keyRunes(fakeSecret), keyF3}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			model := accessScreen(t, theme, testAccessStatus(), accessWeb, tt.keys...)
			model = send(model, agentDashboardStatusMsg{status: elsewhere})
			view := model.View()
			for _, want := range []string{"ACCESS: web", "changed elsewhere", "dave@example.com", "portal-web-2"} {
				if !strings.Contains(view, want) {
					t.Fatalf("the screen should show the stored settings again, lacking %q:\n%s", want, view)
				}
			}
			for _, not := range []string{"carol@example.com", fakeSecret} {
				if strings.Contains(view, not) {
					t.Fatalf("what was edited before the change must be dropped, found %q:\n%s", not, view)
				}
			}
			if _, cmd := press(model, keyF2); cmd != nil {
				t.Fatal("applying right after the refresh must not send the old values back")
			}
		})
	}

	t.Run("a poll that changes nothing", func(t *testing.T) {
		model := accessScreen(t, theme, testAccessStatus(), accessWeb, append(downs(4), keyRunes("carol@example.com"), keyEnter)...)
		view := send(model, agentDashboardStatusMsg{status: testAccessStatus()}).View()
		if !strings.Contains(view, "carol@example.com") || strings.Contains(view, "changed elsewhere") {
			t.Fatalf("an edited draft must survive a poll that brings nothing new:\n%s", view)
		}
	})
}

func TestDashboardAccessShowsTheServerErrorInline(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	const refusal = "invalid_request: oidc client id is required"
	model := accessScreen(t, theme, testAccessStatus(), accessWeb, keyUp, keyRunes(fakeSecret))
	model = send(model, agentDashboardAccessMsg{tunnelID: "web", err: errors.New(refusal)})

	view := model.View()
	if !strings.Contains(view, "Error: "+refusal) || !strings.Contains(view, "ACCESS: web") {
		t.Fatalf("the refusal should show inside the Access screen:\n%s", view)
	}
	// The status poll that follows every answer must not wipe it.
	model = send(model, agentDashboardStatusMsg{status: testAccessStatus()})
	if !strings.Contains(model.View(), "Error: "+refusal) {
		t.Fatalf("the next status poll must not remove the refusal:\n%s", model.View())
	}
	// A refused draft keeps the secret so that the rest can be corrected.
	if view := press1(model, keyF3).View(); !strings.Contains(view, fakeSecret) {
		t.Fatalf("a refused apply must keep the typed secret:\n%s", view)
	}
	if _, cmd := press(model, keyF2); cmd == nil {
		t.Fatal("the draft can be applied again")
	}
}

func TestDashboardAccessDropsTheSecretWhenItsJobIsDone(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	status := testAccessStatus()
	typeIt := []tea.Msg{keyUp, keyRunes(fakeSecret), keyF3}

	// secretShown reopens the screen for web, reveals the secret input and reports what it shows.
	secretShown := func(model agentDashboardModel) string {
		return press1(model, keyF4, keyUp, keyF3).View()
	}
	// secretNowhere looks at the secret row of an open screen as it is and revealed, since a
	// leftover secret may sit behind either.
	secretNowhere := func(t *testing.T, model agentDashboardModel) {
		t.Helper()
		model = press1(model, keyUp)
		for _, view := range []string{model.View(), press1(model, keyF3).View()} {
			if strings.Contains(view, fakeSecret) {
				t.Fatalf("the secret survived a change of mode:\n%s", view)
			}
		}
	}

	t.Run("after a successful apply", func(t *testing.T) {
		model := send(accessScreen(t, theme, status, accessWeb, typeIt...), agentDashboardAccessMsg{tunnelID: "web"})
		if view := model.View(); strings.Contains(view, fakeSecret) || strings.Contains(view, "Secret (shown)") || !strings.Contains(view, "set; type to replace") {
			t.Fatalf("the secret and the reveal should be gone after a successful apply:\n%s", view)
		}
		if view := press1(model, keyF3).View(); strings.Contains(view, fakeSecret) {
			t.Fatalf("revealing after an apply must not bring the secret back:\n%s", view)
		}
	})

	t.Run("after cancel", func(t *testing.T) {
		model := press1(accessScreen(t, theme, status, accessWeb, typeIt...), keyEsc)
		if strings.Contains(model.View(), "ACCESS:") {
			t.Fatal("esc should close the screen")
		}
		if model.access.secret.Value() != "" {
			t.Fatal("the secret must be gone as soon as the screen closes, not only when it opens again")
		}
		if view := secretShown(model); strings.Contains(view, fakeSecret) {
			t.Fatalf("the secret survived a cancel:\n%s", view)
		}
		// What is typed next is hidden again: a cancel also ends the reveal.
		if view := press1(model, keyF4, keyUp, keyRunes("typed-after-cancel")).View(); strings.Contains(view, "typed-after-cancel") {
			t.Fatalf("a cancel must end the reveal:\n%s", view)
		}
	})

	t.Run("when the tunnel goes away", func(t *testing.T) {
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
		if view := secretShown(model); strings.Contains(view, fakeSecret) {
			t.Fatalf("the secret survived the tunnel going away:\n%s", view)
		}
	})

	t.Run("when the mode changes back to the stored one", func(t *testing.T) {
		model := accessScreen(t, theme, status, accessWeb, typeIt...)
		// Down wraps to the mode row, left leaves OIDC and right comes back to it.
		secretNowhere(t, press1(model, keyDown, keyLeft, keyRight))
	})

	t.Run("when the mode changes between two others", func(t *testing.T) {
		// site has no sign-in, so OIDC is not what is stored: three steps right reach it, and the
		// secret typed there must not outlive a visit to the wallet mode.
		model := accessScreen(t, theme, status, accessOpen, keyRight, keyRight, keyRight, keyUp, keyRunes(fakeSecret), keyF3)
		secretNowhere(t, press1(model, keyDown, keyLeft, keyRight))
	})
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
		// At the minimum width the row's own keys stay and the field keys give way.
		{"access, secret row at 80 columns", 80, opened(keyUp), []string{"F2/Enter Apply", "Esc Cancel", "F3/^R Show", "F6/^X Clear", "F10/^C Quit"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bar := lastLine(newTestDashboard(t, theme, tt.width, 40, tt.steps...).View())
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

	if bar := lastLine(accessScreen(t, theme, testAccessStatus(), accessIdle, keyUp).View()); strings.Contains(bar, "Clear") {
		t.Errorf("key bar %q offers to clear a secret that is not stored", bar)
	}
}

func TestDashboardAccessKeys(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	load := agentDashboardStatusMsg{status: testAccessStatus()}

	// Both keys open the screen from the Tunnels and the Relays panes. In the Settings pane s is
	// typed into the focused input, so only F4 opens it there.
	for _, tt := range []struct {
		pane  string
		steps []tea.Msg
		keys  []tea.KeyMsg
	}{
		{"tunnels", []tea.Msg{load}, []tea.KeyMsg{keyF4, keyRunes("s")}},
		{"relays", []tea.Msg{load, keyRight, keyRight}, []tea.KeyMsg{keyF4, keyRunes("s")}},
		{"settings", []tea.Msg{load, keyRight}, []tea.KeyMsg{keyF4}},
	} {
		for _, key := range tt.keys {
			model := newTestDashboard(t, theme, 100, 40, tt.steps...)
			if opened := press1(model, key); !strings.Contains(opened.View(), "ACCESS: web") {
				t.Errorf("%s should open the Access screen from the %s pane", key, tt.pane)
			}
		}
	}
	settings := newTestDashboard(t, theme, 100, 40, load, keyRight)
	if typed := press1(settings, keyRunes("s")); strings.Contains(typed.View(), "ACCESS:") {
		t.Error("s in the Settings pane must be typed, not open the Access screen")
	}

	model := accessScreen(t, theme, testAccessStatus(), accessWeb)
	for _, key := range []tea.KeyMsg{keyRunes("q"), keyRunes("a"), keyRunes("s"), keyTab, keyRight, keyF8} {
		pressed, cmd := press(model, key)
		if isQuit(cmd) || !strings.Contains(pressed.View(), "ACCESS:") || strings.Contains(pressed.View(), "Name:") || strings.Contains(pressed.View(), "Delete tunnel") {
			t.Errorf("%s must stay on the Access screen", key)
		}
	}
	for _, key := range []tea.KeyMsg{keyF10, keyCtrlC} {
		if _, cmd := press(model, key); !isQuit(cmd) {
			t.Errorf("%s should still quit", key)
		}
	}

	typing := accessScreen(t, theme, testAccessStatus(), accessWeb, keyUp, keyRunes("qs"))
	if _, cmd := press(typing, keyRunes("q")); isQuit(cmd) {
		t.Error("q belongs to the focused input on the Access screen")
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

	// The wheel moves the relay selection of the Relays pane, which the Access screen hides.
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
	status.Tunnels[accessWeb].AuthAllowedWallets = entries

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

// The requests the Access screen builds must be what the control API accepts, and what it
// stores must be what the draft said: after every step the draft has nothing left to apply,
// and once the status poll brings the stored settings the screen says Applied.
func TestDashboardAccessRequestsAreWhatTheControlAPIStores(t *testing.T) {
	const storedSecret = "stored-fake-secret"
	const wallet = "0x52908400098527886E0F7030069857D2E4169EE7"
	app := oidcTunnel("app", unreachableIssuer, storedSecret)
	app.AuthIdentityHeaders = true
	m, path := testManager(t, app, testTunnel("site"))
	startManager(t, m)
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	typed := func(text string) tea.Msg { return keyRunes(text) }

	for _, step := range []struct {
		name  string
		down  int // 0 is app, 1 is site
		keys  []tea.Msg
		check func(t *testing.T, saved TunnelConfig)
	}{
		// app has one entry, so its focus ring is mode, entry 1, add 2, headers 3, issuer 4, client ID 5, secret 6.
		{"remove the stored secret and add an entry", 0, []tea.Msg{keyUp, keyF6, keyDown, keyDown, keyDown, typed("carol@example.com"), keyEnter},
			func(t *testing.T, saved TunnelConfig) {
				if !slices.Equal(saved.AuthAllowedWallets, []string{"alice@example.com", "carol@example.com"}) || saved.AuthOIDCClientSecret != "" {
					t.Fatalf("saved = %+v", saved)
				}
			}},
		{"type a secret and turn the identity headers off", 0, []tea.Msg{keyUp, typed("replacement-fake-secret"), keyUp, keyUp, keyUp, keyLeft},
			func(t *testing.T, saved TunnelConfig) {
				if saved.AuthOIDCClientSecret != "replacement-fake-secret" || saved.AuthIdentityHeaders {
					t.Fatalf("saved = %+v", saved)
				}
			}},
		{"leave the stored secret alone while the issuer changes", 0, []tea.Msg{keyUp, keyUp, keyUp, typed("/")},
			func(t *testing.T, saved TunnelConfig) {
				if saved.AuthOIDCClientSecret != "replacement-fake-secret" || saved.AuthOIDCIssuer != unreachableIssuer+"/" {
					t.Fatalf("saved = %+v", saved)
				}
			}},
		{"remove the secret", 0, []tea.Msg{keyUp, keyF6},
			func(t *testing.T, saved TunnelConfig) {
				if saved.AuthOIDCClientSecret != "" || saved.Auth != "oidc" {
					t.Fatalf("saved = %+v", saved)
				}
			}},
		{"OIDC to wallet", 0, []tea.Msg{keyLeft, keyDown, typed(wallet), keyEnter},
			func(t *testing.T, saved TunnelConfig) {
				if saved.Auth != "siwe" || len(saved.AuthAllowedWallets) != 1 || saved.AuthOIDCIssuer != "" || saved.AuthOIDCClientID != "" || saved.AuthOIDCClientSecret != "" {
					t.Fatalf("saved = %+v", saved)
				}
			}},
		{"wallet to credential", 0, []tea.Msg{keyLeft},
			func(t *testing.T, saved TunnelConfig) {
				if saved.Auth != "credential" || len(saved.AuthAllowedWallets) != 0 {
					t.Fatalf("saved = %+v", saved)
				}
			}},
		{"credential to open", 0, []tea.Msg{keyLeft},
			func(t *testing.T, saved TunnelConfig) {
				if !reflect.DeepEqual(saved.applicationAuth(), TunnelConfig{}.applicationAuth()) {
					t.Fatalf("saved = %+v", saved)
				}
			}},
		{"open to OIDC", 1, []tea.Msg{keyRight, keyRight, keyRight, keyDown, typed("bob@example.com"), keyEnter, keyDown, keyDown, typed(unreachableIssuer), keyDown, typed("client-1"), keyDown, typed("first-fake-secret")},
			func(t *testing.T, saved TunnelConfig) {
				if saved.Auth != "oidc" || saved.AuthOIDCIssuer != unreachableIssuer || saved.AuthOIDCClientID != "client-1" || saved.AuthOIDCClientSecret != "first-fake-secret" {
					t.Fatalf("saved = %+v", saved)
				}
			}},
	} {
		t.Run(step.name, func(t *testing.T) {
			model := accessScreen(t, theme, m.Snapshot(), step.down, step.keys...)
			tunnel, _ := model.accessTunnel()
			code, resp := callControl(t, m, http.MethodPatch, types.PathAgentTunnelsPrefix+tunnel.ID, accessBody(t, model))
			if code != http.StatusAccepted {
				t.Fatalf("the control API answered %d: %s", code, resp)
			}
			step.check(t, savedTunnel(t, path, tunnel.ID))

			model = send(model, agentDashboardAccessMsg{tunnelID: tunnel.ID})
			if req := model.access.request(tunnelStatus(t, m, tunnel.ID)); !req.Empty() {
				body, _ := json.Marshal(req)
				t.Fatalf("what the agent stored differs from the draft in %s", body)
			}
			model = send(model, agentDashboardStatusMsg{status: m.Snapshot()})
			if view := model.View(); !strings.Contains(view, "ACCESS: "+tunnel.ID) || !strings.Contains(view, "( Applied )") {
				t.Fatalf("after the poll the screen should stay open and say Applied:\n%s", view)
			}
		})
	}
}

// Under agent run --foreground F10 asks before stopping the agent on the
// Access screen too, the question stands in for the screen's own buttons, and
// its letters answer it instead of going into the focused input.
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
