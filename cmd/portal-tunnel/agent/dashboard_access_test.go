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

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestDashboardAccessRequestNamesOnlyWhatChanged(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	typed := func(text string) tea.Msg { return keyRunes(text) }
	for _, step := range accessRequestNameCases(typed) {
		t.Run(step.name, func(t *testing.T) {
			checkAccessRequestName(t, theme, testAccessStatus(), step)
		})
	}
}

type accessRequestNameCase struct {
	name string
	down int
	keys []tea.Msg
	want string
}

func accessRequestNameCases(typed func(string) tea.Msg) []accessRequestNameCase {
	return []accessRequestNameCase{
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
		{"OIDC to open sends only auth", accessWeb, []tea.Msg{keyRight, keyRight, keyRight}, `{"auth":""}`},
		{"OIDC to SAML clears the OIDC settings and the allow list", accessWeb, []tea.Msg{keyRight},
			`{"auth":"saml","auth_allowed_wallets":[],"auth_oidc_issuer":"","auth_oidc_client_id":"","auth_oidc_client_secret":""}`},
		{"open to SAML", accessOpen,
			[]tea.Msg{keyLeft, keyLeft, keyDown, typed("@example.com"), keyEnter, keyDown, keyDown, typed("https://idp.example/metadata"), keyDown, keyDown, typed("urn:portal:web"), keyDown, typed("email")},
			`{"auth":"saml","auth_email_list":["@example.com"],"auth_saml_metadata_url":"https://idp.example/metadata","auth_saml_entity_id":"urn:portal:web","auth_saml_subject_attribute":"email"}`},
		{"open to email", accessOpen,
			[]tea.Msg{keyLeft, keyDown, typed("alice@example.com"), keyEnter, keyDown, keyDown, typed("smtp.example.com:587"), keyDown, typed("portal"), keyDown, typed(fakeSecret), keyDown, typed("login@example.com")},
			`{"auth":"email","auth_email_list":["alice@example.com"],"auth_smtp_addr":"smtp.example.com:587","auth_smtp_username":"portal","auth_smtp_password":"` + fakeSecret + `","auth_smtp_from":"login@example.com"}`},
		{"open to credential", accessOpen, []tea.Msg{keyRight}, `{"auth":"credential"}`},
		{"wallet to OIDC", accessWallet,
			[]tea.Msg{keyRight, keyDown, typed("carol@example.com"), keyEnter, keyDown, keyDown, typed("https://idp.example.org"), keyDown, typed("client-1"), keyDown, typed(fakeSecret)},
			`{"auth":"oidc","auth_allowed_wallets":[],"auth_email_list":["carol@example.com"],"auth_oidc_issuer":"https://idp.example.org","auth_oidc_client_id":"client-1","auth_oidc_client_secret":"` + fakeSecret + `"}`},
	}
}

func checkAccessRequestName(t *testing.T, theme agentDashboardTheme, status AgentStatusResponse, step accessRequestNameCase) {
	t.Helper()
	model := accessScreen(t, theme, status, step.down, step.keys...)
	if got := accessBody(t, model); !sameJSON(t, got, step.want) {
		t.Fatalf("request body = %s\nwant           %s", got, step.want)
	}
	applied, cmd := press(model, keyF2)
	if (cmd != nil) != (step.want != `{}`) {
		t.Fatalf("F2 sent a request = %v for the body %s", cmd != nil, step.want)
	}
	if strings.Contains(applied.View(), "Error:") {
		t.Fatalf("applying must not fail before it is sent:\n%s", applied.View())
	}
}

func TestDashboardAccessEntries(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})

	t.Run("an entry is normalized, a duplicate is not added twice", func(t *testing.T) {
		checkEntryNormalizedOnce(t, theme)
	})

	t.Run("a wrong entry is refused on the spot and stays typed", func(t *testing.T) {
		checkWrongEntryRefused(t, theme)
	})

	t.Run("an emptied list says what that means for the provider", func(t *testing.T) {
		checkEmptiedListHint(t, theme)
	})

	t.Run("enter on the entry input adds and never applies, F2 applies", func(t *testing.T) {
		checkEnterAddsF2Applies(t, theme)
	})
}

func checkEntryNormalizedOnce(t *testing.T, theme agentDashboardTheme) {
	t.Helper()
	model := accessScreen(t, theme, testAccessStatus(), accessWeb, append(downs(4), keyRunes("Carol@Example.COM"), keyEnter, keyRunes("CAROL@example.com"), keyEnter)...)
	if view := model.View(); !strings.Contains(view, "carol@example.com") || !strings.Contains(view, "4 entries") {
		t.Fatalf("the entry should be added once, in its normal form:\n%s", view)
	}
}

func checkWrongEntryRefused(t *testing.T, theme agentDashboardTheme) {
	t.Helper()
	model := accessScreen(t, theme, testAccessStatus(), accessWallet, keyDown, keyDown, keyRunes("nope"), keyEnter)
	view := model.View()
	if !strings.Contains(view, "address must start with 0x") || !strings.Contains(view, "1 entry") || !strings.Contains(view, "nope") {
		t.Fatalf("the gateway's refusal should show, the list stay as it is and the text stay typed:\n%s", view)
	}
}

func checkEmptiedListHint(t *testing.T, theme agentDashboardTheme) {
	t.Helper()
	if view := accessScreen(t, theme, testAccessStatus(), accessWeb, keyDown, keyDelete, keyDelete, keyDelete).View(); !strings.Contains(view, "needs one entry") {
		t.Fatalf("an OIDC tunnel without entries should say it needs one:\n%s", view)
	}
	if view := accessScreen(t, theme, testAccessStatus(), accessWallet, keyDown, keyDelete).View(); !strings.Contains(view, "any wallet") {
		t.Fatalf("a wallet tunnel without entries should say any wallet signs in:\n%s", view)
	}
}

func checkEnterAddsF2Applies(t *testing.T, theme agentDashboardTheme) {
	t.Helper()
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
}

func TestDashboardAccessApply(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	untouched := accessScreen(t, theme, testAccessStatus(), accessWeb)
	for _, key := range []tea.KeyMsg{keyF2, keyEnter} {
		if _, cmd := press(untouched, key); cmd != nil {
			t.Fatalf("%s with nothing changed must not send a request", key)
		}
	}
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
	added.Tunnels[accessWeb].Allow = append(added.Tunnels[accessWeb].Allow, "carol@example.com")

	model := accessScreen(t, theme, testAccessStatus(), accessWeb, append(downs(4), keyRunes("carol@example.com"), keyEnter)...)
	model = send(press1(model, keyF2), agentDashboardAccessMsg{tunnelID: "web"})
	if view := model.View(); !strings.Contains(view, "[ Apply ]") || strings.Contains(view, "Applied") {
		t.Fatalf("before the poll brings the new settings the draft still differs from what is stored:\n%s", view)
	}
	model = send(model, agentDashboardStatusMsg{status: added})
	view := model.View()
	if !strings.Contains(view, "( Applied )") || !strings.Contains(view, "carol@example.com") || strings.Contains(view, "Error:") {
		t.Fatalf("once the poll brings the new settings the screen says Applied and keeps them:\n%s", view)
	}

	model = press1(model, keyRunes("erin@example.com"), keyEnter)
	view = send(model, agentDashboardStatusMsg{status: added}).View()
	if !strings.Contains(view, "erin@example.com") || strings.Contains(view, "changed meanwhile") {
		t.Fatalf("an edit made after an apply must survive the next poll:\n%s", view)
	}
}

func TestDashboardAccessShowsAChangeMadeElsewhere(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	elsewhere := testAccessStatus()
	elsewhere.Tunnels[accessWeb].Allow = []string{"alice@example.com", "dave@example.com"}
	elsewhere.Tunnels[accessWeb].OIDCClientID = "portal-web-2"

	for _, tt := range []struct {
		name string
		keys []tea.Msg
	}{
		{"an untouched draft", nil},
		{"an edited draft", append(downs(4), keyRunes("carol@example.com"), keyEnter)},
		{"a typed secret", []tea.Msg{keyUp, keyRunes(fakeSecret), keyF3}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			checkChangedMeanwhileReshown(t, theme, testAccessStatus(), elsewhere, tt.keys)
		})
	}

	t.Run("a poll that changes nothing", func(t *testing.T) {
		model := accessScreen(t, theme, testAccessStatus(), accessWeb, append(downs(4), keyRunes("carol@example.com"), keyEnter)...)
		view := send(model, agentDashboardStatusMsg{status: testAccessStatus()}).View()
		if !strings.Contains(view, "carol@example.com") || strings.Contains(view, "changed meanwhile") {
			t.Fatalf("an edited draft must survive a poll that brings nothing new:\n%s", view)
		}
	})
}

func checkChangedMeanwhileReshown(t *testing.T, theme agentDashboardTheme, status, elsewhere AgentStatusResponse, keys []tea.Msg) {
	t.Helper()
	model := accessScreen(t, theme, status, accessWeb, keys...)
	model = send(model, agentDashboardStatusMsg{status: elsewhere})
	view := model.View()
	for _, want := range []string{"ACCESS: web", "changed meanwhile", "dave@example.com", "portal-web-2"} {
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
}

func TestDashboardAccessAppliesOneAtATime(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	typedEntry := append(downs(4), keyRunes("carol@example.com"), keyEnter)

	t.Run("a second save waits for the answer", func(t *testing.T) {
		checkSecondSaveWaitsForAnswer(t, theme, typedEntry)
	})

	t.Run("the answer of a closed screen is not the new screen's", func(t *testing.T) {
		checkClosedScreenAnswerIgnored(t, theme, typedEntry)
	})

	t.Run("an edit made while it runs is dropped for the stored settings", func(t *testing.T) {
		checkEditWhileRunningDropped(t, theme, typedEntry)
	})
}

func checkSecondSaveWaitsForAnswer(t *testing.T, theme agentDashboardTheme, typedEntry []tea.Msg) {
	t.Helper()
	model, cmd := press(accessScreen(t, theme, testAccessStatus(), accessWeb, typedEntry...), keyF2)
	if cmd == nil {
		t.Fatal("F2 should send the request")
	}
	if view := model.View(); !strings.Contains(view, "( Applying... )") {
		t.Fatalf("a running apply should show on the disabled button:\n%s", view)
	}
	if _, again := press(model, keyF2); again != nil {
		t.Fatal("F2 while an apply is running must not send another request")
	}
	refused := send(model, agentDashboardAccessMsg{tunnelID: "web", err: errors.New("invalid_request")})
	if _, cmd := press(refused, keyF2); cmd == nil {
		t.Fatal("after a refusal the draft can be applied again")
	}
}

func checkClosedScreenAnswerIgnored(t *testing.T, theme agentDashboardTheme, typedEntry []tea.Msg) {
	t.Helper()
	model := press1(accessScreen(t, theme, testAccessStatus(), accessWeb, typedEntry...), keyF2, keyEsc)
	if strings.Contains(model.View(), "ACCESS:") {
		t.Fatal("esc should close the screen")
	}
	reopened := press1(model, keyF4, keyUp, keyRunes(fakeSecret), keyF3)
	late := send(reopened, agentDashboardAccessMsg{tunnelID: "web"})
	if view := late.View(); !strings.Contains(view, fakeSecret) || strings.Contains(view, "Applied") {
		t.Fatalf("the late answer must leave the reopened screen as it is:\n%s", view)
	}
}

func checkEditWhileRunningDropped(t *testing.T, theme agentDashboardTheme, typedEntry []tea.Msg) {
	t.Helper()
	applied := testAccessStatus()
	applied.Tunnels[accessWeb].Allow = append(applied.Tunnels[accessWeb].Allow, "carol@example.com")
	model := press1(accessScreen(t, theme, testAccessStatus(), accessWeb, typedEntry...), keyF2)
	model = press1(model, keyRunes("erin@example.com"), keyEnter)
	model = send(model, agentDashboardStatusMsg{status: applied})
	if view := model.View(); !strings.Contains(view, "changed meanwhile") || strings.Contains(view, "erin@example.com") || !strings.Contains(view, "carol@example.com") {
		t.Fatalf("the screen should show what the agent stored and say it changed:\n%s", view)
	}
	model = send(model, agentDashboardAccessMsg{tunnelID: "web"})
	if view := model.View(); !strings.Contains(view, "( Applied )") {
		t.Fatalf("the answer to the apply should still be taken:\n%s", view)
	}
}

func TestDashboardAccessShowsTheServerErrorInline(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{unicode: true})
	const refusal = "invalid_request: oidc client id is required"
	model := accessScreen(t, theme, testAccessStatus(), accessWeb, keyUp, keyRunes(fakeSecret), keyF2)
	model = send(model, agentDashboardAccessMsg{tunnelID: "web", err: errors.New(refusal)})

	view := model.View()
	if !strings.Contains(view, "Error: "+refusal) || !strings.Contains(view, "ACCESS: web") {
		t.Fatalf("the refusal should show inside the Access screen:\n%s", view)
	}
	model = send(model, agentDashboardStatusMsg{status: testAccessStatus()})
	if !strings.Contains(model.View(), "Error: "+refusal) {
		t.Fatalf("the next status poll must not remove the refusal:\n%s", model.View())
	}
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
				checkSecretMaskReveal(t, tt.term, tt.mask, reveal)
			})
		}
	}
}

func checkSecretMaskReveal(t *testing.T, term agentDashboardTerminal, mask string, reveal tea.KeyMsg) {
	t.Helper()
	theme := newAgentDashboardTheme("amber", term)
	model := accessScreen(t, theme, testAccessStatus(), accessWeb, keyUp, keyRunes(fakeSecret))
	if view := model.View(); strings.Contains(view, fakeSecret) || !strings.Contains(view, strings.Repeat(mask, len(fakeSecret))) {
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
