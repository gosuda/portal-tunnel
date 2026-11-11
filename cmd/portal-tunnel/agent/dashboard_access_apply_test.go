package agent

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
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
