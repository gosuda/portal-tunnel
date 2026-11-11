package agent

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

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
