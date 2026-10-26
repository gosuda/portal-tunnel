package agent

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
)

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
