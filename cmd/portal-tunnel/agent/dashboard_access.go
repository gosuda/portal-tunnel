package agent

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// agentDashboardAccessMaxEntries is how many allow list entries the Settings
// pane lists before it counts the rest.
const agentDashboardAccessMaxEntries = 4

// agentDashboardAccessMode names how a tunnel's public address is protected.
func agentDashboardAccessMode(provider string) string {
	switch provider {
	case "":
		return "open to anyone"
	case gateway.ApplicationAuthProviderCredential:
		return "credential"
	case gateway.ApplicationAuthProviderSIWE:
		return "wallet (siwe)"
	case gateway.ApplicationAuthProviderOIDC:
		return "OIDC"
	default:
		return provider
	}
}

// agentDashboardAllowedHint says what an empty allow list means for a
// provider, following the gateway rules: credential and siwe accept any valid
// principal, while OIDC refuses to run without at least one entry.
func agentDashboardAllowedHint(provider string) string {
	switch provider {
	case gateway.ApplicationAuthProviderCredential:
		return "any valid credential"
	case gateway.ApplicationAuthProviderSIWE:
		return "any wallet"
	case gateway.ApplicationAuthProviderOIDC:
		return "needs one entry"
	default:
		return ""
	}
}

// agentDashboardIdentityHeaders describes the identity headers setting.
func agentDashboardIdentityHeaders(on bool) string {
	if on {
		return "on (" + types.HeaderPortalUser + ")"
	}
	return "off"
}

// agentDashboardSecretState says whether a client secret is stored; the secret
// itself never reaches the dashboard.
func agentDashboardSecretState(set bool) string {
	if set {
		return "set"
	}
	return "not set"
}

// agentDashboardProviderCheck is the LED, the word and the style that report
// the check of a tunnel's OIDC provider, made once when the tunnel starts. The
// reason of a failure is the error in the tunnel status.
func agentDashboardProviderCheck(th *agentDashboardTheme, tunnel AgentTunnelStatus) (string, lipgloss.Style) {
	switch {
	case tunnel.AuthOIDCProviderError != "":
		return th.glyph.ledFailed + " failed", th.failed
	case tunnel.AuthOIDCProviderChecked:
		return th.glyph.ledLive + " ok", th.bright
	case tunnel.State == "running" || tunnel.State == "starting":
		return th.glyph.ledConnecting + " checking...", th.pending
	default:
		return th.glyph.ledIdle + " not checked", th.muted
	}
}

// addAccessValue adds one read-only detail line; a value that does not fit
// ends in the truncation marker. An empty label continues the line above.
func (v *agentDashboardView) addAccessValue(th *agentDashboardTheme, width int, label, value string, style lipgloss.Style) {
	const labelWidth = agentDashboardDetailLabelWidth
	if label != "" {
		label += ":"
	}
	v.addLine(th.muted.Render(agentDashboardCell(label, labelWidth)) + " " + style.Render(agentDashboardFit(value, max(1, width-labelWidth-1))))
}

// addAccessSummary shows how the tunnel is protected, one detail per line. An
// open tunnel needs only the first line, and a failed OIDC provider check shows
// there too, so that it is seen without scrolling.
func (v *agentDashboardView) addAccessSummary(th *agentDashboardTheme, width int, tunnel AgentTunnelStatus) {
	mode, style := agentDashboardAccessMode(tunnel.Auth), th.text
	if tunnel.AuthOIDCProviderError != "" {
		mode, style = mode+" "+th.glyph.ledFailed+" check failed", th.failed
	}
	v.addAccessValue(th, width, "Access", mode, style)
	if tunnel.Auth == "" {
		return
	}

	entries := tunnel.AuthAllowedWallets
	if len(entries) == 0 {
		v.addAccessValue(th, width, "Allowed", agentDashboardAllowedHint(tunnel.Auth), th.text)
	}
	for i, entry := range entries[:min(len(entries), agentDashboardAccessMaxEntries)] {
		label := ""
		if i == 0 {
			label = "Allowed"
		}
		v.addAccessValue(th, width, label, entry, th.text)
	}
	if more := len(entries) - agentDashboardAccessMaxEntries; more > 0 {
		v.addAccessValue(th, width, "", fmt.Sprintf("+%d more", more), th.muted)
	}
	v.addAccessValue(th, width, "Headers", agentDashboardIdentityHeaders(tunnel.AuthIdentityHeaders), th.text)
	if tunnel.Auth != gateway.ApplicationAuthProviderOIDC {
		return
	}
	v.addAccessValue(th, width, "Issuer", tunnel.AuthOIDCIssuer, th.text)
	v.addAccessValue(th, width, "Client ID", tunnel.AuthOIDCClientID, th.text)
	v.addAccessValue(th, width, "Client secret", agentDashboardSecretState(tunnel.AuthOIDCClientSecretSet), th.text)
	check, checkStyle := agentDashboardProviderCheck(th, tunnel)
	if tunnel.AuthOIDCProviderError != "" {
		check += ": " + tunnel.AuthOIDCProviderError
	}
	v.addAccessValue(th, width, "Provider check", check, checkStyle)
}
