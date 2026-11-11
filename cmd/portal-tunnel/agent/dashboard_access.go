package agent

import (
	"cmp"
	"fmt"

	"github.com/charmbracelet/lipgloss"

	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
)

const agentDashboardAccessMaxEntries = 4

func agentDashboardAccessMode(provider string) string {
	switch provider {
	case "":
		return "open to anyone"
	case appauth.ProviderCredential:
		return "credential"
	case appauth.ProviderSIWE:
		return "wallet (siwe)"
	case appauth.ProviderOIDC:
		return "OIDC"
	case appauth.ProviderSAML:
		return "SAML"
	case appauth.ProviderEmail:
		return "email link"
	default:
		return provider
	}
}

func agentDashboardAllowedHint(provider string) string {
	switch provider {
	case appauth.ProviderCredential:
		return "any valid credential"
	case appauth.ProviderSIWE:
		return "any wallet"
	case appauth.ProviderOIDC, appauth.ProviderSAML, appauth.ProviderEmail:
		return "needs one entry"
	default:
		return ""
	}
}

func agentDashboardIdentityHeaders(on bool) string {
	if on {
		return "on (" + types.HeaderPortalUser + ")"
	}
	return "off"
}

func agentDashboardSecretState(set bool) string {
	if set {
		return "set"
	}
	return "not set"
}

func agentDashboardSecretSet(provider string, tunnel AgentTunnelStatus) bool {
	switch provider {
	case appauth.ProviderOIDC:
		return tunnel.AuthOIDCClientSecretSet
	case appauth.ProviderEmail:
		return tunnel.AuthSMTPPasswordSet
	default:
		return false
	}
}

func agentDashboardProviderCheck(th *agentDashboardTheme, tunnel AgentTunnelStatus) (string, lipgloss.Style) {
	switch {
	case tunnel.AuthProviderError != "":
		return th.glyph.ledFailed + " failed", th.failed
	case tunnel.AuthProviderChecked:
		return th.glyph.ledLive + " ok", th.bright
	case tunnel.State == "running" || tunnel.State == "starting":
		return th.glyph.ledConnecting + " checking...", th.pending
	default:
		return th.glyph.ledIdle + " not checked", th.muted
	}
}

func (v *agentDashboardView) addAccessValue(th *agentDashboardTheme, width int, label, value string, style lipgloss.Style) {
	const labelWidth = agentDashboardDetailLabelWidth
	if label != "" {
		label += ":"
	}
	v.addLine(th.muted.Render(agentDashboardCell(label, labelWidth)) + " " + style.Render(agentDashboardFit(value, max(1, width-labelWidth-1))))
}

func (v *agentDashboardView) addAccessSummary(th *agentDashboardTheme, width int, tunnel AgentTunnelStatus) {
	mode, style := agentDashboardAccessMode(tunnel.Provider), th.text
	if tunnel.AuthProviderError != "" {
		mode, style = mode+" "+th.glyph.ledFailed+" check failed", th.failed
	}
	v.addAccessValue(th, width, "Access", mode, style)
	if tunnel.Provider == "" {
		return
	}

	entries := tunnel.Allowed()
	if len(entries) == 0 {
		v.addAccessValue(th, width, "Allowed", agentDashboardAllowedHint(tunnel.Provider), th.text)
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
	v.addAccessValue(th, width, "Headers", agentDashboardIdentityHeaders(tunnel.IdentityHeaders), th.text)
	switch tunnel.Provider {
	case appauth.ProviderOIDC:
		v.addAccessValue(th, width, "Issuer", tunnel.OIDCIssuerURL, th.text)
		v.addAccessValue(th, width, "Client ID", tunnel.OIDCClientID, th.text)
		v.addAccessValue(th, width, "Client secret", agentDashboardSecretState(tunnel.AuthOIDCClientSecretSet), th.text)
	case appauth.ProviderSAML:
		v.addAccessValue(th, width, "Metadata", cmp.Or(tunnel.SAMLMetadataURL, tunnel.SAMLMetadataFile), th.text)
		v.addAccessValue(th, width, "Entity ID", cmp.Or(tunnel.SAMLEntityID, agentDashboardSAMLEntityIDDefault), th.text)
		v.addAccessValue(th, width, "Subject", cmp.Or(tunnel.SAMLSubjectAttribute, agentDashboardSAMLSubjectDefault), th.text)
	case appauth.ProviderEmail:
		v.addAccessValue(th, width, "SMTP server", tunnel.SMTPAddr, th.text)
		v.addAccessValue(th, width, "SMTP user", cmp.Or(tunnel.SMTPUsername, agentDashboardSMTPUsernameDefault), th.text)
		v.addAccessValue(th, width, "SMTP password", agentDashboardSecretState(tunnel.AuthSMTPPasswordSet), th.text)
		v.addAccessValue(th, width, "Sender", tunnel.SMTPFrom, th.text)
	default:
		return
	}
	check, checkStyle := agentDashboardProviderCheck(th, tunnel)
	if tunnel.AuthProviderError != "" {
		check += ": " + tunnel.AuthProviderError
	}
	v.addAccessValue(th, width, "Provider check", check, checkStyle)
}

var agentDashboardAccessProviders = []string{
	"",
	appauth.ProviderCredential,
	appauth.ProviderSIWE,
	appauth.ProviderOIDC,
	appauth.ProviderSAML,
	appauth.ProviderEmail,
}

const (
	agentDashboardSAMLEntityIDDefault = "metadata URL of each host"
	agentDashboardSAMLSubjectDefault  = "NameID"
	agentDashboardSMTPUsernameDefault = "none (no SMTP login)"
)

const agentDashboardAccessMessageLines = 4
