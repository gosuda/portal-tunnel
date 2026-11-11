package agent

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"

	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
)

func (m agentDashboardModel) renderAccess(width, height int) agentDashboardView {
	th := &m.theme
	inner := width - agentDashboardFrameWidth
	a := m.access
	tunnel, _ := m.accessTunnel()

	changed := !a.request(tunnel).Empty()
	content := m.accessActionBar(th, inner, a, changed)
	body, focusLine := m.accessBodyRows(th, inner, a, tunnel)
	rows := 0
	if height > 0 {
		rows = max(1, height-agentDashboardFrameHeight-len(content.lines))
	}
	content.addView(body.window(focusLine, rows))

	var out agentDashboardView
	out.addFrame(th, "ACCESS: "+tunnelDashboardName(tunnel), true, width, max(0, height-agentDashboardFrameHeight), content)
	return out
}

func (m agentDashboardModel) accessActionBar(th *agentDashboardTheme, inner int, a agentDashboardAccess, changed bool) agentDashboardView {
	var content agentDashboardView
	if m.confirmStop {
		content.addStyled(inner, th.pending, agentDashboardStopQuestion)
		content.addButtons(th, inner,
			agentDashboardButton{label: "Yes", action: agentDashboardActionAnswerYes},
			agentDashboardButton{label: "No", action: agentDashboardActionAnswerNo},
		)
	} else {
		content.addButtons(th, inner,
			agentDashboardButton{label: accessApplyLabel(a, changed), action: agentDashboardActionApplyAccess, disabled: !changed || a.applying},
			agentDashboardButton{label: "Cancel", action: agentDashboardActionCancelAccess},
		)
	}
	if a.err != nil {
		for _, line := range agentDashboardWrap(th.glyph.ledFailed+" Error: "+a.err.Error(), inner, agentDashboardAccessMessageLines) {
			content.addLine(th.failed.Render(line))
		}
	}
	return content
}

func accessApplyLabel(a agentDashboardAccess, changed bool) string {
	applyLabel := "Apply"
	switch {
	case a.applying:
		applyLabel = "Applying..."
	case !changed && a.applied:
		applyLabel = "Applied"
	}
	return applyLabel
}

func (m agentDashboardModel) accessBodyRows(th *agentDashboardTheme, inner int, a agentDashboardAccess, tunnel AgentTunnelStatus) (agentDashboardView, int) {
	var body agentDashboardView
	focusLine := body.addAccessBodyFields(th, inner, a, tunnel)
	body.addLine("")
	body.addAccessProviderCheck(th, inner, tunnel)
	body.addAccessRestartNote(th, inner)
	return body, focusLine
}

func (v *agentDashboardView) addAccessBodyFields(th *agentDashboardTheme, inner int, a agentDashboardAccess, tunnel AgentTunnelStatus) int {
	focusLine := 0
	for index, field := range a.fields() {
		focused := index == a.focusIndex()
		if focused {
			focusLine = len(v.lines)
		}
		if label, input, ok := a.providerInput(field.row); ok {
			v.addInputRow(th, inner, label, input, agentDashboardActionFocusAccessField, index, focused)
			continue
		}
		switch field.row {
		case agentDashboardAccessRowMode:
			v.addAccessChoice(th, inner, "Mode", agentDashboardAccessMode(a.provider), index, focused)
			if a.provider != "" {
				v.addAccessAllowed(th, inner, a)
			}
		case agentDashboardAccessRowEntry:
			v.addAccessEntryRow(th, inner, a.allowed[field.entry], index, focused)
		case agentDashboardAccessRowAdd:
			input := a.add
			input.Placeholder = agentDashboardAccessEntryPlaceholder(a.provider)
			v.addInputRow(th, inner, "Add entry", input, agentDashboardActionFocusAccessField, index, focused)
		case agentDashboardAccessRowHeaders:
			v.addAccessChoice(th, inner, "Headers", agentDashboardIdentityHeaders(a.headers), index, focused)
		case agentDashboardAccessRowSecret:
			label, input := a.accessSecretField(tunnel)
			v.addInputRow(th, inner, label, input, agentDashboardActionFocusAccessField, index, focused)
		}
	}
	return focusLine
}

func (a agentDashboardAccess) providerInput(field agentDashboardAccessRow) (string, textinput.Model, bool) {
	switch field {
	case agentDashboardAccessRowIssuer:
		return "Issuer", a.issuer, true
	case agentDashboardAccessRowClientID:
		return "Client ID", a.clientID, true
	case agentDashboardAccessRowMetadataURL:
		return "Metadata URL", a.metadataURL, true
	case agentDashboardAccessRowMetadataFile:
		return "Metadata file", a.metadataFile, true
	case agentDashboardAccessRowEntityID:
		return "Entity ID", a.entityID, true
	case agentDashboardAccessRowSubjectAttribute:
		return "Subject attr", a.subjectAttribute, true
	case agentDashboardAccessRowSMTPAddr:
		return "SMTP server", a.smtpAddr, true
	case agentDashboardAccessRowSMTPUsername:
		return "SMTP user", a.smtpUsername, true
	case agentDashboardAccessRowFrom:
		return "Sender", a.from, true
	case agentDashboardAccessRowMode, agentDashboardAccessRowEntry, agentDashboardAccessRowAdd, agentDashboardAccessRowHeaders, agentDashboardAccessRowSecret:
		return "", textinput.Model{}, false
	}
	return "", textinput.Model{}, false
}

func (a agentDashboardAccess) accessSecretField(tunnel AgentTunnelStatus) (string, textinput.Model) {
	input, label := a.secret, "Client secret"
	if a.provider == appauth.ProviderEmail {
		label = "SMTP password"
	}
	input.Placeholder = agentDashboardSecretPlaceholder(a, tunnel)
	if a.revealed() {
		label = "Secret (shown)"
	}
	return label, input
}

func (v *agentDashboardView) addAccessProviderCheck(th *agentDashboardTheme, inner int, tunnel AgentTunnelStatus) {
	if tunnel.Provider != appauth.ProviderOIDC && tunnel.Provider != appauth.ProviderSAML && tunnel.Provider != appauth.ProviderEmail {
		return
	}
	check, style := agentDashboardProviderCheck(th, tunnel)
	v.addAccessValue(th, inner, "Provider check", check, style)
	for _, line := range agentDashboardWrap(tunnel.AuthProviderError, inner, agentDashboardAccessMessageLines) {
		v.addLine(style.Render(line))
	}
}

func (v *agentDashboardView) addAccessRestartNote(th *agentDashboardTheme, inner int) {
	for _, line := range agentDashboardWrap("Applying restarts this tunnel, drops the relays connected to it at runtime, and signs out visitors on its alias.", inner, 3) {
		v.addLine(th.muted.Render(line))
	}
}

func agentDashboardAccessEntryPlaceholder(provider string) string {
	switch provider {
	case appauth.ProviderSIWE:
		return "0x... wallet address"
	case appauth.ProviderOIDC, appauth.ProviderSAML:
		return "email, @domain, sub:id"
	case appauth.ProviderEmail:
		return "email, @domain"
	default:
		return "subject"
	}
}

func agentDashboardSecretPlaceholder(a agentDashboardAccess, stored AgentTunnelStatus) string {
	switch {
	case a.clearSecret:
		return "will be removed"
	case agentDashboardSecretSet(a.provider, stored):
		return "set; type to replace"
	default:
		return "not set"
	}
}

func agentDashboardWrap(text string, width, maxLines int) []string {
	text = strings.TrimSpace(text)
	if text == "" || width <= 0 {
		return nil
	}
	lines := strings.Split(lipgloss.NewStyle().Width(width).Render(text), "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " ")
	}
	if len(lines) > maxLines {
		lines = lines[:maxLines]
		lines[maxLines-1] = agentDashboardFit(lines[maxLines-1]+"~", width)
	}
	return lines
}

func (v *agentDashboardView) addAccessChoice(th *agentDashboardTheme, width int, label, value string, field int, focused bool) {
	labelStyle, valueStyle, prompt := th.muted, th.text, th.glyph.promptBlurred
	if focused {
		labelStyle, valueStyle, prompt = th.bright, th.bright, th.glyph.promptFocused
		value = th.glyph.arrowLeft + " " + value + " " + th.glyph.arrowRight
	}
	valueWidth := max(1, width-agentDashboardLabelWidth-1-lipgloss.Width(prompt))
	v.addFieldRow(labelStyle.Render(agentDashboardCell(label+":", agentDashboardLabelWidth))+" "+th.strong.Render(prompt)+valueStyle.Render(agentDashboardFit(value, valueWidth)), width, field)
}

func (v *agentDashboardView) addAccessAllowed(th *agentDashboardTheme, width int, a agentDashboardAccess) {
	text, style := fmt.Sprintf("%d entries", len(a.allowed)), th.muted
	switch len(a.allowed) {
	case 0:
		text, style = agentDashboardAllowedHint(a.provider), th.pending
	case 1:
		text = "1 entry"
	}
	valueWidth := max(1, width-agentDashboardLabelWidth-1-lipgloss.Width(th.glyph.promptBlurred))
	v.addLine(th.muted.Render(agentDashboardCell("Allowed:", agentDashboardLabelWidth)) + " " + th.glyph.promptBlurred + style.Render(agentDashboardFit(text, valueWidth)))
}

func (v *agentDashboardView) addAccessEntryRow(th *agentDashboardTheme, width int, entry string, field int, focused bool) {
	marker, style := th.glyph.unselected, th.text
	if focused {
		marker, style = th.glyph.selected, th.selected
	}
	v.addFieldRow(style.Width(width).Render(marker+agentDashboardFit(entry, max(1, width-lipgloss.Width(marker)))), width, field)
}

func (v *agentDashboardView) addFieldRow(line string, width, field int) {
	v.regions = append(v.regions, agentDashboardRegion{x0: 0, x1: width, y: len(v.lines), action: agentDashboardActionFocusAccessField, field: field})
	v.addLine(line)
}
