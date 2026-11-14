package agent

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
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

type agentDashboardAccessRow int

const (
	agentDashboardAccessRowMode agentDashboardAccessRow = iota
	agentDashboardAccessRowEntry
	agentDashboardAccessRowAdd
	agentDashboardAccessRowHeaders
	agentDashboardAccessRowIssuer
	agentDashboardAccessRowClientID
	agentDashboardAccessRowSecret
	agentDashboardAccessRowMetadataURL
	agentDashboardAccessRowMetadataFile
	agentDashboardAccessRowEntityID
	agentDashboardAccessRowSubjectAttribute
	agentDashboardAccessRowSMTPAddr
	agentDashboardAccessRowSMTPUsername
	agentDashboardAccessRowFrom
)

type agentDashboardAccessField struct {
	row   agentDashboardAccessRow
	entry int
}

type agentDashboardAccess struct {
	tunnelID    string
	focus       int
	provider    string
	headers     bool
	allowed     []string
	clearSecret bool
	applying    bool
	applied     bool
	err         error
	base        AgentTunnelStatus

	add, issuer, clientID, secret                         textinput.Model
	metadataURL, metadataFile, entityID, subjectAttribute textinput.Model
	smtpAddr, smtpUsername, from                          textinput.Model
}

type agentDashboardAccessMsg struct {
	tunnelID string
	err      error
}

func newAgentDashboardAccess(theme agentDashboardTheme) agentDashboardAccess {
	return agentDashboardAccess{
		add:      theme.newInput(""),
		issuer:   theme.newInput("https://idp.example"),
		clientID: theme.newInput("client id"),
		secret:   theme.newSecretInput(),

		metadataURL:      theme.newInput("https://idp.example/metadata"),
		metadataFile:     theme.newInput("or a metadata file path"),
		entityID:         theme.newInput(agentDashboardSAMLEntityIDDefault),
		subjectAttribute: theme.newInput(agentDashboardSAMLSubjectDefault),

		smtpAddr:     theme.newInput("smtp.example.com:587"),
		smtpUsername: theme.newInput("none"),
		from:         theme.newInput("Portal <login@example.com>"),
	}
}

func (m agentDashboardModel) accessing() bool { return m.access.tunnelID != "" }

func (m agentDashboardModel) accessTunnel() (AgentTunnelStatus, bool) {
	index := slices.IndexFunc(m.status.Tunnels, func(tunnel AgentTunnelStatus) bool { return tunnel.ID == m.access.tunnelID })
	if index < 0 {
		return AgentTunnelStatus{}, false
	}
	return m.status.Tunnels[index], true
}

func (m agentDashboardModel) openAccess() (tea.Model, tea.Cmd) {
	tunnel, ok := m.selectedTunnelStatus()
	if !ok {
		return m, nil
	}
	m.access.tunnelID = tunnel.ID
	m.access.load(tunnel)
	m.access.moveFocus(0)
	return m, nil
}

func (m *agentDashboardModel) closeAccess() {
	a := &m.access
	a.forgetSecret()
	a.add.Reset()
	a.resetProviderInputs()
	a.blur()
	a.tunnelID = ""
	a.allowed = nil
	a.err = nil
	a.applying = false
}

func (m *agentDashboardModel) syncAccess() {
	tunnel, ok := m.accessTunnel()
	if !ok {
		return
	}
	a := &m.access
	switch {
	case a.request(tunnel).Empty():
		a.base = tunnel
	case !sameAccessSettings(tunnel, a.base):
		a.forgetSecret()
		a.load(tunnel)
		a.moveFocus(a.focusIndex())
		a.err = errors.New("settings changed meanwhile; showing what is stored")
	}
}

func sameAccessSettings(a, b AgentTunnelStatus) bool {
	return authChanges(a.AuthConfig, b.AuthConfig) == nil &&
		a.AuthOIDCClientSecretSet == b.AuthOIDCClientSecretSet &&
		a.AuthSMTPPasswordSet == b.AuthSMTPPasswordSet
}

func (a *agentDashboardAccess) load(tunnel AgentTunnelStatus) {
	a.base = tunnel
	a.applied = false
	a.provider = tunnel.Provider
	a.headers = tunnel.IdentityHeaders
	a.allowed = slices.Clone(tunnel.Allowed())
	a.err = nil
	a.add.Reset()
	for input, value := range map[*textinput.Model]string{
		&a.issuer:           tunnel.OIDCIssuerURL,
		&a.clientID:         tunnel.OIDCClientID,
		&a.metadataURL:      tunnel.SAMLMetadataURL,
		&a.metadataFile:     tunnel.SAMLMetadataFile,
		&a.entityID:         tunnel.SAMLEntityID,
		&a.subjectAttribute: tunnel.SAMLSubjectAttribute,
		&a.smtpAddr:         tunnel.SMTPAddr,
		&a.smtpUsername:     tunnel.SMTPUsername,
		&a.from:             tunnel.SMTPFrom,
	} {
		input.SetValue(value)
		input.CursorEnd()
	}
}

func (a *agentDashboardAccess) resetProviderInputs() {
	for _, input := range []*textinput.Model{&a.issuer, &a.clientID, &a.metadataURL, &a.metadataFile, &a.entityID, &a.subjectAttribute, &a.smtpAddr, &a.smtpUsername, &a.from} {
		input.Reset()
	}
}

func (a *agentDashboardAccess) forgetSecret() {
	a.secret.Reset()
	a.secret.EchoMode = textinput.EchoPassword
	a.clearSecret = false
}

func (a *agentDashboardAccess) setClearSecret(clear bool, stored AgentTunnelStatus) {
	a.clearSecret = clear
	if clear {
		a.secret.Reset()
	}
	if a.provider != appauth.ProviderEmail {
		return
	}
	switch {
	case clear:
		a.smtpUsername.Reset()
	case a.smtpUsername.Value() == "":
		a.smtpUsername.SetValue(stored.SMTPUsername)
	}
}

func (a *agentDashboardAccess) setProvider(provider string, stored AgentTunnelStatus) {
	if provider == a.provider {
		return
	}
	a.forgetSecret()
	if provider == stored.Provider {
		a.load(stored)
		return
	}
	a.provider = provider
	a.headers = a.headers && provider != ""
	a.allowed = nil
	a.err = nil
	a.add.Reset()
	a.resetProviderInputs()
}

func (a agentDashboardAccess) fields() []agentDashboardAccessField {
	fields := []agentDashboardAccessField{{row: agentDashboardAccessRowMode}}
	if a.provider == "" {
		return fields
	}
	for i := range a.allowed {
		fields = append(fields, agentDashboardAccessField{row: agentDashboardAccessRowEntry, entry: i})
	}
	fields = append(fields, agentDashboardAccessField{row: agentDashboardAccessRowAdd}, agentDashboardAccessField{row: agentDashboardAccessRowHeaders})
	return append(fields, accessProviderFields(a.provider)...)
}

func accessProviderFields(provider string) []agentDashboardAccessField {
	switch provider {
	case appauth.ProviderOIDC:
		return []agentDashboardAccessField{
			{row: agentDashboardAccessRowIssuer},
			{row: agentDashboardAccessRowClientID},
			{row: agentDashboardAccessRowSecret},
		}
	case appauth.ProviderSAML:
		return []agentDashboardAccessField{
			{row: agentDashboardAccessRowMetadataURL},
			{row: agentDashboardAccessRowMetadataFile},
			{row: agentDashboardAccessRowEntityID},
			{row: agentDashboardAccessRowSubjectAttribute},
		}
	case appauth.ProviderEmail:
		return []agentDashboardAccessField{
			{row: agentDashboardAccessRowSMTPAddr},
			{row: agentDashboardAccessRowSMTPUsername},
			{row: agentDashboardAccessRowSecret},
			{row: agentDashboardAccessRowFrom},
		}
	}
	return nil
}

func (a agentDashboardAccess) focusIndex() int {
	return max(0, min(a.focus, len(a.fields())-1))
}

func (a agentDashboardAccess) current() agentDashboardAccessField {
	return a.fields()[a.focusIndex()]
}

func (a *agentDashboardAccess) focusedInput() *textinput.Model {
	switch a.current().row {
	case agentDashboardAccessRowAdd:
		return &a.add
	case agentDashboardAccessRowIssuer:
		return &a.issuer
	case agentDashboardAccessRowClientID:
		return &a.clientID
	case agentDashboardAccessRowSecret:
		return &a.secret
	case agentDashboardAccessRowMetadataURL:
		return &a.metadataURL
	case agentDashboardAccessRowMetadataFile:
		return &a.metadataFile
	case agentDashboardAccessRowEntityID:
		return &a.entityID
	case agentDashboardAccessRowSubjectAttribute:
		return &a.subjectAttribute
	case agentDashboardAccessRowSMTPAddr:
		return &a.smtpAddr
	case agentDashboardAccessRowSMTPUsername:
		return &a.smtpUsername
	case agentDashboardAccessRowFrom:
		return &a.from
	default:
		return nil
	}
}

func (a *agentDashboardAccess) blur() {
	for _, input := range []*textinput.Model{&a.add, &a.issuer, &a.clientID, &a.secret, &a.metadataURL, &a.metadataFile, &a.entityID, &a.subjectAttribute, &a.smtpAddr, &a.smtpUsername, &a.from} {
		input.Blur()
	}
}

func (a *agentDashboardAccess) moveFocus(index int) {
	count := len(a.fields())
	a.focus = (index%count + count) % count
	a.blur()
	if input := a.focusedInput(); input != nil {
		_ = input.Focus()
	}
}

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

func (a agentDashboardAccess) request(stored AgentTunnelStatus) AgentTunnelUpdateRequest {
	if a.provider == "" {
		if stored.Provider == "" {
			return AgentTunnelUpdateRequest{}
		}
		return AgentTunnelUpdateRequest{Auth: map[string]json.RawMessage{"auth": json.RawMessage(`""`)}}
	}
	draft := a.accessDraft(stored)
	req := AgentTunnelUpdateRequest{Auth: authChanges(stored.AuthConfig, draft)}
	for key, value := range a.secretChanges(stored) {
		if req.Auth == nil {
			req.Auth = make(map[string]json.RawMessage)
		}
		req.Auth[key] = value
	}
	return req
}

func (a agentDashboardAccess) accessDraft(stored AgentTunnelStatus) appauth.Config {
	draft := appauth.Config{Provider: a.provider, IdentityHeaders: a.headers}
	if appauth.ProviderTakesEmailList(a.provider) && (a.provider != stored.Provider || len(stored.Allow) == 0) {
		draft.EmailList = a.allowed
	} else {
		draft.Allow = a.allowed
	}
	draft.OIDCConfig, draft.SAMLConfig, draft.EmailConfig = a.accessProviderConfigs()
	return draft
}

func (a agentDashboardAccess) accessProviderConfigs() (appauth.OIDCConfig, appauth.SAMLConfig, appauth.EmailConfig) {
	var oidc appauth.OIDCConfig
	var saml appauth.SAMLConfig
	var email appauth.EmailConfig
	switch a.provider {
	case appauth.ProviderOIDC:
		oidc = appauth.OIDCConfig{
			OIDCIssuerURL: strings.TrimSpace(a.issuer.Value()),
			OIDCClientID:  strings.TrimSpace(a.clientID.Value()),
		}
	case appauth.ProviderSAML:
		saml = appauth.SAMLConfig{
			SAMLMetadataURL:      strings.TrimSpace(a.metadataURL.Value()),
			SAMLMetadataFile:     strings.TrimSpace(a.metadataFile.Value()),
			SAMLEntityID:         strings.TrimSpace(a.entityID.Value()),
			SAMLSubjectAttribute: strings.TrimSpace(a.subjectAttribute.Value()),
		}
	case appauth.ProviderEmail:
		email = appauth.EmailConfig{
			SMTPAddr:     strings.TrimSpace(a.smtpAddr.Value()),
			SMTPUsername: strings.TrimSpace(a.smtpUsername.Value()),
			SMTPFrom:     strings.TrimSpace(a.from.Value()),
		}
	}
	return oidc, saml, email
}

func (a agentDashboardAccess) secretChanges(stored AgentTunnelStatus) map[string]json.RawMessage {
	var changes map[string]json.RawMessage
	for _, owned := range []struct{ provider, key string }{
		{appauth.ProviderOIDC, "auth_oidc_client_secret"},
		{appauth.ProviderEmail, "auth_smtp_password"},
	} {
		var secret string
		if a.provider == owned.provider {
			secret = strings.TrimSpace(a.secret.Value())
		}
		removeSecret := agentDashboardSecretSet(owned.provider, stored) && (a.provider != owned.provider || a.clearSecret)
		if secret != "" || removeSecret {
			if changes == nil {
				changes = make(map[string]json.RawMessage)
			}
			changes[owned.key], _ = json.Marshal(secret)
		}
	}
	return changes
}
func (m agentDashboardModel) applyAccess() (tea.Model, tea.Cmd) {
	tunnel, ok := m.accessTunnel()
	if !ok {
		return m, nil
	}
	req := m.access.request(tunnel)
	if m.access.applying || req.Empty() {
		return m, nil
	}
	m.access.err = nil
	m.access.applying = true
	stateDir, tunnelID := m.stateDir, tunnel.ID
	return m, func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := UpdateTunnel(ctx, stateDir, tunnelID, req)
		if errors.Is(err, context.DeadlineExceeded) {
			err = errors.New("the agent did not answer in time; the change may still be applied, the next status shows it")
		}
		return agentDashboardAccessMsg{tunnelID: tunnelID, err: err}
	}
}

func (m *agentDashboardModel) answerAccess(msg agentDashboardAccessMsg) {
	if msg.tunnelID != m.access.tunnelID || !m.access.applying {
		m.err = msg.err
		return
	}
	m.access.applying = false
	m.access.err = msg.err
	if msg.err == nil {
		m.access.forgetSecret()
		m.access.applied = true
	}
}

func (m *agentDashboardModel) addAccessEntry() {
	a := &m.access
	entry := strings.TrimSpace(a.add.Value())
	if entry == "" {
		return
	}
	normalized, err := appauth.Config{Provider: a.provider, Allow: []string{entry}}.Normalize()
	if err != nil {
		a.err = err
		return
	}
	a.err = nil
	a.add.Reset()
	if !slices.Contains(a.allowed, normalized.Allow[0]) {
		a.allowed = append(slices.Clone(a.allowed), normalized.Allow[0])
	}
	a.moveFocus(slices.IndexFunc(a.fields(), func(field agentDashboardAccessField) bool { return field.row == agentDashboardAccessRowAdd }))
}

func (a *agentDashboardAccess) removeEntry() {
	if field := a.current(); field.row == agentDashboardAccessRowEntry {
		a.allowed = slices.Delete(slices.Clone(a.allowed), field.entry, field.entry+1)
		a.err = nil
		a.moveFocus(a.focusIndex())
	}
}

func (m *agentDashboardModel) changeAccessChoice(step int) {
	a := &m.access
	switch a.current().row {
	case agentDashboardAccessRowMode:
		tunnel, ok := m.accessTunnel()
		if !ok {
			return
		}
		count := len(agentDashboardAccessProviders)
		index := slices.Index(agentDashboardAccessProviders, a.provider)
		a.setProvider(agentDashboardAccessProviders[((index+step)%count+count)%count], tunnel)
	case agentDashboardAccessRowHeaders:
		a.headers = !a.headers
	}
}

func (a *agentDashboardAccess) toggleReveal() {
	if a.revealed() {
		a.secret.EchoMode = textinput.EchoPassword
	} else {
		a.secret.EchoMode = textinput.EchoNormal
	}
}

func (a agentDashboardAccess) revealed() bool { return a.secret.EchoMode == textinput.EchoNormal }
