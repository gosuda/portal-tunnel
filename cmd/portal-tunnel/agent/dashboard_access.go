package agent

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
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

// agentDashboardAccessProviders lists the access modes in the order left and
// right step through them.
var agentDashboardAccessProviders = []string{
	"",
	gateway.ApplicationAuthProviderCredential,
	gateway.ApplicationAuthProviderSIWE,
	gateway.ApplicationAuthProviderOIDC,
}

// agentDashboardAccessMessageLines is how many lines of an error, or of the
// reason a provider check failed, the Access screen keeps.
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
)

// agentDashboardAccessField is one stop of the focus ring of the Access screen.
type agentDashboardAccessField struct {
	row   agentDashboardAccessRow
	entry int // index into the allow list of an entry row
}

// agentDashboardAccess is the draft behind the Access screen; the screen is
// open while tunnelID is set. A typed secret lives only in its input: it is
// cleared when the screen closes, when the mode changes and after a successful
// apply, and it is drawn only while the input is revealed.
type agentDashboardAccess struct {
	tunnelID    string
	focus       int // index into fields
	provider    string
	headers     bool
	allowed     []string
	clearSecret bool // the stored client secret is to be removed
	err         error

	add, issuer, clientID, secret textinput.Model
}

// agentDashboardAccessMsg is the answer to the PATCH that applies a draft.
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
	}
}

func (m agentDashboardModel) accessing() bool { return m.access.tunnelID != "" }

// accessTunnel is the status of the tunnel the Access screen is open for.
func (m agentDashboardModel) accessTunnel() (AgentTunnelStatus, bool) {
	index := slices.IndexFunc(m.status.Tunnels, func(tunnel AgentTunnelStatus) bool { return tunnel.ID == m.access.tunnelID })
	if index < 0 {
		return AgentTunnelStatus{}, false
	}
	return m.status.Tunnels[index], true
}

// openAccess opens the Access screen for the selected tunnel with a draft of
// what is stored. The dashboard reads the status with the agent's own token, so
// the allow list in it is complete.
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

// closeAccess leaves the Access screen and drops the draft, secret included.
func (m *agentDashboardModel) closeAccess() {
	a := &m.access
	a.forgetSecret()
	a.add.Reset()
	a.issuer.Reset()
	a.clientID.Reset()
	a.blur()
	a.tunnelID = ""
	a.allowed = nil
	a.err = nil
}

// load makes the draft equal to what the tunnel has stored. The secret input
// is not part of that: it is empty whenever the screen is closed, and every
// change of mode empties it.
func (a *agentDashboardAccess) load(tunnel AgentTunnelStatus) {
	a.provider = tunnel.Auth
	a.headers = tunnel.AuthIdentityHeaders
	a.allowed = slices.Clone(tunnel.AuthAllowedWallets)
	a.err = nil
	a.add.Reset()
	a.issuer.SetValue(tunnel.AuthOIDCIssuer)
	a.issuer.CursorEnd()
	a.clientID.SetValue(tunnel.AuthOIDCClientID)
	a.clientID.CursorEnd()
}

// forgetSecret drops a typed secret, a pending removal of the stored one, and
// the reveal.
func (a *agentDashboardAccess) forgetSecret() {
	a.secret.Reset()
	a.secret.EchoMode = textinput.EchoPassword
	a.clearSecret = false
}

// setProvider switches the draft to provider and drops a typed secret. The
// allow list and the OIDC settings belong to one provider, so another provider
// than the stored one starts without them; coming back to the stored one
// restores what is stored.
func (a *agentDashboardAccess) setProvider(provider string, stored AgentTunnelStatus) {
	if provider == a.provider {
		return
	}
	a.forgetSecret()
	if provider == stored.Auth {
		a.load(stored)
		return
	}
	a.provider = provider
	a.headers = a.headers && provider != ""
	a.allowed = nil
	a.err = nil
	a.add.Reset()
	a.issuer.Reset()
	a.clientID.Reset()
}

// fields is the focus ring: the mode, then, unless the tunnel is open, the
// allow list entries, the entry input, the identity headers and, for OIDC, the
// provider settings.
func (a agentDashboardAccess) fields() []agentDashboardAccessField {
	fields := []agentDashboardAccessField{{row: agentDashboardAccessRowMode}}
	if a.provider == "" {
		return fields
	}
	for i := range a.allowed {
		fields = append(fields, agentDashboardAccessField{row: agentDashboardAccessRowEntry, entry: i})
	}
	fields = append(fields, agentDashboardAccessField{row: agentDashboardAccessRowAdd}, agentDashboardAccessField{row: agentDashboardAccessRowHeaders})
	if a.provider == gateway.ApplicationAuthProviderOIDC {
		fields = append(fields,
			agentDashboardAccessField{row: agentDashboardAccessRowIssuer},
			agentDashboardAccessField{row: agentDashboardAccessRowClientID},
			agentDashboardAccessField{row: agentDashboardAccessRowSecret},
		)
	}
	return fields
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
	default:
		return nil
	}
}

func (a *agentDashboardAccess) blur() {
	for _, input := range []*textinput.Model{&a.add, &a.issuer, &a.clientID, &a.secret} {
		input.Blur()
	}
}

// moveFocus focuses the field at index of the ring, wrapping around its ends.
func (a *agentDashboardAccess) moveFocus(index int) {
	count := len(a.fields())
	a.focus = (index%count + count) % count
	a.blur()
	if input := a.focusedInput(); input != nil {
		_ = input.Focus()
	}
}

// request is the PATCH that turns what the tunnel has stored into the draft. It
// names only what differs, because a named field replaces the stored one. An
// empty secret input leaves the stored secret alone; only clearSecret, or
// leaving OIDC, sends an empty one.
func (a agentDashboardAccess) request(stored AgentTunnelStatus) AgentTunnelUpdateRequest {
	var req AgentTunnelUpdateRequest
	if a.provider != stored.Auth {
		req.Auth = &a.provider
	}
	if a.provider == "" {
		// The agent clears the other settings itself and refuses them next to an empty auth.
		return req
	}
	if !slices.Equal(a.allowed, stored.AuthAllowedWallets) {
		// An empty list must reach the agent as [], since null leaves the list as it is.
		allowed := append([]string{}, a.allowed...)
		req.AuthAllowedWallets = &allowed
	}
	if a.headers != stored.AuthIdentityHeaders {
		headers := a.headers
		req.AuthIdentityHeaders = &headers
	}

	// Leaving OIDC clears its settings, as the validators refuse them for another provider.
	var issuer, clientID, secret string
	if a.provider == gateway.ApplicationAuthProviderOIDC {
		issuer = strings.TrimSpace(a.issuer.Value())
		clientID = strings.TrimSpace(a.clientID.Value())
		secret = strings.TrimSpace(a.secret.Value())
	}
	if issuer != stored.AuthOIDCIssuer {
		req.AuthOIDCIssuer = &issuer
	}
	if clientID != stored.AuthOIDCClientID {
		req.AuthOIDCClientID = &clientID
	}
	removeSecret := stored.AuthOIDCClientSecretSet && (a.provider != gateway.ApplicationAuthProviderOIDC || a.clearSecret)
	if secret != "" || removeSecret {
		req.AuthOIDCClientSecret = &secret
	}
	return req
}

func (m agentDashboardModel) applyAccess() (tea.Model, tea.Cmd) {
	tunnel, ok := m.accessTunnel()
	if !ok {
		return m, nil
	}
	req := m.access.request(tunnel)
	if req.Empty() {
		return m, nil
	}
	m.access.err = nil
	// The command holds the request, not the model, so that a typed secret has
	// no other copy than the one in its input and the request on its way.
	stateDir, tunnelID := m.stateDir, tunnel.ID
	return m, func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return agentDashboardAccessMsg{tunnelID: tunnelID, err: UpdateTunnel(ctx, stateDir, tunnelID, req)}
	}
}

// answerAccess handles the answer to applyAccess. A refusal stays on the
// screen with the secret still typed, so that the rest can be corrected; a
// success drops the secret. The screen keeps its own error because the status
// poll that follows every answer replaces the dashboard's.
func (m *agentDashboardModel) answerAccess(msg agentDashboardAccessMsg) {
	if msg.tunnelID != m.access.tunnelID {
		m.err = msg.err // the screen was closed while the request ran
		return
	}
	m.access.err = msg.err
	if msg.err == nil {
		m.access.forgetSecret()
	}
}

// addAccessEntry moves the typed entry to the allow list. The gateway
// normalizes it for the provider, so a wrong entry is refused at once.
func (m *agentDashboardModel) addAccessEntry() {
	a := &m.access
	entry := strings.TrimSpace(a.add.Value())
	if entry == "" {
		return
	}
	normalized, err := gateway.NormalizeApplicationAuthAllowed(a.provider, []string{entry})
	if err != nil {
		a.err = err
		return
	}
	a.err = nil
	a.add.Reset()
	if !slices.Contains(a.allowed, normalized[0]) {
		a.allowed = append(slices.Clone(a.allowed), normalized[0])
	}
	// The entry row is one further down now that the list grew.
	a.moveFocus(slices.IndexFunc(a.fields(), func(field agentDashboardAccessField) bool { return field.row == agentDashboardAccessRowAdd }))
}

func (a *agentDashboardAccess) removeEntry() {
	if field := a.current(); field.row == agentDashboardAccessRowEntry {
		a.allowed = slices.Delete(slices.Clone(a.allowed), field.entry, field.entry+1)
		a.err = nil
		a.moveFocus(a.focusIndex())
	}
}

// changeAccessChoice steps the mode through the providers, or flips the
// identity headers, depending on the focused row.
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

func (m agentDashboardModel) renderAccess(width, height int) agentDashboardView {
	th := &m.theme
	inner := width - agentDashboardFrameWidth
	a := m.access
	tunnel, _ := m.accessTunnel()

	changed := !a.request(tunnel).Empty()
	applyLabel := "Apply"
	if !changed {
		applyLabel = "Applied"
	}
	var content agentDashboardView
	if m.confirmStop {
		// The screen stands in for the Tunnels pane, where the question is drawn otherwise.
		content.addStyled(inner, th.pending, agentDashboardStopQuestion)
		content.addButtons(th, inner,
			agentDashboardButton{label: "Yes", action: agentDashboardActionAnswerYes},
			agentDashboardButton{label: "No", action: agentDashboardActionAnswerNo},
		)
	} else {
		content.addButtons(th, inner,
			agentDashboardButton{label: applyLabel, action: agentDashboardActionApplyAccess, disabled: !changed},
			agentDashboardButton{label: "Cancel", action: agentDashboardActionCancelAccess},
		)
	}
	if a.err != nil {
		for _, line := range agentDashboardWrap(th.glyph.ledFailed+" Error: "+a.err.Error(), inner, agentDashboardAccessMessageLines) {
			content.addLine(th.failed.Render(line))
		}
	}

	var body agentDashboardView
	focusLine := 0
	for index, field := range a.fields() {
		focused := index == a.focusIndex()
		if focused {
			focusLine = len(body.lines)
		}
		switch field.row {
		case agentDashboardAccessRowMode:
			body.addAccessChoice(th, inner, "Mode", agentDashboardAccessMode(a.provider), index, focused)
			if a.provider != "" {
				body.addAccessAllowed(th, inner, a)
			}
		case agentDashboardAccessRowEntry:
			body.addAccessEntryRow(th, inner, a.allowed[field.entry], index, focused)
		case agentDashboardAccessRowAdd:
			input := a.add
			input.Placeholder = agentDashboardAccessEntryPlaceholder(a.provider)
			body.addInputRow(th, inner, "Add entry", input, agentDashboardActionFocusAccessField, index, focused)
		case agentDashboardAccessRowHeaders:
			body.addAccessChoice(th, inner, "Headers", agentDashboardIdentityHeaders(a.headers), index, focused)
		case agentDashboardAccessRowIssuer:
			body.addInputRow(th, inner, "Issuer", a.issuer, agentDashboardActionFocusAccessField, index, focused)
		case agentDashboardAccessRowClientID:
			body.addInputRow(th, inner, "Client ID", a.clientID, agentDashboardActionFocusAccessField, index, focused)
		case agentDashboardAccessRowSecret:
			input, label := a.secret, "Client secret"
			input.Placeholder = agentDashboardSecretPlaceholder(a, tunnel)
			if a.revealed() {
				label = "Secret (shown)"
			}
			body.addInputRow(th, inner, label, input, agentDashboardActionFocusAccessField, index, focused)
		}
	}
	body.addLine("")
	if tunnel.Auth == gateway.ApplicationAuthProviderOIDC {
		check, style := agentDashboardProviderCheck(th, tunnel)
		body.addAccessValue(th, inner, "Provider check", check, style)
		for _, line := range agentDashboardWrap(tunnel.AuthOIDCProviderError, inner, agentDashboardAccessMessageLines) {
			body.addLine(style.Render(line))
		}
	}
	// A changed sign-in gate restarts the tunnel from its saved settings.
	for _, line := range agentDashboardWrap("Applying restarts this tunnel and drops the relays connected to it at runtime.", inner, 2) {
		body.addLine(th.muted.Render(line))
	}

	rows := 0
	if height > 0 {
		rows = max(1, height-agentDashboardFrameHeight-len(content.lines))
	}
	content.addView(body.window(focusLine, rows))

	var out agentDashboardView
	out.addFrame(th, "ACCESS: "+tunnelDashboardName(tunnel), true, width, max(0, height-agentDashboardFrameHeight), content)
	return out
}

func agentDashboardAccessEntryPlaceholder(provider string) string {
	switch provider {
	case gateway.ApplicationAuthProviderSIWE:
		return "0x... wallet address"
	case gateway.ApplicationAuthProviderOIDC:
		return "email, @domain, sub:id"
	default:
		return "subject"
	}
}

// agentDashboardSecretPlaceholder says what the secret input stands for while it
// is empty: the stored secret stays unless it is marked for removal.
func agentDashboardSecretPlaceholder(a agentDashboardAccess, stored AgentTunnelStatus) string {
	switch {
	case a.clearSecret:
		return "will be removed"
	case stored.AuthOIDCClientSecretSet:
		return "set; type to replace"
	default:
		return "not set"
	}
}

// agentDashboardWrap breaks text into lines of at most width cells and keeps
// the first maxLines of them, marking the cut.
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

// addAccessChoice adds a row whose value changes with left and right.
func (v *agentDashboardView) addAccessChoice(th *agentDashboardTheme, width int, label, value string, field int, focused bool) {
	labelStyle, valueStyle, prompt := th.muted, th.text, th.glyph.promptBlurred
	if focused {
		labelStyle, valueStyle, prompt = th.bright, th.bright, th.glyph.promptFocused
		value = th.glyph.arrowLeft + " " + value + " " + th.glyph.arrowRight
	}
	valueWidth := max(1, width-agentDashboardLabelWidth-1-lipgloss.Width(prompt))
	v.addFieldRow(labelStyle.Render(agentDashboardCell(label+":", agentDashboardLabelWidth))+" "+th.strong.Render(prompt)+valueStyle.Render(agentDashboardFit(value, valueWidth)), width, field)
}

// addAccessAllowed adds the line above the allow list entries: how many there
// are, or what an empty list means for the provider.
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

// addAccessEntryRow adds one allow list entry, over the whole width so that a
// wallet address fits.
func (v *agentDashboardView) addAccessEntryRow(th *agentDashboardTheme, width int, entry string, field int, focused bool) {
	marker, style := th.glyph.unselected, th.text
	if focused {
		marker, style = th.glyph.selected, th.selected
	}
	v.addFieldRow(style.Width(width).Render(marker+agentDashboardFit(entry, max(1, width-lipgloss.Width(marker)))), width, field)
}

// addFieldRow adds a line that focuses a field of the Access screen on click.
func (v *agentDashboardView) addFieldRow(line string, width, field int) {
	v.regions = append(v.regions, agentDashboardRegion{x0: 0, x1: width, y: len(v.lines), action: agentDashboardActionFocusAccessField, field: field})
	v.addLine(line)
}
