package agent

import (
	"errors"
	"slices"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
)

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
