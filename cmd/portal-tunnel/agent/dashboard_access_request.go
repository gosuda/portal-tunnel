package agent

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
)

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
