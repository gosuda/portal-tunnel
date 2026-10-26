package agent

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	agentDashboardSettingsFieldMaxActiveRelays = iota
	agentDashboardSettingsFieldDescription
	agentDashboardSettingsFieldTags
	agentDashboardSettingsFieldOwner
	agentDashboardSettingsFieldThumbnail
	agentDashboardSettingsFieldHide
	agentDashboardSettingsFieldCount
)

func (m *agentDashboardModel) focusSettingsField(field int) {
	fieldCount := agentDashboardSettingsFieldCount
	if field < 0 {
		field = fieldCount - 1
	}
	if field >= fieldCount {
		field = 0
	}
	m.blurAddTunnelInputs()
	m.settingsFocus = field
	for _, input := range []*textinput.Model{
		&m.settingsMaxRelays,
		&m.metadataDescription,
		&m.metadataTags,
		&m.metadataOwner,
		&m.metadataThumbnail,
		&m.metadataHide,
	} {
		input.Blur()
	}
	if input := m.focusedSettingsInput(); input != nil {
		_ = input.Focus()
	}
}

func (m *agentDashboardModel) focusedSettingsInput() *textinput.Model {
	switch m.settingsFocus {
	case agentDashboardSettingsFieldMaxActiveRelays:
		return &m.settingsMaxRelays
	case agentDashboardSettingsFieldDescription:
		return &m.metadataDescription
	case agentDashboardSettingsFieldTags:
		return &m.metadataTags
	case agentDashboardSettingsFieldOwner:
		return &m.metadataOwner
	case agentDashboardSettingsFieldThumbnail:
		return &m.metadataThumbnail
	case agentDashboardSettingsFieldHide:
		return &m.metadataHide
	default:
		return nil
	}
}

func (m *agentDashboardModel) blurSettingsInputs() {
	for _, input := range []*textinput.Model{
		&m.settingsMaxRelays,
		&m.metadataDescription,
		&m.metadataTags,
		&m.metadataOwner,
		&m.metadataThumbnail,
		&m.metadataHide,
	} {
		input.Blur()
	}
}

func (m *agentDashboardModel) clearSettingsDraft() {
	m.settingsEditTunnelID = ""
	for _, input := range []*textinput.Model{
		&m.settingsMaxRelays,
		&m.metadataDescription,
		&m.metadataTags,
		&m.metadataOwner,
		&m.metadataThumbnail,
		&m.metadataHide,
	} {
		input.Reset()
	}
	m.blurSettingsInputs()
	if m.activePane == agentDashboardPaneTunnels && m.addingTunnel {
		m.focusAddTunnelField(m.addFocus)
	}
}

func (m *agentDashboardModel) ensureSelectedSettingsDraft() {
	tunnel, ok := m.selectedTunnelStatus()
	if !ok {
		return
	}
	m.ensureSettingsDraft(tunnel)
}

func (m *agentDashboardModel) ensureSettingsDraft(tunnel AgentTunnelStatus) {
	if m.settingsEditTunnelID == tunnel.ID {
		return
	}
	m.loadSettingsDraft(tunnel)
}

func (m *agentDashboardModel) loadSettingsDraft(tunnel AgentTunnelStatus) {
	metadata := tunnel.Metadata
	m.settingsEditTunnelID = tunnel.ID
	m.settingsMaxRelays.SetValue(strconv.Itoa(tunnel.MaxActiveRelays))
	m.metadataDescription.SetValue(strings.TrimSpace(metadata.Description))
	m.metadataTags.SetValue(strings.Join(metadata.Tags, ","))
	m.metadataOwner.SetValue(strings.TrimSpace(metadata.Owner))
	m.metadataThumbnail.SetValue(strings.TrimSpace(metadata.Thumbnail))
	m.metadataHide.SetValue(strconv.FormatBool(metadata.Hide))
	m.settingsMaxRelays.CursorEnd()
	m.metadataDescription.CursorEnd()
	m.metadataTags.CursorEnd()
	m.metadataOwner.CursorEnd()
	m.metadataThumbnail.CursorEnd()
	m.metadataHide.CursorEnd()
}

func (m agentDashboardModel) applySettingsEdit() (tea.Model, tea.Cmd) {
	tunnel, ok := m.selectedTunnelStatus()
	if !ok {
		return m, nil
	}
	if !m.settingsChanged(tunnel) {
		return m, nil
	}
	maxActiveRelays, err := strconv.Atoi(strings.TrimSpace(m.settingsMaxRelays.Value()))
	if err != nil || maxActiveRelays <= 0 {
		m.err = fmt.Errorf("max active relays must be a positive integer")
		return m, nil
	}

	hideRaw := strings.TrimSpace(m.metadataHide.Value())
	hideRaw = cmp.Or(hideRaw, "false")
	hide, err := strconv.ParseBool(hideRaw)
	if err != nil {
		m.err = fmt.Errorf("metadata hidden must be true or false")
		return m, nil
	}

	description := strings.TrimSpace(m.metadataDescription.Value())
	tags := utils.SplitCSV(m.metadataTags.Value())
	owner := strings.TrimSpace(m.metadataOwner.Value())
	thumbnail := strings.TrimSpace(m.metadataThumbnail.Value())
	metadata := AgentMetadataRequest{
		Description: &description,
		Tags:        &tags,
		Owner:       &owner,
		Thumbnail:   &thumbnail,
		Hide:        &hide,
	}
	req := AgentTunnelUpdateRequest{
		MaxActiveRelays: &maxActiveRelays,
		Metadata:        &metadata,
	}
	m.err = nil
	return m, agentDashboardRun(func(ctx context.Context) error {
		return UpdateTunnel(ctx, m.stateDir, tunnel.ID, req)
	})
}

func (m agentDashboardModel) renderSettingsSection(width, rows int) agentDashboardView {
	th := &m.theme
	var pane agentDashboardView
	tunnel, ok := m.selectedTunnelStatus()
	if !ok {
		pane.addStyled(width, th.muted, "select a tunnel")
		return pane
	}

	applyLabel := "Apply"
	settingsChanged := m.settingsChanged(tunnel)
	if m.settingsEditTunnelID == tunnel.ID && !settingsChanged {
		applyLabel = "Applied"
	}
	pane.addButtons(th, width,
		agentDashboardButton{label: applyLabel, action: agentDashboardActionApplySettings, disabled: !settingsChanged},
	)

	var body agentDashboardView
	m.renderSettingsInputRows(&body, width, tunnel)
	focus, bodyRows := 0, 0
	if m.activePane == agentDashboardPaneSettings {
		focus = m.settingsFocus
	}
	if rows > 0 {
		bodyRows = max(1, rows-len(pane.lines))
	}
	pane.addView(body.window(focus, bodyRows))
	return pane
}

// renderSettingsInputRows draws one line per input, in field order, followed by
// the read-only details.
func (m agentDashboardModel) renderSettingsInputRows(pane *agentDashboardView, width int, tunnel AgentTunnelStatus) {
	th := &m.theme
	rows := []struct {
		label string
		input textinput.Model
		field int
	}{
		{label: "Max Relays", input: m.settingsMaxRelays, field: agentDashboardSettingsFieldMaxActiveRelays},
		{label: "Description", input: m.metadataDescription, field: agentDashboardSettingsFieldDescription},
		{label: "Tags", input: m.metadataTags, field: agentDashboardSettingsFieldTags},
		{label: "Owner", input: m.metadataOwner, field: agentDashboardSettingsFieldOwner},
		{label: "Thumbnail", input: m.metadataThumbnail, field: agentDashboardSettingsFieldThumbnail},
		{label: "Hidden", input: m.metadataHide, field: agentDashboardSettingsFieldHide},
	}
	for _, row := range rows {
		focused := m.activePane == agentDashboardPaneSettings && m.settingsFocus == row.field
		pane.addInputRow(th, width, row.label, row.input, agentDashboardActionFocusSettingsField, row.field, focused)
	}
	pane.addMeta(th, width, agentDashboardDetailLabelWidth, 0, "Discovery", strconv.FormatBool(tunnel.Discovery))
	pane.addAccessSummary(th, width, tunnel)

	paidRouteCount := 0
	for _, route := range tunnel.HTTPRoutes {
		if strings.TrimSpace(route.Amount) != "" {
			paidRouteCount++
		}
	}
	payTo := strings.TrimSpace(tunnel.PayTo)
	if payTo == "" && len(tunnel.HTTPRoutes) == 0 {
		return
	}
	pane.addLine("")
	pane.addStyled(width, th.muted, "Payments")
	if payTo != "" {
		pane.addMeta(th, width, agentDashboardDetailLabelWidth, 0, "Pay To", payTo)
	}
	if payTo != "" || paidRouteCount > 0 {
		pane.addMeta(th, width, agentDashboardDetailLabelWidth, 0, "Network", agentDashboardX402Network(tunnel.Network, tunnel.Testnet))
	}
	if strings.TrimSpace(tunnel.Asset) != "" {
		pane.addMeta(th, width, agentDashboardDetailLabelWidth, 0, "Asset", tunnel.Asset)
	}
	if len(tunnel.HTTPRoutes) == 0 {
		pane.addStyled(width, th.muted, "no routed HTTP paths")
		return
	}

	shown := 0
	for _, route := range tunnel.HTTPRoutes {
		if shown >= 4 {
			break
		}
		pane.addStyled(width, th.text, agentDashboardHTTPRouteSummary(route))
		shown++
	}
	if len(tunnel.HTTPRoutes) > shown {
		pane.addStyled(width, th.muted, fmt.Sprintf("+%d more routes", len(tunnel.HTTPRoutes)-shown))
	}
	if paidRouteCount == 0 {
		pane.addStyled(width, th.muted, "no paid routes")
	}
}

func agentDashboardHTTPRouteSummary(route tunnel.HTTPRoute) string {
	prefix := strings.TrimSpace(route.Prefix)
	prefix = cmp.Or(prefix, "-")
	upstream := strings.TrimSpace(route.Upstream)
	upstream = cmp.Or(upstream, "-")
	if amount := strings.TrimSpace(route.Amount); amount != "" {
		methods := "ALL"
		if len(route.Methods) > 0 {
			var normalized []string
			for _, raw := range route.Methods {
				if method := strings.ToUpper(strings.TrimSpace(raw)); method != "" {
					normalized = append(normalized, method)
				}
			}
			if len(normalized) > 0 {
				methods = strings.Join(normalized, ",")
			}
		}
		return fmt.Sprintf("%s -> %s (%s %s)", prefix, upstream, methods, amount)
	}
	return prefix + " -> " + upstream
}

func agentDashboardX402Network(network string, testnet bool) string {
	if network = strings.TrimSpace(network); network != "" {
		return network
	}
	if testnet {
		return "sui:testnet"
	}
	return "sui:mainnet"
}

func (m agentDashboardModel) settingsChanged(tunnel AgentTunnelStatus) bool {
	if m.settingsEditTunnelID != tunnel.ID {
		return false
	}
	maxRelays, err := strconv.Atoi(strings.TrimSpace(m.settingsMaxRelays.Value()))
	if err != nil {
		return true
	}
	hide, err := strconv.ParseBool(utils.StringOrDefault(strings.TrimSpace(m.metadataHide.Value()), "false"))
	if err != nil {
		return true
	}
	metadata := tunnel.Metadata
	return maxRelays != tunnel.MaxActiveRelays ||
		strings.TrimSpace(m.metadataDescription.Value()) != strings.TrimSpace(metadata.Description) ||
		!slices.Equal(utils.SplitCSV(m.metadataTags.Value()), metadata.Tags) ||
		strings.TrimSpace(m.metadataOwner.Value()) != strings.TrimSpace(metadata.Owner) ||
		strings.TrimSpace(m.metadataThumbnail.Value()) != strings.TrimSpace(metadata.Thumbnail) ||
		hide != metadata.Hide
}
