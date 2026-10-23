package agent

import (
	"context"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

const agentDashboardPollInterval = 2 * time.Second

type agentDashboardAction int

const (
	agentDashboardActionSelectTunnel agentDashboardAction = iota + 1
	agentDashboardActionSelectPane
	agentDashboardActionAddTunnel
	agentDashboardActionCancelAddTunnel
	agentDashboardActionDeleteTunnel
	agentDashboardActionConnectRelay
	agentDashboardActionDisconnectRelay
	agentDashboardActionApplySettings
	agentDashboardActionFocusSettingsField
	agentDashboardActionFocusAddTunnelField
	agentDashboardActionOpenTunnelURL
)

type agentDashboardPane int

const (
	agentDashboardPaneTunnels agentDashboardPane = iota
	agentDashboardPaneSettings
	agentDashboardPaneRelays
	agentDashboardPaneCount
)

type agentDashboardModel struct {
	configPath string
	stateDir   string

	status AgentStatusResponse
	err    error

	width  int
	height int

	sidebarScrollX  int
	sidebarDragX    int
	sidebarDragging bool

	selectedTunnelID string
	selectedRelayURL string
	activePane       agentDashboardPane
	relayAttempts    map[relayAttemptKey]bool

	addingTunnel     bool
	addFocus         int
	addName          textinput.Model
	addTarget        textinput.Model
	addHTTPRoutes    textinput.Model
	addX402PayTo     textinput.Model
	addX402Testnet   textinput.Model
	addX402Network   textinput.Model
	addX402Asset     textinput.Model
	addX402Endpoints textinput.Model
	addRelays        textinput.Model
	addDiscovery     textinput.Model
	addMaxRelays     textinput.Model

	settingsEditTunnelID string
	settingsFocus        int
	settingsMaxRelays    textinput.Model
	metadataDescription  textinput.Model
	metadataTags         textinput.Model
	metadataOwner        textinput.Model
	metadataThumbnail    textinput.Model
	metadataHide         textinput.Model
}

type agentDashboardStatusMsg struct {
	status AgentStatusResponse
	err    error
}

type agentDashboardActionMsg struct {
	err error
}

type agentDashboardTickMsg struct{}

func RunDashboard(configPath, stateDir string) error {
	model := newAgentDashboardModel(configPath, stateDir)
	_, err := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run()
	return err
}

func newAgentDashboardModel(configPath, stateDir string) agentDashboardModel {
	model := agentDashboardModel{
		configPath:          configPath,
		stateDir:            stateDir,
		addName:             newAgentDashboardInlineInput("myapp"),
		addTarget:           newAgentDashboardInlineInput("3000"),
		addHTTPRoutes:       newAgentDashboardInlineInput("/paid=3001 GET:0.01; /=5173"),
		addX402PayTo:        newAgentDashboardInlineInput("0x..."),
		addX402Testnet:      newAgentDashboardInlineInput("false"),
		addX402Network:      newAgentDashboardInlineInput("casper:casper-test"),
		addX402Asset:        newAgentDashboardInlineInput("hash-..."),
		addX402Endpoints:    newAgentDashboardInlineInput("https://x402-facilitator.cspr.cloud"),
		addRelays:           newAgentDashboardInlineInput("https://portal.example.com"),
		addDiscovery:        newAgentDashboardInlineInput("true"),
		addMaxRelays:        newAgentDashboardInlineInput("3"),
		settingsMaxRelays:   newAgentDashboardInlineInput("3"),
		metadataDescription: newAgentDashboardInlineInput("description"),
		metadataTags:        newAgentDashboardInlineInput("api,staging"),
		metadataOwner:       newAgentDashboardInlineInput("owner"),
		metadataThumbnail:   newAgentDashboardInlineInput("https://..."),
		metadataHide:        newAgentDashboardInlineInput("true or false"),
	}
	model.resetAddTunnelForm()
	model.resizeInputs(0)
	return model
}

func newAgentDashboardTextInput() textinput.Model {
	input := textinput.New()
	input.CharLimit = 512
	input.PromptStyle = agentDashboardSectionStyle
	input.TextStyle = agentDashboardInputStyle
	input.PlaceholderStyle = agentDashboardMutedStyle
	return input
}

func newAgentDashboardInlineInput(placeholder string) textinput.Model {
	input := newAgentDashboardTextInput()
	input.Placeholder = placeholder
	return input
}

func (m agentDashboardModel) Init() tea.Cmd {
	return tea.Batch(agentDashboardFetchStatus(m.stateDir), agentDashboardTick(), textinput.Blink)
}

func (m agentDashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.resizeInputs(msg.Width)
		m.clampSidebarScroll()
		return m, nil
	case agentDashboardTickMsg:
		return m, tea.Batch(agentDashboardFetchStatus(m.stateDir), agentDashboardTick())
	case agentDashboardStatusMsg:
		m.err = msg.err
		if msg.err == nil {
			m.status = msg.status
			if strings.TrimSpace(msg.status.ConfigPath) != "" {
				m.configPath = msg.status.ConfigPath
			}
			m.clampSelection()
			m.ensureSelectedSettingsDraft()
			m.syncRelayAttempts()
			m.clampSidebarScroll()
		}
		return m, nil
	case agentDashboardActionMsg:
		m.err = msg.err
		return m, agentDashboardFetchStatus(m.stateDir)
	case tea.KeyMsg:
		return m.updateKeys(msg)
	case tea.MouseMsg:
		return m.updateMouse(msg)
	default:
		return m, nil
	}
}

func (m agentDashboardModel) updateKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.err = nil
		if m.activePane == agentDashboardPaneTunnels {
			if m.addingTunnel {
				m.cancelTunnelInput()
			}
		} else {
			m.setActivePane(agentDashboardPaneTunnels)
		}
		return m, nil
	case "left":
		m.setActivePane(m.activePane - 1)
		return m, nil
	case "right":
		m.setActivePane(m.activePane + 1)
		return m, nil
	}

	switch m.activePane {
	case agentDashboardPaneTunnels:
		return m.updateTunnelKeys(msg)
	case agentDashboardPaneRelays:
		return m.updateRelayKeys(msg)
	case agentDashboardPaneSettings:
		return m.updateSettingsKeys(msg)
	default:
		m.setActivePane(agentDashboardPaneTunnels)
		return m, nil
	}
}

func (m agentDashboardModel) updateTunnelKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.addingTunnel {
		switch msg.String() {
		case "tab", "down":
			m.focusAddTunnelField(m.addFocus + 1)
			return m, nil
		case "shift+tab", "up":
			m.focusAddTunnelField(m.addFocus - 1)
			return m, nil
		case "enter":
			return m.addTunnelFromInput()
		}

		input := m.focusedAddTunnelInput()
		if input == nil {
			return m, nil
		}
		var cmd tea.Cmd
		*input, cmd = input.Update(msg)
		return m, cmd
	}

	switch msg.String() {
	case "up":
		m.selectTunnelOffset(-1)
		return m, nil
	case "down":
		m.selectTunnelOffset(1)
		return m, nil
	case "delete":
		return m.deleteTunnel("")
	}
	return m, nil
}

func (m agentDashboardModel) updateRelayKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up":
		m.selectRelayOffset(-1)
	case "down":
		m.selectRelayOffset(1)
	case "enter", "c":
		return m.connectSelectedRelay()
	case "d", "delete":
		return m.disconnectSelectedRelay()
	case "o":
		return m.openRelayTunnelURL("", "")
	}
	return m, nil
}

func (m agentDashboardModel) updateSettingsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "tab", "down":
		m.focusSettingsField(m.settingsFocus + 1)
		return m, nil
	case "shift+tab", "up":
		m.focusSettingsField(m.settingsFocus - 1)
		return m, nil
	case "enter":
		return m.applySettingsEdit()
	}

	input := m.focusedSettingsInput()
	if input == nil {
		return m, nil
	}
	var cmd tea.Cmd
	*input, cmd = input.Update(msg)
	return m, cmd
}

func (m agentDashboardModel) updateMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	event := tea.MouseEvent(msg)
	switch event.Button {
	case tea.MouseButtonWheelUp:
		return m.scrollActivePane(-1)
	case tea.MouseButtonWheelDown:
		return m.scrollActivePane(1)
	}
	if m.sidebarDragging {
		switch event.Action {
		case tea.MouseActionMotion:
			m.sidebarScrollX += m.sidebarDragX - event.X
			m.sidebarDragX = event.X
			m.clampSidebarScroll()
			return m, nil
		case tea.MouseActionRelease:
			m.sidebarDragging = false
			return m, nil
		}
	}
	if event.Action != tea.MouseActionPress || event.Button != tea.MouseButtonLeft {
		return m, nil
	}
	if m.mouseInSidebar(event) {
		m.sidebarDragging = true
		m.sidebarDragX = event.X
		return m, nil
	}
	for _, region := range m.layout().regions {
		if event.Y == region.y && event.X >= region.x0 && event.X < region.x1 {
			if region.action == agentDashboardActionSelectPane {
				m.setActivePane(region.pane)
				return m, nil
			}
			if region.action == agentDashboardActionFocusSettingsField {
				m.setActivePane(agentDashboardPaneSettings)
				m.focusSettingsField(region.field)
				return m, nil
			}
			if region.action == agentDashboardActionFocusAddTunnelField {
				m.setActivePane(agentDashboardPaneTunnels)
				if !m.addingTunnel {
					m.addingTunnel = true
					m.resetAddTunnelForm()
				}
				m.focusAddTunnelField(region.field)
				return m, nil
			}
			return m.runAction(region.action, region.tunnel, region.relay)
		}
	}
	return m, nil
}

func (m agentDashboardModel) runAction(action agentDashboardAction, tunnelID, relayURL string) (tea.Model, tea.Cmd) {
	switch action {
	case agentDashboardActionSelectTunnel:
		if tunnelID != "" {
			m.selectTunnel(tunnelID)
		}
	case agentDashboardActionAddTunnel:
		return m.startOrAddTunnel()
	case agentDashboardActionCancelAddTunnel:
		m.cancelTunnelInput()
	case agentDashboardActionDeleteTunnel:
		return m.deleteTunnel(tunnelID)
	case agentDashboardActionConnectRelay:
		return m.connectSelectedRelay()
	case agentDashboardActionDisconnectRelay:
		return m.disconnectSelectedRelay()
	case agentDashboardActionApplySettings:
		return m.applySettingsEdit()
	case agentDashboardActionOpenTunnelURL:
		return m.openRelayTunnelURL(tunnelID, relayURL)
	}
	return m, nil
}

func (m agentDashboardModel) View() string {
	layout := m.layout()
	lines := layout.lines
	if m.height > 0 {
		if len(lines) > m.height {
			lines = lines[:m.height]
		}
		for len(lines) < m.height {
			lines = append(lines, "")
		}
	}
	return strings.Join(lines, "\n")
}

func (m agentDashboardModel) selectedTunnelIndex() int {
	if len(m.status.Tunnels) == 0 {
		return -1
	}
	for i, tunnel := range m.status.Tunnels {
		if tunnel.ID == m.selectedTunnelID {
			return i
		}
	}
	return 0
}

func (m *agentDashboardModel) selectTunnel(id string) {
	for i, tunnel := range m.status.Tunnels {
		if tunnel.ID == id {
			m.selectTunnelIndex(i)
			return
		}
	}
}

func (m *agentDashboardModel) selectTunnelIndex(index int) {
	if index < 0 || index >= len(m.status.Tunnels) {
		return
	}
	tunnelID := m.status.Tunnels[index].ID
	m.selectedTunnelID = tunnelID
	m.selectedRelayURL = ""
	if len(m.status.Tunnels[index].Relays) > 0 {
		m.selectedRelayURL = m.status.Tunnels[index].Relays[0].RelayURL
	}
	m.loadSettingsDraft(m.status.Tunnels[index])
}

func (m *agentDashboardModel) selectTunnelOffset(delta int) {
	index := m.selectedTunnelIndex()
	next := index + delta
	if next >= 0 && next < len(m.status.Tunnels) {
		m.selectTunnelIndex(next)
	}
}

func (m *agentDashboardModel) selectRelay(relayURL string) {
	m.selectedRelayURL = relayURL
}

func (m *agentDashboardModel) selectRelayOffset(delta int) {
	tunnel, ok := m.selectedTunnelStatus()
	index := m.selectedRelayIndex(tunnel)
	next := index + delta
	if !ok || next < 0 || next >= len(tunnel.Relays) {
		return
	}
	m.selectRelay(tunnel.Relays[next].RelayURL)
}

func (m *agentDashboardModel) setActivePane(pane agentDashboardPane) {
	if pane < 0 {
		pane = agentDashboardPaneCount - 1
	}
	if pane >= agentDashboardPaneCount {
		pane = 0
	}
	m.activePane = pane
	m.blurAddTunnelInputs()
	m.blurSettingsInputs()
	switch pane {
	case agentDashboardPaneTunnels:
		if m.addingTunnel {
			m.focusAddTunnelField(m.addFocus)
		}
	case agentDashboardPaneSettings:
		m.ensureSelectedSettingsDraft()
		if input := m.focusedSettingsInput(); input != nil {
			_ = input.Focus()
		}
	}
}

func (m agentDashboardModel) scrollActivePane(delta int) (tea.Model, tea.Cmd) {
	m.selectRelayOffset(delta)
	return m, nil
}

func (m *agentDashboardModel) clampSelection() {
	if len(m.status.Tunnels) == 0 {
		m.selectedTunnelID = ""
		m.selectedRelayURL = ""
		m.clearSettingsDraft()
		return
	}

	tunnelIndex := m.selectedTunnelIndex()
	tunnelID := m.status.Tunnels[tunnelIndex].ID
	m.selectedTunnelID = tunnelID
	m.ensureSettingsDraft(m.status.Tunnels[tunnelIndex])

	relays := m.status.Tunnels[tunnelIndex].Relays
	if len(relays) == 0 {
		m.selectedRelayURL = ""
		return
	}
	if m.selectedRelayURL != "" {
		for _, relay := range relays {
			if relay.RelayURL == m.selectedRelayURL {
				return
			}
		}
	}
	m.selectedRelayURL = relays[0].RelayURL
}

func (m agentDashboardModel) selectedTunnelStatus() (AgentTunnelStatus, bool) {
	index := m.selectedTunnelIndex()
	if index < 0 {
		return AgentTunnelStatus{}, false
	}
	return m.status.Tunnels[index], true
}

func (m agentDashboardModel) selectedRelayIndex(tunnel AgentTunnelStatus) int {
	if len(tunnel.Relays) == 0 {
		return -1
	}
	for i, relay := range tunnel.Relays {
		if relay.RelayURL == m.selectedRelayURL {
			return i
		}
	}
	return 0
}

func (m agentDashboardModel) selectedRelayStatus() (AgentRelayStatus, bool) {
	tunnel, ok := m.selectedTunnelStatus()
	index := m.selectedRelayIndex(tunnel)
	if !ok || index < 0 {
		return AgentRelayStatus{}, false
	}
	return tunnel.Relays[index], true
}

func (m agentDashboardModel) selectedTunnelRelay() (AgentTunnelStatus, AgentRelayStatus, bool) {
	tunnel, ok := m.selectedTunnelStatus()
	if !ok {
		return AgentTunnelStatus{}, AgentRelayStatus{}, false
	}
	relay, ok := m.selectedRelayStatus()
	if !ok {
		return AgentTunnelStatus{}, AgentRelayStatus{}, false
	}
	return tunnel, relay, true
}

func (m *agentDashboardModel) resizeInputs(width int) {
	if width <= 0 {
		width = 88
	}
	contentWidth, _, _ := agentDashboardColumnWidths(width)
	settingsWidth := max(1, min(agentDashboardTunnelInputMaxWidth, contentWidth-13))
	for _, input := range []*textinput.Model{
		&m.addName,
		&m.addTarget,
		&m.addHTTPRoutes,
		&m.addX402PayTo,
		&m.addX402Testnet,
		&m.addX402Network,
		&m.addX402Asset,
		&m.addX402Endpoints,
		&m.addRelays,
		&m.addDiscovery,
		&m.addMaxRelays,
		&m.settingsMaxRelays,
		&m.metadataDescription,
		&m.metadataTags,
		&m.metadataOwner,
		&m.metadataThumbnail,
		&m.metadataHide,
	} {
		input.Width = settingsWidth
	}
}

func agentDashboardFetchStatus(stateDir string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		status, err := Status(ctx, stateDir)
		return agentDashboardStatusMsg{status: status, err: err}
	}
}

func agentDashboardTick() tea.Cmd {
	return tea.Tick(agentDashboardPollInterval, func(t time.Time) tea.Msg {
		return agentDashboardTickMsg{}
	})
}

func agentDashboardRun(run func(context.Context) error) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		return agentDashboardActionMsg{err: run(ctx)}
	}
}
