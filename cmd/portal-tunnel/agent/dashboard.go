package agent

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	agentDashboardPollInterval = 2 * time.Second
	agentDashboardMinListRows  = 10
)

type agentDashboardMode int

const (
	agentDashboardNormalMode agentDashboardMode = iota
	agentDashboardAddTunnelMode
	agentDashboardAddRelayMode
)

type agentDashboardAction int

const (
	agentDashboardActionSelectTunnel agentDashboardAction = iota + 1
	agentDashboardActionSelectRelay
	agentDashboardActionAddTunnel
	agentDashboardActionDeleteTunnel
	agentDashboardActionAddRelay
	agentDashboardActionDeleteRelay
	agentDashboardActionAttachRelay
	agentDashboardActionDetachRelay
	agentDashboardActionAddHop
	agentDashboardActionRemoveHop
	agentDashboardActionApplyHop
	agentDashboardActionClearHop
)

type agentDashboardModel struct {
	configPath string
	stateDir   string

	status types.AgentStatusResponse
	err    error

	width  int
	height int

	selectedTunnelID string
	selectedRelayURL string

	routeDraft    []string
	draftTunnelID string

	mode  agentDashboardMode
	input textinput.Model
}

type agentDashboardStatusMsg struct {
	status types.AgentStatusResponse
	err    error
}

type agentDashboardActionMsg struct {
	err error
}

type agentDashboardTickMsg struct{}

type agentDashboardRegion struct {
	x0     int
	x1     int
	y      int
	action agentDashboardAction
	tunnel string
	relay  string
}

type agentDashboardButton struct {
	label    string
	action   agentDashboardAction
	disabled bool
}

type agentDashboardView struct {
	lines   []string
	regions []agentDashboardRegion
}

var (
	agentDashboardTitleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	agentDashboardSectionStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("81"))
	agentDashboardMutedStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	agentDashboardSelectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("25"))
	agentDashboardButtonStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("238"))
	agentDashboardDisabledStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	agentDashboardErrorStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	agentDashboardOKStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("120"))
	agentDashboardInputStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("120"))
)

func RunDashboard(configPath, stateDir string) error {
	input := textinput.New()
	input.CharLimit = 512
	input.Prompt = "> "
	input.Width = 72

	_, err := tea.NewProgram(agentDashboardModel{
		configPath: configPath,
		stateDir:   stateDir,
		input:      input,
	}, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run()
	return err
}

func (m agentDashboardModel) Init() tea.Cmd {
	return tea.Batch(agentDashboardFetchStatus(m.stateDir), agentDashboardTick())
}

func (m agentDashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.input.Width = max(1, min(88, msg.Width-8))
		return m, nil
	case agentDashboardTickMsg:
		return m, tea.Batch(agentDashboardFetchStatus(m.stateDir), agentDashboardTick())
	case agentDashboardStatusMsg:
		m.err = msg.err
		if msg.err == nil {
			m.status = msg.status
			m.clampSelection()
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
	if m.mode != agentDashboardNormalMode {
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			m.cancelInput()
			return m, nil
		case "enter":
			return m.submitInput()
		default:
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			return m, cmd
		}
	}

	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "up", "k":
		m.selectTunnelOffset(-1)
	case "down", "j":
		m.selectTunnelOffset(1)
	case "left", "h":
		m.selectRelayOffset(-1)
	case "right", "l":
		m.selectRelayOffset(1)
	case "n":
		return m.runAction(agentDashboardActionAddTunnel, "", "")
	case "x":
		return m.runAction(agentDashboardActionDeleteTunnel, "", "")
	case "a":
		return m.runAction(agentDashboardActionAddRelay, "", "")
	case "d":
		return m.runAction(agentDashboardActionDeleteRelay, "", "")
	case "m":
		return m.runAction(agentDashboardActionAddHop, "", "")
	case "u":
		return m.runAction(agentDashboardActionRemoveHop, "", "")
	case "p":
		return m.runAction(agentDashboardActionApplyHop, "", "")
	case "c":
		return m.runAction(agentDashboardActionClearHop, "", "")
	}
	return m, nil
}

func (m agentDashboardModel) updateMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	event := tea.MouseEvent(msg)
	switch event.Button {
	case tea.MouseButtonWheelUp:
		m.selectTunnelOffset(-1)
		return m, nil
	case tea.MouseButtonWheelDown:
		m.selectTunnelOffset(1)
		return m, nil
	}
	if event.Action != tea.MouseActionPress || event.Button != tea.MouseButtonLeft {
		return m, nil
	}
	for _, region := range m.layout().regions {
		if event.Y == region.y && event.X >= region.x0 && event.X < region.x1 {
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
	case agentDashboardActionSelectRelay:
		if tunnelID != "" {
			m.selectTunnel(tunnelID)
		}
		if relayURL != "" {
			m.selectRelay(relayURL)
		}
	case agentDashboardActionAddTunnel:
		return m.startInput(agentDashboardAddTunnelMode, "New tunnel: ", "name port")
	case agentDashboardActionDeleteTunnel:
		return m.deleteSelectedTunnel()
	case agentDashboardActionAddRelay:
		if _, ok := m.selectedTunnelStatus(); !ok {
			return m, nil
		}
		return m.startInput(agentDashboardAddRelayMode, "Add relay: ", "https://relay.example.com")
	case agentDashboardActionDeleteRelay:
		return m.deleteSelectedRelay()
	case agentDashboardActionAttachRelay:
		return m.attachSelectedRelay()
	case agentDashboardActionDetachRelay:
		return m.detachSelectedRelay()
	case agentDashboardActionAddHop:
		return m.addSelectedHop()
	case agentDashboardActionRemoveHop:
		return m.removeSelectedHop()
	case agentDashboardActionApplyHop:
		return m.applyRoute()
	case agentDashboardActionClearHop:
		return m.clearRoute()
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
	m.selectedTunnelID = m.status.Tunnels[index].ID
	m.selectedRelayURL = ""
	if len(m.status.Tunnels[index].Relays) > 0 {
		m.selectedRelayURL = m.status.Tunnels[index].Relays[0].RelayURL
	}
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

func (m *agentDashboardModel) clampSelection() {
	if len(m.status.Tunnels) == 0 {
		m.selectedTunnelID = ""
		m.selectedRelayURL = ""
		return
	}

	tunnelIndex := m.selectedTunnelIndex()
	m.selectedTunnelID = m.status.Tunnels[tunnelIndex].ID

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

func (m agentDashboardModel) selectedTunnelStatus() (types.AgentTunnelStatus, bool) {
	index := m.selectedTunnelIndex()
	if index < 0 {
		return types.AgentTunnelStatus{}, false
	}
	return m.status.Tunnels[index], true
}

func (m agentDashboardModel) selectedRelayIndex(tunnel types.AgentTunnelStatus) int {
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

func (m agentDashboardModel) selectedRelayStatus() (types.AgentRelayStatus, bool) {
	tunnel, ok := m.selectedTunnelStatus()
	index := m.selectedRelayIndex(tunnel)
	if !ok || index < 0 {
		return types.AgentRelayStatus{}, false
	}
	return tunnel.Relays[index], true
}

func (m agentDashboardModel) selectedTunnelRelay() (types.AgentTunnelStatus, types.AgentRelayStatus, bool) {
	tunnel, ok := m.selectedTunnelStatus()
	if !ok {
		return types.AgentTunnelStatus{}, types.AgentRelayStatus{}, false
	}
	relay, ok := m.selectedRelayStatus()
	if !ok {
		return types.AgentTunnelStatus{}, types.AgentRelayStatus{}, false
	}
	return tunnel, relay, true
}

func (m agentDashboardModel) startInput(mode agentDashboardMode, prompt, placeholder string) (tea.Model, tea.Cmd) {
	m.mode = mode
	m.input.Reset()
	m.input.Prompt = prompt
	m.input.Placeholder = placeholder
	m.input.PromptStyle = agentDashboardSectionStyle
	m.input.TextStyle = agentDashboardInputStyle
	m.input.PlaceholderStyle = agentDashboardMutedStyle
	m.input.Width = max(1, min(88, m.width-8))
	return m, tea.Batch(m.input.Focus(), textinput.Blink)
}

func (m *agentDashboardModel) cancelInput() {
	m.mode = agentDashboardNormalMode
	m.input.Blur()
	m.input.Reset()
}

func (m agentDashboardModel) submitInput() (tea.Model, tea.Cmd) {
	mode := m.mode
	value := strings.TrimSpace(m.input.Value())
	m.mode = agentDashboardNormalMode
	m.input.Blur()
	m.input.Reset()

	switch mode {
	case agentDashboardAddTunnelMode:
		fields := strings.Fields(value)
		if len(fields) < 2 {
			return m, nil
		}
		name := strings.Join(fields[:len(fields)-1], " ")
		port := strings.TrimPrefix(fields[len(fields)-1], ":")
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return m, nil
		}
		return m, agentDashboardRun(func(ctx context.Context) error {
			return AddTunnel(ctx, m.stateDir, types.AgentTunnelRequest{
				Name:       name,
				TargetAddr: "127.0.0.1:" + port,
			})
		})
	case agentDashboardAddRelayMode:
		if value == "" {
			return m, nil
		}
		tunnel, ok := m.selectedTunnelStatus()
		if !ok {
			return m, nil
		}
		return m, agentDashboardRun(func(ctx context.Context) error {
			return AddRelay(ctx, m.stateDir, tunnel.ID, value)
		})
	}
	return m, nil
}

func (m agentDashboardModel) deleteSelectedTunnel() (tea.Model, tea.Cmd) {
	tunnel, ok := m.selectedTunnelStatus()
	if !ok {
		return m, nil
	}
	if len(m.status.Tunnels) <= 1 {
		return m, nil
	}
	return m, agentDashboardRun(func(ctx context.Context) error {
		return DeleteTunnel(ctx, m.stateDir, tunnel.ID)
	})
}

func (m agentDashboardModel) deleteSelectedRelay() (tea.Model, tea.Cmd) {
	tunnel, relay, ok := m.selectedTunnelRelay()
	if !ok {
		return m, nil
	}
	return m, agentDashboardRun(func(ctx context.Context) error {
		return RemoveRelay(ctx, m.stateDir, tunnel.ID, relay.RelayURL)
	})
}

func (m agentDashboardModel) attachSelectedRelay() (tea.Model, tea.Cmd) {
	tunnel, relay, ok := m.selectedTunnelRelay()
	if !ok {
		return m, nil
	}
	if relayDashboardInUse(relay) {
		return m, nil
	}
	return m, agentDashboardRun(func(ctx context.Context) error {
		return AddRelay(ctx, m.stateDir, tunnel.ID, relay.RelayURL)
	})
}

func (m agentDashboardModel) detachSelectedRelay() (tea.Model, tea.Cmd) {
	tunnel, relay, ok := m.selectedTunnelRelay()
	if !ok {
		return m, nil
	}
	return m, agentDashboardRun(func(ctx context.Context) error {
		return SeedRelay(ctx, m.stateDir, tunnel.ID, relay.RelayURL)
	})
}

func (m agentDashboardModel) addSelectedHop() (tea.Model, tea.Cmd) {
	tunnel, relay, ok := m.selectedTunnelRelay()
	if !ok {
		return m, nil
	}
	if !relay.SupportsOverlay {
		return m, nil
	}
	m.ensureRouteDraft(tunnel)
	if slices.Contains(m.routeDraft, relay.RelayURL) {
		return m, nil
	}
	m.routeDraft = append(m.routeDraft, relay.RelayURL)
	return m, nil
}

func (m agentDashboardModel) removeSelectedHop() (tea.Model, tea.Cmd) {
	tunnel, relay, ok := m.selectedTunnelRelay()
	if !ok {
		return m, nil
	}
	m.ensureRouteDraft(tunnel)

	next := m.routeDraft[:0]
	for _, relayURL := range m.routeDraft {
		if relayURL != relay.RelayURL {
			next = append(next, relayURL)
		}
	}
	if len(next) == len(m.routeDraft) {
		return m, nil
	}
	m.routeDraft = next
	return m, nil
}

func (m agentDashboardModel) applyRoute() (tea.Model, tea.Cmd) {
	tunnel, ok := m.selectedTunnelStatus()
	if !ok {
		return m, nil
	}
	route := m.displayedRoute(tunnel)
	if len(route) < 2 {
		return m, nil
	}
	m.routeDraft = nil
	m.draftTunnelID = ""
	return m, agentDashboardRun(func(ctx context.Context) error {
		return SetMultiHop(ctx, m.stateDir, tunnel.ID, route)
	})
}

func (m agentDashboardModel) clearRoute() (tea.Model, tea.Cmd) {
	tunnel, ok := m.selectedTunnelStatus()
	if !ok {
		return m, nil
	}
	m.routeDraft = nil
	m.draftTunnelID = ""
	return m, agentDashboardRun(func(ctx context.Context) error {
		return SetMultiHop(ctx, m.stateDir, tunnel.ID, nil)
	})
}

func (m *agentDashboardModel) ensureRouteDraft(tunnel types.AgentTunnelStatus) {
	if m.draftTunnelID == tunnel.ID {
		return
	}
	m.draftTunnelID = tunnel.ID
	m.routeDraft = append([]string(nil), tunnel.MultiHop...)
}

func (m agentDashboardModel) displayedRoute(tunnel types.AgentTunnelStatus) []string {
	if m.draftTunnelID == tunnel.ID {
		return append([]string(nil), m.routeDraft...)
	}
	return append([]string(nil), tunnel.MultiHop...)
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

func (m agentDashboardModel) layout() agentDashboardView {
	width := m.width
	if width <= 0 {
		width = 88
	}
	leftWidth, rightWidth, bodyHeight := agentDashboardSizes(width, m.height)

	var layout agentDashboardView
	layout.addStyled(width, agentDashboardTitleStyle, "Portal Agent  "+types.ReleaseVersion)
	layout.addLine(agentDashboardMutedStyle.Render(strings.Repeat("-", min(width, 120))))

	if m.err != nil && m.status.ControlAddr == "" {
		layout.addStyled(width, agentDashboardErrorStyle, fmt.Sprintf("Agent unavailable: %v", m.err))
		layout.addLine("")
		layout.addText(width, "Start managed service: portal agent run --config "+m.configPath)
		layout.addText(width, "No service manager:   portal agent run --foreground --config "+m.configPath)
		return layout
	}

	if m.err != nil {
		layout.addStyled(width, agentDashboardErrorStyle, fmt.Sprintf("Error: %v", m.err))
	}
	if m.mode != agentDashboardNormalMode {
		layout.addLine(m.input.View())
	}
	layout.addLine("")
	if m.height > 0 {
		bodyHeight = max(1, m.height-len(layout.lines))
	}

	left := m.renderTunnelsPane(leftWidth, bodyHeight)
	right := m.renderTunnelPane(rightWidth, bodyHeight)
	layout.addPanes(left, right, leftWidth, 2)
	return layout
}

func (m agentDashboardModel) renderTunnelsPane(width, height int) agentDashboardView {
	var pane agentDashboardView
	pane.addStyled(width, agentDashboardSectionStyle, "Tunnels")
	pane.addButtons(width,
		agentDashboardButton{label: "Add Tunnel", action: agentDashboardActionAddTunnel},
		agentDashboardButton{label: "Delete Tunnel", action: agentDashboardActionDeleteTunnel, disabled: len(m.status.Tunnels) <= 1},
	)
	pane.addStyled(width, agentDashboardMutedStyle, fmt.Sprintf("%d managed", len(m.status.Tunnels)))
	pane.addLine(agentDashboardMutedStyle.Render(strings.Repeat("-", width)))

	if len(m.status.Tunnels) == 0 {
		pane.addStyled(width, agentDashboardMutedStyle, "no managed tunnels")
		pane.clip(height)
		return pane
	}

	detailLines := make([]string, 0, 5)
	if tunnel, ok := m.selectedTunnelStatus(); ok {
		detailLines = append(detailLines,
			"",
			agentDashboardSectionStyle.Render(agentDashboardFit("Selected Tunnel", width)),
			agentDashboardFit("State: "+valueOrDash(tunnel.State), width),
			agentDashboardFit("Target: "+valueOrDash(tunnel.TargetAddr), width),
			agentDashboardFit("Public: "+tunnelPublicURL(tunnel), width),
		)
		if strings.TrimSpace(tunnel.LastError) != "" {
			detailLines = append(detailLines, agentDashboardErrorStyle.Render(agentDashboardFit("Error: "+tunnel.LastError, width)))
		}
	}
	listLimit := max(agentDashboardMinListRows, height-len(pane.lines)-len(detailLines))
	selectedTunnelID := m.selectedTunnelID
	if selectedTunnelID == "" && len(m.status.Tunnels) > 0 {
		selectedTunnelID = m.status.Tunnels[0].ID
	}
	for i, tunnel := range m.status.Tunnels {
		if i >= listLimit || len(pane.lines) >= height {
			pane.addStyled(width, agentDashboardMutedStyle, fmt.Sprintf("+ %d more", len(m.status.Tunnels)-i))
			break
		}
		name := tunnel.ID
		if strings.TrimSpace(tunnel.Name) != "" {
			name = tunnel.Name
		}
		nameWidth := max(8, width-11)
		line := fmt.Sprintf("%-10s %s", truncateDashboardValue(tunnel.State, 10), agentDashboardFit(name, nameWidth))
		pane.addClickRow(line, width, agentDashboardTunnelStyle(tunnel.ID == selectedTunnelID, tunnel.State), agentDashboardActionSelectTunnel, tunnel.ID, "")
	}
	for _, line := range detailLines {
		if len(pane.lines) >= height {
			break
		}
		pane.addLine(line)
	}
	pane.clip(height)
	return pane
}

func (m agentDashboardModel) renderTunnelPane(width, height int) agentDashboardView {
	var pane agentDashboardView
	tunnel, ok := m.selectedTunnelStatus()
	if !ok {
		pane.addStyled(width, agentDashboardSectionStyle, "Relays")
		pane.addStyled(width, agentDashboardMutedStyle, "select a managed tunnel")
		pane.clip(height)
		return pane
	}

	relayLimit := max(agentDashboardMinListRows, (height-len(pane.lines)-6)/2)
	m.renderRelaysSection(&pane, width, relayLimit, tunnel)
	pane.addLine("")
	m.renderRouteSection(&pane, width, height, tunnel)
	pane.clip(height)
	return pane
}

func (m agentDashboardModel) renderRelaysSection(pane *agentDashboardView, width, maxRows int, tunnel types.AgentTunnelStatus) {
	relay, hasRelay := m.selectedRelayStatus()
	inUse := hasRelay && relayDashboardInUse(relay)
	attachDisabled := !hasRelay || inUse || relay.Connecting || relay.Banned
	detachDisabled := !hasRelay || relay.Banned || (!inUse && !relay.Connecting && relay.Bootstrap)
	deleteDisabled := !hasRelay

	pane.addStyled(width, agentDashboardSectionStyle, "Relays")
	pane.addButtons(width,
		agentDashboardButton{label: "Attach", action: agentDashboardActionAttachRelay, disabled: attachDisabled},
		agentDashboardButton{label: "Detach", action: agentDashboardActionDetachRelay, disabled: detachDisabled},
		agentDashboardButton{label: "Add URL", action: agentDashboardActionAddRelay},
		agentDashboardButton{label: "Remove", action: agentDashboardActionDeleteRelay, disabled: deleteDisabled},
	)
	if hasRelay {
		pane.addStyled(width, agentDashboardMutedStyle, "Selected: "+relay.RelayURL)
	}
	pane.addLine(agentDashboardMutedStyle.Render(agentDashboardRelayRow(width, "STATE", "ROLE", "FEATURES", "RELAY")))

	if len(tunnel.Relays) == 0 {
		pane.addStyled(width, agentDashboardMutedStyle, "no relays")
		return
	}
	selectedRelayURL := m.selectedRelayURL
	if selectedRelayURL == "" && len(tunnel.Relays) > 0 {
		selectedRelayURL = tunnel.Relays[0].RelayURL
	}
	for i, relay := range tunnel.Relays {
		if i >= maxRows {
			pane.addStyled(width, agentDashboardMutedStyle, fmt.Sprintf("+ %d more", len(tunnel.Relays)-i))
			break
		}
		line := agentDashboardRelayRow(width,
			relayDashboardState(relay),
			relayDashboardRole(relay),
			relayDashboardFeatures(relay),
			relay.RelayURL,
		)
		pane.addClickRow(line, width, agentDashboardRelayStyle(relay.RelayURL == selectedRelayURL, relay), agentDashboardActionSelectRelay, tunnel.ID, relay.RelayURL)
	}
}

func (m agentDashboardModel) renderRouteSection(pane *agentDashboardView, width, height int, tunnel types.AgentTunnelStatus) {
	route := m.displayedRoute(tunnel)
	relay, hasRelay := m.selectedRelayStatus()
	inRoute := hasRelay && slices.Contains(route, relay.RelayURL)
	canAdd := hasRelay && relay.SupportsOverlay && !inRoute

	pane.addStyled(width, agentDashboardSectionStyle, "Route")
	pane.addButtons(width,
		agentDashboardButton{label: "Add Hop", action: agentDashboardActionAddHop, disabled: !canAdd},
		agentDashboardButton{label: "Remove Hop", action: agentDashboardActionRemoveHop, disabled: !inRoute},
		agentDashboardButton{label: "Apply", action: agentDashboardActionApplyHop, disabled: len(route) < 2},
		agentDashboardButton{label: "Clear", action: agentDashboardActionClearHop, disabled: len(route) == 0},
	)

	routeLabel := "Route:"
	if m.draftTunnelID == tunnel.ID {
		routeLabel += " draft"
	}
	if len(route) == 0 {
		routeLabel = "Route: none"
	}
	pane.addText(width, routeLabel)
	for i, relayURL := range route {
		if len(pane.lines) >= height {
			return
		}
		pane.addText(width, fmt.Sprintf("%d. %s", i+1, relayURL))
	}
}

func (v *agentDashboardView) addLine(line string) {
	v.lines = append(v.lines, line)
}

func (v *agentDashboardView) addText(width int, text string) {
	v.addLine(agentDashboardFit(text, width))
}

func (v *agentDashboardView) addStyled(width int, style lipgloss.Style, text string) {
	v.addLine(style.Render(agentDashboardFit(text, width)))
}

func (v *agentDashboardView) addButtons(width int, buttons ...agentDashboardButton) {
	lines, regions := agentDashboardRenderButtons(width, len(v.lines), 0, buttons...)
	v.lines = append(v.lines, lines...)
	v.regions = append(v.regions, regions...)
}

func (v *agentDashboardView) addPanes(left, right agentDashboardView, leftWidth, gutter int) {
	startY := len(v.lines)
	height := max(len(left.lines), len(right.lines))
	for i := 0; i < height; i++ {
		leftLine := ""
		if i < len(left.lines) {
			leftLine = left.lines[i]
		}
		rightLine := ""
		if i < len(right.lines) {
			rightLine = right.lines[i]
		}
		v.lines = append(v.lines, agentDashboardPadStyled(leftLine, leftWidth)+strings.Repeat(" ", gutter)+rightLine)
	}
	for _, region := range left.regions {
		region.y += startY
		v.regions = append(v.regions, region)
	}
	for _, region := range right.regions {
		region.y += startY
		region.x0 += leftWidth + gutter
		region.x1 += leftWidth + gutter
		v.regions = append(v.regions, region)
	}
}

func (v *agentDashboardView) addClickRow(line string, width int, style lipgloss.Style, action agentDashboardAction, tunnel, relay string) {
	plain := agentDashboardFit(line, width)
	y := len(v.lines)
	v.lines = append(v.lines, style.Width(width).Render(plain))
	v.regions = append(v.regions, agentDashboardRegion{
		x0:     0,
		x1:     width,
		y:      y,
		action: action,
		tunnel: tunnel,
		relay:  relay,
	})
}

func (v *agentDashboardView) clip(height int) {
	if height <= 0 || len(v.lines) <= height {
		return
	}
	v.lines = v.lines[:height]
	regions := v.regions[:0]
	for _, region := range v.regions {
		if region.y < height {
			regions = append(regions, region)
		}
	}
	v.regions = regions
}

func agentDashboardRenderButtons(width, y, x int, buttons ...agentDashboardButton) ([]string, []agentDashboardRegion) {
	if width <= 0 {
		width = 1
	}
	var line strings.Builder
	var lines []string
	var regions []agentDashboardRegion
	lineY := y
	lineX := x
	for i, button := range buttons {
		plain := "[ " + button.label + " ]"
		if lipgloss.Width(plain) > width {
			plain = agentDashboardFit(plain, width)
		}
		plainWidth := lipgloss.Width(plain)
		space := 0
		if i > 0 && line.Len() > 0 {
			space = 1
		}
		if line.Len() > 0 && lineX+space+plainWidth > width {
			lines = append(lines, line.String())
			line.Reset()
			lineY++
			lineX = x
			space = 0
		}
		if space > 0 {
			line.WriteString(" ")
			lineX++
		}
		style := agentDashboardButtonStyle
		if button.disabled {
			style = agentDashboardDisabledStyle
		} else {
			regions = append(regions, agentDashboardRegion{
				x0:     lineX,
				x1:     min(lineX+plainWidth, width),
				y:      lineY,
				action: button.action,
			})
		}
		line.WriteString(style.Render(plain))
		lineX += plainWidth
	}
	if line.Len() > 0 || len(lines) == 0 {
		lines = append(lines, line.String())
	}
	return lines, regions
}

func agentDashboardSizes(width, height int) (int, int, int) {
	if width <= 0 {
		width = 104
	}

	gutter := 2
	if width < 84 {
		leftWidth := min(max(width/2, 1), 40)
		if width >= 48 {
			leftWidth = max(leftWidth, 24)
		}
		rightWidth := width - leftWidth - gutter
		if rightWidth < 1 {
			rightWidth = 1
			leftWidth = max(1, width-gutter-rightWidth)
		}
		return leftWidth, rightWidth, defaultDashboardBodyHeight(height)
	}

	leftWidth := width / 3
	leftWidth = min(max(leftWidth, 40), 56)
	rightWidth := max(1, width-leftWidth-gutter)
	return leftWidth, rightWidth, defaultDashboardBodyHeight(height)
}

func defaultDashboardBodyHeight(height int) int {
	bodyHeight := height - 8
	if height <= 0 {
		bodyHeight = 22
	}
	return max(bodyHeight, 1)
}

func agentDashboardTunnelStyle(selected bool, state string) lipgloss.Style {
	if selected {
		return agentDashboardSelectedStyle
	}
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "running":
		return agentDashboardOKStyle
	case "error":
		return agentDashboardErrorStyle
	case "starting":
		return agentDashboardMutedStyle
	default:
		return lipgloss.NewStyle()
	}
}

func agentDashboardRelayStyle(selected bool, relay types.AgentRelayStatus) lipgloss.Style {
	if selected {
		return agentDashboardSelectedStyle
	}
	if relay.Banned {
		return agentDashboardErrorStyle
	}
	if relayDashboardInUse(relay) {
		return agentDashboardOKStyle
	}
	return agentDashboardMutedStyle
}

func relayDashboardState(relay types.AgentRelayStatus) string {
	switch {
	case relay.Banned:
		return "blocked"
	case relay.PublicURL != "":
		return "ready"
	case relay.Connecting:
		return "trying"
	case relay.Bootstrap:
		return "seed"
	default:
		return "known"
	}
}

func relayDashboardRole(relay types.AgentRelayStatus) string {
	switch {
	case relay.Banned:
		return "blocked"
	case relayDashboardInUse(relay):
		return "attached"
	case relay.Connecting:
		return "trying"
	case relay.Bootstrap:
		return "seed"
	default:
		return "candidate"
	}
}

func relayDashboardInUse(relay types.AgentRelayStatus) bool {
	return relay.PublicURL != ""
}

func relayDashboardFeatures(relay types.AgentRelayStatus) string {
	var features []string
	if relay.SupportsOverlay {
		features = append(features, "hop")
	}
	if relay.SupportsUDP {
		features = append(features, "udp")
	}
	if relay.SupportsTCP {
		features = append(features, "tcp")
	}
	if len(features) == 0 {
		return "-"
	}
	return strings.Join(features, ",")
}

func agentDashboardRelayRow(width int, state, role, features, relayURL string) string {
	if width < 28 {
		return agentDashboardFit(state+" "+relayURL, width)
	}
	if width < 48 {
		stateW := 7
		return agentDashboardCell(state, stateW) + " " + agentDashboardFit(relayURL, width-stateW-1)
	}
	stateW := 8
	roleW := 9
	if width < 68 {
		relayW := max(1, width-stateW-roleW-2)
		return agentDashboardCell(state, stateW) + " " +
			agentDashboardCell(role, roleW) + " " +
			agentDashboardFit(relayURL, relayW)
	}
	featuresW := 11
	relayW := max(1, width-stateW-roleW-featuresW-3)
	return agentDashboardCell(state, stateW) + " " +
		agentDashboardCell(role, roleW) + " " +
		agentDashboardCell(features, featuresW) + " " +
		agentDashboardFit(relayURL, relayW)
}

func tunnelPublicURL(tunnel types.AgentTunnelStatus) string {
	for _, relay := range tunnel.Relays {
		if strings.TrimSpace(relay.PublicURL) != "" {
			return relay.PublicURL
		}
	}
	return "-"
}

func valueOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func truncateDashboardValue(value string, maxLength int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return agentDashboardFit(value, maxLength)
}

func agentDashboardFit(value string, width int) string {
	value = strings.TrimSpace(value)
	if value == "" || width <= 0 {
		return ""
	}
	if lipgloss.Width(value) <= width {
		return value
	}
	if width == 1 {
		return "~"
	}
	var out strings.Builder
	used := 0
	for _, r := range value {
		cellWidth := lipgloss.Width(string(r))
		if used+cellWidth > width-1 {
			break
		}
		out.WriteRune(r)
		used += cellWidth
	}
	return out.String() + "~"
}

func agentDashboardCell(value string, width int) string {
	value = agentDashboardFit(value, width)
	if lipgloss.Width(value) >= width {
		return value
	}
	return value + strings.Repeat(" ", width-lipgloss.Width(value))
}

func agentDashboardPadStyled(value string, width int) string {
	if lipgloss.Width(value) >= width {
		return value
	}
	return value + strings.Repeat(" ", width-lipgloss.Width(value))
}
