package agent

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func (m agentDashboardModel) deleteTunnel(tunnelID string) (tea.Model, tea.Cmd) {
	tunnelID = strings.TrimSpace(tunnelID)
	if tunnelID == "" {
		tunnel, ok := m.selectedTunnelStatus()
		if !ok {
			return m, nil
		}
		tunnelID = tunnel.ID
	}
	return m, agentDashboardRun(func(ctx context.Context) error {
		return DeleteTunnel(ctx, m.stateDir, tunnelID)
	})
}

func (m agentDashboardModel) tunnelsSectionHeight(bodyHeight int) int {
	if bodyHeight <= 0 {
		return bodyHeight
	}
	if _, ok := m.selectedTunnelStatus(); !ok {
		return bodyHeight
	}
	minRelaySectionHeight := agentDashboardMinRelayRows + 3
	if bodyHeight <= minRelaySectionHeight {
		return 1
	}
	return max(1, bodyHeight-minRelaySectionHeight-1)
}

func (m agentDashboardModel) renderTunnelsSection(width, height int) agentDashboardView {
	var pane agentDashboardView
	th := &m.theme
	pane.addSectionTitle(th, width, agentDashboardPaneTunnels, "Tunnels", m.activePane == agentDashboardPaneTunnels)
	addLabel := "Add Tunnel"
	addDisabled := false
	if m.addingTunnel {
		addLabel = "Create"
		addDisabled = strings.TrimSpace(m.addName.Value()) == ""
	}
	buttons := []agentDashboardButton{
		{label: addLabel, action: agentDashboardActionAddTunnel, disabled: addDisabled},
	}
	if m.addingTunnel {
		buttons = append(buttons, agentDashboardButton{label: "Cancel", action: agentDashboardActionCancelAddTunnel})
	}
	buttons = append(buttons,
		agentDashboardButton{label: "Delete", action: agentDashboardActionDeleteTunnel, disabled: len(m.status.Tunnels) == 0},
	)
	pane.addButtons(th, width, buttons...)
	if m.addingTunnel {
		m.renderAddTunnelForm(&pane, width)
	}
	tunnelRowWidth := agentDashboardTunnelTableWidth(width, m.status.Tunnels)
	pane.addLine(th.strong.Render(agentDashboardTunnelRow(tunnelRowWidth, "STATUS", "TARGET", "TUNNEL")))

	if len(m.status.Tunnels) == 0 {
		pane.addStyled(width, th.muted, "no tunnels")
		return pane
	}

	selectedTunnelID := m.selectedTunnelID
	if selectedTunnelID == "" && len(m.status.Tunnels) > 0 {
		selectedTunnelID = m.status.Tunnels[0].ID
	}
	maxRows := len(m.status.Tunnels)
	if height > 0 {
		maxRows = max(1, height-len(pane.lines)-2)
	}
	selectedIndex := m.selectedTunnelIndex()
	start, end := agentDashboardRelayWindow(selectedIndex, len(m.status.Tunnels), maxRows)
	rowWidth := tunnelRowWidth
	for i := start; i < end; i++ {
		tunnel := m.status.Tunnels[i]
		pane.addTunnelRow(th, width, rowWidth, tunnel, tunnel.ID == selectedTunnelID)
	}

	if tunnel, ok := m.selectedTunnelStatus(); ok && strings.TrimSpace(tunnel.LastError) != "" {
		pane.addStyled(width, th.failed, "Error: "+tunnel.LastError)
	}
	return pane
}

func (v *agentDashboardView) addTunnelRow(th *agentDashboardTheme, width, rowWidth int, tunnel AgentTunnelStatus, selected bool) {
	if width <= 0 {
		width = 1
	}
	rowWidth = min(rowWidth, max(1, width))
	line := agentDashboardTunnelRow(rowWidth, tunnel.State, tunnel.TargetAddr, tunnelDashboardName(tunnel))
	style := agentDashboardTunnelStyle(th, selected, tunnel.State)
	y := len(v.lines)
	v.lines = append(v.lines, style.Width(rowWidth).Render(agentDashboardFit(line, rowWidth)))
	v.regions = append(v.regions, agentDashboardRegion{
		x0:     0,
		x1:     rowWidth,
		y:      y,
		action: agentDashboardActionSelectTunnel,
		tunnel: tunnel.ID,
	})
}

func agentDashboardTunnelStyle(th *agentDashboardTheme, selected bool, state string) lipgloss.Style {
	if selected {
		return th.selected
	}
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "running":
		return th.bright
	case "starting":
		return th.pending
	case "error":
		return th.failed
	default:
		return th.muted
	}
}

func tunnelDashboardName(tunnel AgentTunnelStatus) string {
	if strings.TrimSpace(tunnel.Name) != "" {
		return tunnel.Name
	}
	return tunnel.ID
}

func tunnelDashboardTarget(tunnel AgentTunnelStatus) string {
	if tunnel.Serve != "" {
		return tunnel.Serve
	}
	if target := strings.TrimSpace(tunnel.TargetAddr); target != "" {
		return target
	}
	if len(tunnel.HTTPRoutes) == 0 {
		return "-"
	}
	paid := 0
	for _, route := range tunnel.HTTPRoutes {
		if strings.TrimSpace(route.Amount) != "" {
			paid++
		}
	}
	if paid == 0 {
		return fmt.Sprintf("%d routes", len(tunnel.HTTPRoutes))
	}
	return fmt.Sprintf("%d routes, %d paid", len(tunnel.HTTPRoutes), paid)
}

func agentDashboardTunnelTableWidth(width int, tunnels []AgentTunnelStatus) int {
	tableWidth := 56
	for _, tunnel := range tunnels {
		nameWidth := max(lipgloss.Width(tunnelDashboardName(tunnel)), lipgloss.Width("TUNNEL"))
		targetWidth := max(lipgloss.Width(tunnelDashboardTarget(tunnel)), lipgloss.Width("TARGET"))
		tableWidth = max(tableWidth, 11+1+targetWidth+1+nameWidth)
	}
	return max(1, min(tableWidth, width))
}

func agentDashboardTunnelRow(width int, state, target, name string) string {
	if width < 28 {
		return agentDashboardFit(state+" "+name, width)
	}
	if width < 56 {
		stateW := 11
		return agentDashboardCell(state, stateW) + " " +
			agentDashboardFit(name, width-stateW-1)
	}
	stateW := 11
	targetW := 22
	nameW := max(1, width-stateW-targetW-2)
	return agentDashboardCell(state, stateW) + " " +
		agentDashboardCell(target, targetW) + " " +
		agentDashboardFit(name, nameW)
}
