package agent

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const agentDashboardTunnelLead = 5

func (m agentDashboardModel) askDeleteTunnel(tunnelID string) (tea.Model, tea.Cmd) {
	tunnelID = strings.TrimSpace(tunnelID)
	if tunnelID == "" {
		tunnel, ok := m.selectedTunnelStatus()
		if !ok {
			return m, nil
		}
		tunnelID = tunnel.ID
	}
	m.confirmDelete = tunnelID
	return m, nil
}

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

const agentDashboardStopQuestion = "Stop the agent? Every tunnel goes down."

func (m agentDashboardModel) renderTunnelsSection(width, rows int) agentDashboardView {
	th := &m.theme
	var pane agentDashboardView
	if m.confirming() {
		pane.addStyled(width, th.pending, m.tunnelsConfirmQuestion())
		pane.addButtons(th, width,
			agentDashboardButton{label: "Yes", action: agentDashboardActionAnswerYes},
			agentDashboardButton{label: "No", action: agentDashboardActionAnswerNo},
		)
	} else {
		m.addTunnelsButtons(&pane, th, width)
	}
	m.addTunnelsTable(&pane, th, width, rows)
	return pane
}

func (m agentDashboardModel) tunnelsConfirmQuestion() string {
	if m.confirmDelete == "" {
		return agentDashboardStopQuestion
	}
	name := m.confirmDelete
	for _, tunnel := range m.status.Tunnels {
		if tunnel.ID == m.confirmDelete {
			name = tunnelDashboardName(tunnel)
		}
	}
	return fmt.Sprintf("Delete tunnel %q?", name)
}

func (m agentDashboardModel) addTunnelsButtons(pane *agentDashboardView, th *agentDashboardTheme, width int) {
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
}

func (m agentDashboardModel) addTunnelsTable(pane *agentDashboardView, th *agentDashboardTheme, width, rows int) {
	var tail []string
	if tunnel, ok := m.selectedTunnelStatus(); ok && strings.TrimSpace(tunnel.LastError) != "" {
		tail = append(tail, m.theme.failed.Render(agentDashboardFit(m.theme.glyph.ledFailed+" Error: "+tunnel.LastError, width)))
	}
	room := rows - len(pane.lines) - 1 - len(tail)
	var form agentDashboardView
	if m.addingTunnel && !m.confirming() {
		m.renderAddTunnelForm(&form, width)
		formRows := len(form.lines)
		if rows > 0 {
			formRows = min(formRows, max(1, room-1))
		}
		pane.addView(form.window(m.addFocus, formRows))
		room -= formRows
	}
	pane.addLine(th.strong.Render(strings.Repeat(" ", agentDashboardTunnelLead) + agentDashboardTunnelRow(width-agentDashboardTunnelLead, "STATE", "TARGET", "TUNNEL")))
	if len(m.status.Tunnels) == 0 {
		pane.addStyled(width, th.muted, "no tunnels")
	}
	tableRows := len(m.status.Tunnels)
	if rows > 0 {
		tableRows = max(1, room)
	}
	selected := m.selectedTunnelIndex()
	start, end := agentDashboardRowWindow(selected, len(m.status.Tunnels), tableRows)
	for i := start; i < end; i++ {
		pane.addTunnelRow(th, width, m.status.Tunnels[i], i == selected)
	}
	pane.lines = append(pane.lines, tail...)
}

func (v *agentDashboardView) addTunnelRow(th *agentDashboardTheme, width int, tunnel AgentTunnelStatus, selected bool) {
	led, style := agentDashboardTunnelLook(th, tunnel.State)
	marker := th.glyph.unselected
	if selected {
		marker, style = th.glyph.selected, th.selected
	}
	row := agentDashboardTunnelRow(width-agentDashboardTunnelLead, tunnel.State, tunnelDashboardTarget(tunnel), tunnelDashboardName(tunnel))
	v.addClickRow(marker+led+" "+row, width, style, agentDashboardActionSelectTunnel, tunnel.ID, "")
}

func agentDashboardTunnelLook(th *agentDashboardTheme, state string) (string, lipgloss.Style) {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "running":
		return th.glyph.ledLive, th.bright
	case "starting":
		return th.glyph.ledConnecting, th.pending
	case "error":
		return th.glyph.ledFailed, th.failed
	default:
		return th.glyph.ledIdle, th.muted
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

func agentDashboardTunnelRow(width int, state, target, name string) string {
	if width < 24 {
		return agentDashboardFit(name, width)
	}
	if width < 60 {
		targetW := 18
		return agentDashboardCell(target, targetW) + " " +
			agentDashboardFit(name, width-targetW-1)
	}
	stateW := 8
	targetW := 22
	nameW := max(1, width-stateW-targetW-2)
	return agentDashboardCell(state, stateW) + " " +
		agentDashboardCell(target, targetW) + " " +
		agentDashboardFit(name, nameW)
}
