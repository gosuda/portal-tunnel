package agent

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// agentDashboardTunnelLead is the width of the row marker, the LED and the space after them.
const agentDashboardTunnelLead = 5

// askDeleteTunnel asks for confirmation before deleting the tunnel; an empty
// tunnelID means the selected one.
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

func (m agentDashboardModel) renderTunnelsSection(width, rows int) agentDashboardView {
	th := &m.theme
	var pane agentDashboardView
	if m.confirming() {
		question := "Stop the agent? Every tunnel goes down."
		if m.confirmDelete != "" {
			name := m.confirmDelete
			for _, tunnel := range m.status.Tunnels {
				if tunnel.ID == m.confirmDelete {
					name = tunnelDashboardName(tunnel)
				}
			}
			question = fmt.Sprintf("Delete tunnel %q?", name)
		}
		pane.addStyled(width, th.pending, question)
		pane.addButtons(th, width,
			agentDashboardButton{label: "Yes", action: agentDashboardActionAnswerYes},
			agentDashboardButton{label: "No", action: agentDashboardActionAnswerNo},
		)
	} else {
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

	var tail []string
	if tunnel, ok := m.selectedTunnelStatus(); ok && strings.TrimSpace(tunnel.LastError) != "" {
		tail = append(tail, th.failed.Render(agentDashboardFit(th.glyph.ledFailed+" Error: "+tunnel.LastError, width)))
	}

	// What is left after the buttons, the table header and the error goes to
	// the add form, if open, and to the table, which keeps at least one row.
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
	return pane
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

// agentDashboardTunnelLook is the LED and the style a tunnel state is drawn with.
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

// agentDashboardTunnelRow lays out what follows the marker and the LED of a
// tunnel row. The LED already shows the state, so the state word and then the
// target are the first columns to go when the pane narrows.
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
