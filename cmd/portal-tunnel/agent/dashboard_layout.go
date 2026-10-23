package agent

import (
	"cmp"
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	agentDashboardMinRelayRows        = 5
	agentDashboardSidebarGutter       = 2
	agentDashboardSidebarWidth        = 32
	agentDashboardTunnelInputMaxWidth = 80
)

type agentDashboardRegion struct {
	x0     int
	x1     int
	y      int
	action agentDashboardAction
	tunnel string
	relay  string
	field  int
	pane   agentDashboardPane
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

func (m agentDashboardModel) mouseInSidebar(event tea.MouseEvent) bool {
	mainWidth, gutter, _ := agentDashboardColumnWidths(m.width)
	return event.X >= mainWidth+gutter
}

func (m *agentDashboardModel) clampSidebarScroll() {
	_, _, sidebarWidth := agentDashboardColumnWidths(m.width)
	m.sidebarScrollX = max(0, min(m.sidebarScrollX, max(0, m.sidebarContentWidth()-sidebarWidth)))
}

func (m agentDashboardModel) sidebarContentWidth() int {
	configPath := strings.TrimSpace(m.status.ConfigPath)
	configPath = cmp.Or(configPath, strings.TrimSpace(m.configPath))
	contentWidth := lipgloss.Width("PORTAL")
	contentWidth = max(contentWidth, agentDashboardMetaWidth(configPath))
	contentWidth = max(contentWidth, agentDashboardMetaWidth(strings.TrimSpace(m.status.ControlAddr)))
	contentWidth = max(contentWidth, agentDashboardMetaWidth(strconv.Itoa(len(m.status.Tunnels))))
	if wallet := strings.TrimSpace(m.status.WalletAddress); wallet != "" {
		contentWidth = max(contentWidth, agentDashboardMetaWidth(wallet))
	}
	return contentWidth
}

func (m agentDashboardModel) layout() agentDashboardView {
	width := m.width
	if width <= 0 {
		width = 88
	}
	mainWidth, gutter, sidebarWidth := agentDashboardColumnWidths(width)
	main := m.renderMainLayout(mainWidth)
	sidebar := m.renderSidebar(sidebarWidth, m.height)
	return agentDashboardJoinHorizontal(main, sidebar, mainWidth, gutter, width, m.height)
}

func (m agentDashboardModel) renderMainLayout(width int) agentDashboardView {
	bodyHeight := defaultDashboardBodyHeight(m.height)

	var layout agentDashboardView
	if m.err != nil && m.status.ControlAddr == "" {
		layout.addStyled(width, m.theme.failed, fmt.Sprintf("Agent unavailable: %v", m.err))
		layout.addLine("")
		layout.addStyled(width, m.theme.text, "Start managed service: portal agent run --config "+m.configPath)
		layout.addStyled(width, m.theme.text, "No service manager:   portal agent run --foreground --config "+m.configPath)
		return layout
	}

	if m.err != nil {
		layout.addStyled(width, m.theme.failed, fmt.Sprintf("Error: %v", m.err))
	}
	layout.addLine("")
	if m.height > 0 {
		bodyHeight = max(1, m.height-len(layout.lines))
	}

	tunnels := m.renderTunnelsSection(width, m.tunnelsSectionHeight(bodyHeight))
	layout.addView(tunnels)
	layout.addLine("")
	if m.height > 0 {
		bodyHeight = max(1, m.height-len(layout.lines))
	}
	body := m.renderTunnelPane(width, bodyHeight)
	layout.addView(body)
	return layout
}

func (m agentDashboardModel) renderSidebar(width, height int) agentDashboardView {
	th := &m.theme
	var pane agentDashboardView
	pane.addStyled(width, th.rule, strings.Repeat("/", width))
	pane.addStyled(width, th.strong, "PORTAL")
	pane.addStyled(width, th.muted, "Agent "+types.ReleaseVersion)
	pane.addStyled(width, th.rule, strings.Repeat("-", width))

	configPath := strings.TrimSpace(m.status.ConfigPath)
	configPath = cmp.Or(configPath, strings.TrimSpace(m.configPath))
	pane.addSidebarTitle(th, width, "Runtime")
	pane.addMeta(th, width, m.sidebarScrollX, "Config", configPath)
	pane.addMeta(th, width, m.sidebarScrollX, "Control", strings.TrimSpace(m.status.ControlAddr))
	pane.addMeta(th, width, m.sidebarScrollX, "Tunnels", strconv.Itoa(len(m.status.Tunnels)))
	if wallet := strings.TrimSpace(m.status.WalletAddress); wallet != "" {
		pane.addMeta(th, width, m.sidebarScrollX, "Wallet", wallet)
	}

	pane.clip(height)
	return pane
}

func (m agentDashboardModel) renderTunnelPane(width, height int) agentDashboardView {
	var pane agentDashboardView
	tunnel, ok := m.selectedTunnelStatus()
	if !ok {
		pane.addSectionTitle(&m.theme, width, agentDashboardPaneSettings, "Settings", m.activePane == agentDashboardPaneSettings)
		pane.addStyled(width, m.theme.muted, "select a tunnel")
		pane.clip(height)
		return pane
	}

	m.renderSettingsSection(&pane, width, height, tunnel)
	pane.addLine("")
	relayLimit := m.relayRowsForHeight(tunnel, max(1, height-len(pane.lines)))
	m.renderRelaysSection(&pane, width, relayLimit, tunnel)
	pane.addLine("")
	pane.clip(height)
	return pane
}

func (v *agentDashboardView) addLine(line string) {
	v.lines = append(v.lines, line)
}

func (v *agentDashboardView) addStyled(width int, style lipgloss.Style, text string) {
	v.addLine(style.Render(agentDashboardFit(text, width)))
}

func (v *agentDashboardView) addSidebarTitle(th *agentDashboardTheme, width int, title string) {
	label := agentDashboardFit(strings.TrimSpace(title), width)
	line := th.strong.Render(label)
	if ruleWidth := width - lipgloss.Width(label); ruleWidth > 0 {
		line += th.rule.Render(strings.Repeat("-", ruleWidth))
	}
	v.addLine(line)
}

func (v *agentDashboardView) addMeta(th *agentDashboardTheme, width, offset int, label, value string) {
	value = strings.TrimSpace(value)
	value = cmp.Or(value, "-")
	labelText := th.muted.Render(agentDashboardCell(label+":", 9))
	valueText := th.text.Render(agentDashboardWindow(value, offset, max(1, width-10)))
	v.addLine(labelText + " " + valueText)
}

func (v *agentDashboardView) addSectionTitle(th *agentDashboardTheme, width int, pane agentDashboardPane, title string, active bool) {
	if width <= 0 {
		width = 1
	}
	style := th.strong
	if active {
		style = th.selected
	}
	label := agentDashboardFit(" "+title+" ", width)
	labelWidth := lipgloss.Width(label)
	line := style.Render(label)
	if ruleWidth := width - labelWidth; ruleWidth > 0 {
		line += th.rule.Render(strings.Repeat("-", ruleWidth))
	}
	y := len(v.lines)
	v.lines = append(v.lines, line)
	v.regions = append(v.regions, agentDashboardRegion{
		x0:     0,
		x1:     min(labelWidth, width),
		y:      y,
		action: agentDashboardActionSelectPane,
		pane:   pane,
	})
}

func (v *agentDashboardView) addButtons(th *agentDashboardTheme, width int, buttons ...agentDashboardButton) {
	lines, regions := agentDashboardRenderButtons(th, width, len(v.lines), 0, buttons...)
	v.lines = append(v.lines, lines...)
	v.regions = append(v.regions, regions...)
}

func (v *agentDashboardView) addView(child agentDashboardView) {
	startY := len(v.lines)
	v.lines = append(v.lines, child.lines...)
	for _, region := range child.regions {
		region.y += startY
		v.regions = append(v.regions, region)
	}
}

func agentDashboardJoinHorizontal(left, right agentDashboardView, leftWidth, gutter, totalWidth, height int) agentDashboardView {
	rows := max(len(left.lines), len(right.lines))
	if height > 0 {
		rows = height
	}
	var out agentDashboardView
	out.lines = make([]string, 0, rows)
	gap := strings.Repeat(" ", gutter)
	rightWidth := max(1, totalWidth-leftWidth-gutter)
	for i := range rows {
		leftLine, rightLine := "", ""
		if i < len(left.lines) {
			leftLine = left.lines[i]
		}
		if i < len(right.lines) {
			rightLine = right.lines[i]
		}
		out.lines = append(out.lines,
			agentDashboardPadLine(leftLine, leftWidth)+gap+agentDashboardPadLine(rightLine, rightWidth),
		)
	}
	for _, region := range left.regions {
		if height <= 0 || region.y < height {
			out.regions = append(out.regions, region)
		}
	}
	for _, region := range right.regions {
		if height > 0 && region.y >= height {
			continue
		}
		region.x0 += leftWidth + gutter
		region.x1 += leftWidth + gutter
		out.regions = append(out.regions, region)
	}
	return out
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

func (v *agentDashboardView) addInputRow(th *agentDashboardTheme, width int, label string, input textinput.Model, action agentDashboardAction, field int, focused bool) {
	if width <= 0 {
		width = 1
	}
	labelStyle := th.muted
	if focused {
		labelStyle = th.bright
	}
	labelText := agentDashboardCell(label+":", 12)
	y := len(v.lines)
	v.lines = append(v.lines, labelStyle.Render(labelText)+" "+input.View())
	v.regions = append(v.regions, agentDashboardRegion{
		x0:     0,
		x1:     width,
		y:      y,
		action: action,
		field:  field,
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

func agentDashboardRenderButtons(th *agentDashboardTheme, width, y, x int, buttons ...agentDashboardButton) ([]string, []agentDashboardRegion) {
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
		style := th.strong
		if button.disabled {
			style = th.muted
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

func agentDashboardColumnWidths(width int) (int, int, int) {
	if width <= 0 {
		width = 88
	}
	gutter := agentDashboardSidebarGutter
	if width <= gutter+2 {
		gutter = 0
	}
	sidebarWidth := min(agentDashboardSidebarWidth, max(1, width-gutter-1))
	mainWidth := max(1, width-sidebarWidth-gutter)
	return mainWidth, gutter, sidebarWidth
}

func agentDashboardMetaWidth(value string) int {
	value = strings.TrimSpace(value)
	value = cmp.Or(value, "-")
	return 10 + lipgloss.Width(value)
}

func defaultDashboardBodyHeight(height int) int {
	bodyHeight := height - 8
	if height <= 0 {
		bodyHeight = 22
	}
	return max(bodyHeight, 1)
}

func agentDashboardRelayWindow(selected, total, rows int) (int, int) {
	if total <= 0 || rows <= 0 {
		return 0, 0
	}
	if rows >= total {
		return 0, total
	}
	if selected < 0 {
		selected = 0
	}
	if selected >= total {
		selected = total - 1
	}
	start := max(selected-rows/2, 0)
	if start+rows > total {
		start = total - rows
	}
	return start, start + rows
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

func agentDashboardWindow(value string, offset, width int) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), "\t", " ")
	if value == "" || width <= 0 {
		return ""
	}
	offset = max(0, offset)
	if offset == 0 && lipgloss.Width(value) <= width {
		return value
	}
	var out strings.Builder
	skipped := 0
	used := 0
	for _, r := range value {
		cellWidth := lipgloss.Width(string(r))
		if skipped+cellWidth <= offset {
			skipped += cellWidth
			continue
		}
		if skipped < offset {
			skipped += cellWidth
			continue
		}
		if used+cellWidth > width {
			break
		}
		out.WriteRune(r)
		used += cellWidth
	}
	return out.String()
}

func agentDashboardPadLine(line string, width int) string {
	if pad := width - lipgloss.Width(line); pad > 0 {
		return line + strings.Repeat(" ", pad)
	}
	return line
}

func agentDashboardCell(value string, width int) string {
	value = agentDashboardFit(value, width)
	if lipgloss.Width(value) >= width {
		return value
	}
	return value + strings.Repeat(" ", width-lipgloss.Width(value))
}
