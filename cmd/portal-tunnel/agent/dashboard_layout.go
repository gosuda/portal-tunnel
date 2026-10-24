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
	agentDashboardSidebarGutter       = 1
	agentDashboardSidebarWidth        = 32
	agentDashboardTunnelInputMaxWidth = 80
	agentDashboardFrameWidth          = 4  // columns the borders and one cell of padding on each side take
	agentDashboardFrameHeight         = 2  // rows the top and bottom border take
	agentDashboardMinPaneRows         = 3  // content rows every pane keeps, even when it is not the active one
	agentDashboardLabelWidth          = 15 // input row label, colon included
	agentDashboardMetaLabelWidth      = 10
	// agentDashboardDetailLabelWidth lines read-only details up with the text of the input rows above them.
	agentDashboardDetailLabelWidth = agentDashboardLabelWidth + 2
	// agentDashboardInputChrome is what an input row spends besides its text
	// area: the label, a space, the 2-cell prompt and the cursor cell.
	agentDashboardInputChrome = agentDashboardLabelWidth + 4
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
	visible := sidebarWidth - agentDashboardFrameWidth
	m.sidebarScrollX = max(0, min(m.sidebarScrollX, max(0, m.sidebarContentWidth()-visible)))
}

func (m agentDashboardModel) sidebarContentWidth() int {
	configPath := strings.TrimSpace(m.status.ConfigPath)
	configPath = cmp.Or(configPath, strings.TrimSpace(m.configPath))
	contentWidth := agentDashboardMetaWidth(configPath)
	contentWidth = max(contentWidth, agentDashboardMetaWidth(strings.TrimSpace(m.status.ControlAddr)))
	contentWidth = max(contentWidth, agentDashboardMetaWidth(strconv.Itoa(len(m.status.Tunnels))))
	if wallet := strings.TrimSpace(m.status.WalletAddress); wallet != "" {
		contentWidth = max(contentWidth, agentDashboardMetaWidth(wallet))
	}
	return contentWidth
}

// layout draws the title bar, the panes and the sidebar side by side, and an
// error line when there is one.
func (m agentDashboardModel) layout() agentDashboardView {
	width := m.width
	if width <= 0 {
		width = 88
	}
	mainWidth, gutter, sidebarWidth := agentDashboardColumnWidths(width)

	var status string
	if m.err != nil && m.status.ControlAddr != "" {
		status = m.theme.failed.Render(agentDashboardFit(fmt.Sprintf("%s Error: %v", m.theme.glyph.ledFailed, m.err), width))
	}
	bodyHeight := 0
	if m.height > 0 {
		bodyHeight = max(1, m.height-1)
		if status != "" {
			bodyHeight = max(1, bodyHeight-1)
		}
	}

	var out agentDashboardView
	out.addLine(m.renderTitleBar(width))
	out.addView(agentDashboardJoinHorizontal(m.renderMain(mainWidth, bodyHeight), m.renderSidebar(sidebarWidth, bodyHeight), mainWidth, gutter, width, bodyHeight))
	if status != "" {
		out.addLine(status)
	}
	return out
}

func (m agentDashboardModel) renderTitleBar(width int) string {
	th := &m.theme
	rule := th.glyph.horizontal
	name := agentDashboardFit("PORTAL TUNNEL TERMINAL", max(1, width-4))
	left := th.rule.Render(rule) + " " + th.strong.Render(name) + " "
	right := " " + th.muted.Render("Agent "+types.ReleaseVersion) + " " + th.rule.Render(rule)
	fill := width - lipgloss.Width(left) - lipgloss.Width(right)
	if fill < 1 {
		right = ""
		fill = width - lipgloss.Width(left)
	}
	return left + th.rule.Render(strings.Repeat(rule, max(0, fill))) + right
}

// renderMain stacks the Tunnels, Settings and Relays panes in frames that
// together fill height rows; height 0 gives every pane its natural size.
func (m agentDashboardModel) renderMain(width, height int) agentDashboardView {
	if m.err != nil && m.status.ControlAddr == "" {
		return m.renderUnavailable(width, height)
	}

	inner := width - agentDashboardFrameWidth
	var want [agentDashboardPaneCount]int
	for pane := range agentDashboardPaneCount {
		want[pane] = len(m.renderPane(pane, inner, 0).lines)
	}
	rows := agentDashboardPaneRows(height, want, m.activePane)

	titles := [agentDashboardPaneCount]string{"TUNNELS", "SETTINGS", "RELAYS"}
	var main agentDashboardView
	for pane := range agentDashboardPaneCount {
		y := len(main.lines)
		x0, x1 := main.addFrame(&m.theme, titles[pane], pane == m.activePane, width, rows[pane], m.renderPane(pane, inner, rows[pane]))
		main.regions = append(main.regions, agentDashboardRegion{x0: x0, x1: x1, y: y, action: agentDashboardActionSelectPane, pane: pane})
	}
	return main
}

// renderPane draws the content of a pane in at most rows lines; rows 0 means all of it.
func (m agentDashboardModel) renderPane(pane agentDashboardPane, width, rows int) agentDashboardView {
	switch pane {
	case agentDashboardPaneSettings:
		return m.renderSettingsSection(width, rows)
	case agentDashboardPaneRelays:
		return m.renderRelaysSection(width, rows)
	default:
		return m.renderTunnelsSection(width, rows)
	}
}

// agentDashboardPaneRows divides height terminal rows between the panes. Every
// pane keeps a few rows, the active pane then grows to the rows it wants, the
// other panes share what is left a row at a time, and any excess goes to the
// last pane so the column fills the body.
func agentDashboardPaneRows(height int, want [agentDashboardPaneCount]int, active agentDashboardPane) [agentDashboardPaneCount]int {
	if height <= 0 {
		return want
	}
	var rows [agentDashboardPaneCount]int
	free := height - agentDashboardFrameHeight*int(agentDashboardPaneCount)
	for pane := range agentDashboardPaneCount {
		rows[pane] = min(want[pane], agentDashboardMinPaneRows)
		free -= rows[pane]
	}
	grow := max(0, min(want[active]-rows[active], free))
	rows[active] += grow
	free -= grow
	for grown := true; grown && free > 0; {
		grown = false
		for pane := range agentDashboardPaneCount {
			if rows[pane] < want[pane] && free > 0 {
				rows[pane]++
				free--
				grown = true
			}
		}
	}
	rows[agentDashboardPaneCount-1] += max(0, free)
	return rows
}

func (m agentDashboardModel) renderUnavailable(width, height int) agentDashboardView {
	th := &m.theme
	inner := width - agentDashboardFrameWidth
	var content agentDashboardView
	content.addStyled(inner, th.failed, fmt.Sprintf("%s Agent unavailable: %v", th.glyph.ledFailed, m.err))
	content.addLine("")
	content.addStyled(inner, th.text, "Start managed service: portal agent run --config "+m.configPath)
	content.addStyled(inner, th.text, "No service manager:   portal agent run --foreground --config "+m.configPath)

	var out agentDashboardView
	out.addFrame(th, "AGENT", true, width, max(0, height-agentDashboardFrameHeight), content)
	return out
}

func (m agentDashboardModel) renderSidebar(width, height int) agentDashboardView {
	th := &m.theme
	inner := width - agentDashboardFrameWidth
	var content agentDashboardView

	configPath := strings.TrimSpace(m.status.ConfigPath)
	configPath = cmp.Or(configPath, strings.TrimSpace(m.configPath))
	content.addMeta(th, inner, agentDashboardMetaLabelWidth, m.sidebarScrollX, "Config", configPath)
	content.addMeta(th, inner, agentDashboardMetaLabelWidth, m.sidebarScrollX, "Control", strings.TrimSpace(m.status.ControlAddr))
	content.addMeta(th, inner, agentDashboardMetaLabelWidth, m.sidebarScrollX, "Tunnels", strconv.Itoa(len(m.status.Tunnels)))
	if wallet := strings.TrimSpace(m.status.WalletAddress); wallet != "" {
		content.addMeta(th, inner, agentDashboardMetaLabelWidth, m.sidebarScrollX, "Wallet", wallet)
	}
	content.addLine("")
	content.addSidebarTitle(th, inner, "Legend")
	for _, state := range []string{"running", "starting", "stopped", "error"} {
		led, style := agentDashboardTunnelLook(th, state)
		content.addStyled(inner, style, led+" "+state)
	}

	var out agentDashboardView
	out.addFrame(th, "RUNTIME", false, width, max(0, height-agentDashboardFrameHeight), content)
	return out
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
		line += th.rule.Render(strings.Repeat(th.glyph.divider, ruleWidth))
	}
	v.addLine(line)
}

func (v *agentDashboardView) addMeta(th *agentDashboardTheme, width, labelWidth, offset int, label, value string) {
	value = strings.TrimSpace(value)
	value = cmp.Or(value, "-")
	labelText := th.muted.Render(agentDashboardCell(label+":", labelWidth))
	valueText := th.text.Render(agentDashboardWindow(value, offset, max(1, width-labelWidth-1)))
	v.addLine(labelText + " " + valueText)
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

// addFrame draws content in a double-line box of the given outer width with the
// title in the top border, and returns the columns the title spans. The box is
// rows content lines tall, or as tall as the content when rows is 0.
func (v *agentDashboardView) addFrame(th *agentDashboardTheme, title string, active bool, width, rows int, content agentDashboardView) (int, int) {
	g := th.glyph
	inner := max(0, width-agentDashboardFrameWidth)
	edge := max(0, width-2) // between the corners
	border, labelStyle, open, closing := th.rule, th.muted, " ", " "
	if active {
		border, labelStyle, open, closing = th.strong, th.selected, g.activeOpen, g.activeClose
	}
	label := open + agentDashboardFit(title, max(1, edge-1-lipgloss.Width(g.activeOpen+g.activeClose))) + closing
	labelWidth := lipgloss.Width(label)
	v.addLine(border.Render(g.topLeft+g.horizontal) + labelStyle.Render(label) +
		border.Render(strings.Repeat(g.horizontal, max(0, edge-1-labelWidth))+g.topRight))

	if rows <= 0 {
		rows = len(content.lines)
	}
	content = content.window(0, rows)
	startY := len(v.lines)
	side := border.Render(g.vertical)
	for i := range rows {
		line := ""
		if i < len(content.lines) {
			line = content.lines[i]
		}
		v.addLine(side + " " + agentDashboardPadLine(line, inner) + " " + side)
	}
	for _, region := range content.regions {
		region.x0 += agentDashboardFrameWidth / 2
		region.x1 += agentDashboardFrameWidth / 2
		region.y += startY
		v.regions = append(v.regions, region)
	}
	v.addLine(border.Render(g.bottomLeft + strings.Repeat(g.horizontal, edge) + g.bottomRight))
	return 2, 2 + labelWidth
}

// window returns at most rows lines of the view, scrolled so that the focus
// line is visible.
func (v agentDashboardView) window(focus, rows int) agentDashboardView {
	if rows <= 0 || rows >= len(v.lines) {
		return v
	}
	start, end := agentDashboardRowWindow(focus, len(v.lines), rows)
	out := agentDashboardView{lines: v.lines[start:end]}
	for _, region := range v.regions {
		if region.y >= start && region.y < end {
			region.y -= start
			out.regions = append(out.regions, region)
		}
	}
	return out
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

// addClickRow adds a row that fills the width and acts on click. A line that is
// too wide is truncated; the caller keeps any leading space of a line that fits.
func (v *agentDashboardView) addClickRow(line string, width int, style lipgloss.Style, action agentDashboardAction, tunnel, relay string) {
	if lipgloss.Width(line) > width {
		line = agentDashboardFit(line, width)
	}
	y := len(v.lines)
	v.lines = append(v.lines, style.Width(width).Render(line))
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
	// The input would shorten a placeholder that is too long with a non-ASCII ellipsis.
	input.Placeholder = agentDashboardFit(input.Placeholder, input.Width-lipgloss.Width(input.Prompt))
	input.Prompt = th.glyph.promptBlurred
	if focused {
		labelStyle = th.bright
		input.Prompt = th.glyph.promptFocused
	}
	labelText := agentDashboardCell(label+":", agentDashboardLabelWidth)
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
		open, closing, style := th.glyph.buttonOpen, th.glyph.buttonClose, th.strong
		if button.disabled {
			open, closing, style = th.glyph.buttonOffOpen, th.glyph.buttonOffClose, th.muted
		}
		plain := open + button.label + closing
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
		if !button.disabled {
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
	return agentDashboardMetaLabelWidth + 1 + lipgloss.Width(value)
}

// agentDashboardRowWindow picks the rows of a list of total rows that fit in
// rows lines and keep the selected row visible, centered when it can be.
func agentDashboardRowWindow(selected, total, rows int) (int, int) {
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
