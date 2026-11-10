package agent

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func agentDashboardRenderButtons(th *agentDashboardTheme, width, y, x int, buttons ...agentDashboardButton) ([]string, []agentDashboardRegion) {
	if width <= 0 {
		width = 1
	}
	accum := &agentDashboardButtonLine{lineY: y, lineX: x, width: width, x: x}
	for i, button := range buttons {
		face := newAgentDashboardButtonFace(th, width, button)
		space := 0
		if i > 0 && accum.line.Len() > 0 {
			space = 1
		}
		space = accum.wrapButtonLine(space, face.width)
		accum.appendButtonFace(face, space)
	}
	if accum.line.Len() > 0 || len(accum.lines) == 0 {
		accum.lines = append(accum.lines, accum.line.String())
	}
	return accum.lines, accum.regions
}

type agentDashboardButtonLine struct {
	line    strings.Builder
	lines   []string
	regions []agentDashboardRegion
	lineY   int
	lineX   int
	width   int
	x       int
}

func (a *agentDashboardButtonLine) wrapButtonLine(space, faceWidth int) int {
	if a.line.Len() > 0 && a.lineX+space+faceWidth > a.width {
		a.lines = append(a.lines, a.line.String())
		a.line.Reset()
		a.lineY++
		a.lineX = a.x
		return 0
	}
	return space
}

func (a *agentDashboardButtonLine) appendButtonFace(face agentDashboardButtonFace, space int) {
	if space > 0 {
		a.line.WriteString(" ")
		a.lineX++
	}
	if region, ok := face.region(a.lineX, a.lineY, a.width); ok {
		a.regions = append(a.regions, region)
	}
	a.line.WriteString(face.style.Render(face.plain))
	a.lineX += face.width
}

type agentDashboardButtonFace struct {
	plain    string
	style    lipgloss.Style
	width    int
	action   agentDashboardAction
	disabled bool
}

func newAgentDashboardButtonFace(th *agentDashboardTheme, width int, button agentDashboardButton) agentDashboardButtonFace {
	style := th.strong
	open, closing := th.glyph.buttonOpen, th.glyph.buttonClose
	if button.disabled {
		style = th.muted
		open, closing = th.glyph.buttonOffOpen, th.glyph.buttonOffClose
	}
	plain := open + button.label + closing
	if lipgloss.Width(plain) > width {
		plain = agentDashboardFit(plain, width)
	}
	return agentDashboardButtonFace{plain: plain, style: style, width: lipgloss.Width(plain), action: button.action, disabled: button.disabled}
}

func (f agentDashboardButtonFace) region(lineX, lineY, width int) (agentDashboardRegion, bool) {
	if f.disabled {
		return agentDashboardRegion{}, false
	}
	return agentDashboardRegion{x0: lineX, x1: min(lineX+f.width, width), y: lineY, action: f.action}, true
}
