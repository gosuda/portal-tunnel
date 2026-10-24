package agent

import (
	"github.com/charmbracelet/lipgloss"
)

var (
	agentDashboardSectionStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("45"))
	agentDashboardMutedStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	agentDashboardRuleStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
	agentDashboardHeaderStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("250"))
	agentDashboardSelectedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("25"))
	agentDashboardBrandStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("93"))
	agentDashboardLabelStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	agentDashboardButtonStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("238"))
	agentDashboardDisabledStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	agentDashboardErrorStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	agentDashboardOKStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("120"))
	agentDashboardPendingStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	agentDashboardInputStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("120"))
)
