package agent

import (
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const agentDashboardKeyBarGap = "  "

type agentDashboardBinding struct {
	keys  []string
	label string
	when  func(agentDashboardModel) bool
	run   func(m agentDashboardModel, key string) (tea.Model, tea.Cmd)
}

var agentDashboardBindings = []agentDashboardBinding{
	{
		keys: []string{"y"}, label: "Yes", when: agentDashboardModel.confirming,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) { return m.answerYes() },
	},
	{
		keys: []string{"n", "esc", "q", "f10"}, label: "No", when: agentDashboardModel.confirming,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) { return m.answerNo() },
	},
	{
		keys: []string{"f2", "enter"}, label: "Create", when: agentDashboardModel.inForm,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) { return m.addTunnelFromInput() },
	},
	{
		keys: []string{"esc"}, label: "Cancel", when: agentDashboardModel.inForm,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) {
			m.err = nil
			m.cancelTunnelInput()
			return m, nil
		},
	},
	{
		keys: []string{"enter"}, label: "Apply", when: agentDashboardModel.inSettings,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) { return m.applySettingsEdit() },
	},
	{
		keys: []string{"enter"}, label: "Add entry", when: agentDashboardModel.onAccessAdd,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) {
			m.addAccessEntry()
			return m, nil
		},
	},
	{
		keys: []string{"f2", "enter"}, label: "Apply", when: agentDashboardModel.inAccess,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) { return m.applyAccess() },
	},
	{
		keys: []string{"esc"}, label: "Cancel", when: agentDashboardModel.inAccess,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) {
			m.err = nil
			m.closeAccess()
			return m, nil
		},
	},
	{
		keys: []string{"left", "right"}, label: "Change", when: agentDashboardModel.onAccessChoice,
		run: func(m agentDashboardModel, key string) (tea.Model, tea.Cmd) {
			m.changeAccessChoice(agentDashboardKeyStep(key))
			return m, nil
		},
	},
	{
		keys: []string{"delete", "backspace"}, label: "Remove", when: agentDashboardModel.onAccessEntry,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) {
			m.access.removeEntry()
			return m, nil
		},
	},
	{
		keys: []string{"f3", "ctrl+r"}, label: "Show", when: agentDashboardModel.onAccessSecret,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) {
			m.access.toggleReveal()
			return m, nil
		},
	},
	{
		keys: []string{"f6", "ctrl+x"}, label: "Clear", when: agentDashboardModel.canClearAccessSecret,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) {
			tunnel, _ := m.accessTunnel()
			m.access.setClearSecret(!m.access.clearSecret, tunnel)
			return m, nil
		},
	},
	{
		keys: []string{"tab", "shift+tab", "down", "up"}, label: "Field", when: agentDashboardModel.editing,
		run: func(m agentDashboardModel, key string) (tea.Model, tea.Cmd) {
			step := agentDashboardKeyStep(key)
			switch {
			case m.inForm():
				m.focusAddTunnelField(m.addFocus + step)
			case m.accessing():
				m.access.moveFocus(m.access.focusIndex() + step)
			default:
				m.focusSettingsField(m.settingsFocus + step)
			}
			return m, nil
		},
	},
	{
		keys: []string{"enter", "c"}, label: "Connect", when: agentDashboardModel.inRelays,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) { return m.connectSelectedRelay() },
	},
	{
		keys: []string{"d", "delete"}, label: "Disconnect", when: agentDashboardModel.inRelays,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) { return m.disconnectSelectedRelay() },
	},
	{
		keys: []string{"o"}, label: "Open", when: agentDashboardModel.inRelays,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) { return m.openRelayTunnelURL("", "") },
	},
	{
		keys: []string{"up", "down"}, label: "Select", when: agentDashboardModel.inRelays,
		run: func(m agentDashboardModel, key string) (tea.Model, tea.Cmd) {
			m.selectRelayOffset(agentDashboardKeyStep(key))
			return m, nil
		},
	},
	{
		keys: []string{"f8", "delete"}, label: "Delete", when: agentDashboardModel.inList,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) { return m.askDeleteTunnel("") },
	},
	{
		keys: []string{"up", "down"}, label: "Select", when: agentDashboardModel.inList,
		run: func(m agentDashboardModel, key string) (tea.Model, tea.Cmd) {
			m.selectTunnelOffset(agentDashboardKeyStep(key))
			return m, nil
		},
	},
	{
		keys: []string{"tab", "right", "shift+tab", "left"}, label: "Pane", when: agentDashboardModel.browsing,
		run: func(m agentDashboardModel, key string) (tea.Model, tea.Cmd) {
			m.setActivePane(m.activePane + agentDashboardPane(agentDashboardKeyStep(key)))
			return m, nil
		},
	},
	{
		keys: []string{"f2", "a"}, label: "Add", when: agentDashboardModel.canAdd,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) { return m.startOrAddTunnel() },
	},
	{
		keys: []string{"f4", "s"}, label: "Access", when: agentDashboardModel.canOpenAccess,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) { return m.openAccess() },
	},
	{
		keys: []string{"esc"}, label: "Back", when: agentDashboardModel.awayFromTunnels,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) {
			m.err = nil
			m.setActivePane(agentDashboardPaneTunnels)
			return m, nil
		},
	},
	{
		keys: []string{"esc"}, when: agentDashboardModel.browsing,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) {
			m.err = nil
			return m, nil
		},
	},
	{
		keys: []string{"f10", "q"}, label: "Stop agent", when: agentDashboardModel.asksBeforeStopping,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) {
			m.confirmStop = true
			return m, nil
		},
	},
	{
		keys: []string{"ctrl+c"}, when: agentDashboardModel.asksBeforeStopping,
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) { return m, tea.Quit },
	},
	{
		keys: []string{"f10", "q", "ctrl+c"}, label: "Quit",
		run: func(m agentDashboardModel, _ string) (tea.Model, tea.Cmd) { return m, tea.Quit },
	},
}

var agentDashboardKeyNames = map[string]string{
	"enter": "Enter", "esc": "Esc", "tab": "Tab", "shift+tab": "S-Tab", "delete": "Del", "backspace": "Bksp",
	"ctrl+c": "^C", "ctrl+r": "^R", "ctrl+x": "^X",
}

type agentDashboardLiveBinding struct {
	binding agentDashboardBinding
	keys    []string
}

func (m agentDashboardModel) confirming() bool { return m.confirmDelete != "" || m.confirmStop }

func (m agentDashboardModel) asksBeforeStopping() bool { return m.stopsAgent && !m.confirming() }

func (m agentDashboardModel) browsing() bool { return !m.confirming() && !m.accessing() }

func (m agentDashboardModel) inList() bool {
	return m.browsing() && m.activePane == agentDashboardPaneTunnels && !m.addingTunnel
}

func (m agentDashboardModel) inForm() bool {
	return m.browsing() && m.activePane == agentDashboardPaneTunnels && m.addingTunnel
}

func (m agentDashboardModel) inSettings() bool {
	return m.browsing() && m.activePane == agentDashboardPaneSettings
}

func (m agentDashboardModel) inRelays() bool {
	return m.browsing() && m.activePane == agentDashboardPaneRelays
}

func (m agentDashboardModel) awayFromTunnels() bool {
	return m.browsing() && m.activePane != agentDashboardPaneTunnels
}

func (m agentDashboardModel) canAdd() bool { return m.browsing() && !m.addingTunnel }

func (m agentDashboardModel) canOpenAccess() bool {
	return m.browsing() && !m.inForm() && len(m.status.Tunnels) > 0
}

func (m agentDashboardModel) onAccessRow(row agentDashboardAccessRow) bool {
	return m.inAccess() && m.access.current().row == row
}

func (m agentDashboardModel) onAccessAdd() bool {
	return m.onAccessRow(agentDashboardAccessRowAdd)
}

func (m agentDashboardModel) onAccessEntry() bool {
	return m.onAccessRow(agentDashboardAccessRowEntry)
}

func (m agentDashboardModel) onAccessSecret() bool {
	return m.onAccessRow(agentDashboardAccessRowSecret)
}

func (m agentDashboardModel) onAccessChoice() bool {
	return m.onAccessRow(agentDashboardAccessRowMode) || m.onAccessRow(agentDashboardAccessRowHeaders)
}

func (m agentDashboardModel) canClearAccessSecret() bool {
	tunnel, ok := m.accessTunnel()
	return ok && m.onAccessSecret() && agentDashboardSecretSet(m.access.provider, tunnel)
}

func (m agentDashboardModel) inAccess() bool { return m.accessing() && !m.confirming() }

func (m agentDashboardModel) editing() bool { return m.inForm() || m.inSettings() || m.inAccess() }

func (m agentDashboardModel) liveBindings() []agentDashboardLiveBinding {
	editing := m.editing()
	claimed := make(map[string]bool)
	var live []agentDashboardLiveBinding
	for _, binding := range agentDashboardBindings {
		if binding.when != nil && !binding.when(m) {
			continue
		}
		var keys []string
		for _, key := range binding.keys {
			if claimed[key] || (editing && utf8.RuneCountInString(key) == 1) {
				continue
			}
			claimed[key] = true
			keys = append(keys, key)
		}
		if len(keys) > 0 {
			live = append(live, agentDashboardLiveBinding{binding: binding, keys: keys})
		}
	}
	return live
}

func (m agentDashboardModel) updateKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	for _, live := range m.liveBindings() {
		if slices.Contains(live.keys, key) {
			return live.binding.run(m, key)
		}
	}
	return m.updateInput(msg)
}

func (m agentDashboardModel) updateInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var input *textinput.Model
	switch {
	case m.inForm():
		input = m.focusedAddTunnelInput()
	case m.inSettings():
		input = m.focusedSettingsInput()
	case m.inAccess():
		input = m.access.focusedInput()
	}
	if input == nil {
		return m, nil
	}
	var cmd tea.Cmd
	*input, cmd = input.Update(msg)
	if m.inAccess() && input == &m.access.secret && input.Value() != "" && m.access.clearSecret {
		tunnel, _ := m.accessTunnel()
		m.access.setClearSecret(false, tunnel)
	}
	return m, cmd
}

func agentDashboardKeyStep(key string) int {
	switch key {
	case "up", "shift+tab", "left":
		return -1
	default:
		return 1
	}
}

func (m agentDashboardModel) renderKeyBar(width int) string {
	th := &m.theme
	type entry struct{ hint, label string }
	var entries []entry
	for _, live := range m.liveBindings() {
		if live.binding.label != "" {
			entries = append(entries, entry{hint: th.keyHint(live.keys), label: live.binding.label})
		}
	}

	entryWidth := func(e entry) int { return lipgloss.Width(e.hint) + 1 + lipgloss.Width(e.label) }
	gap := lipgloss.Width(agentDashboardKeyBarGap)
	used := 1
	if len(entries) > 0 {
		used += gap + entryWidth(entries[len(entries)-1])
	}
	var parts []string
	for i, e := range entries {
		if i < len(entries)-1 {
			if used+gap+entryWidth(e) > width {
				continue
			}
			used += gap + entryWidth(e)
		}
		parts = append(parts, th.selected.Render(e.hint)+" "+th.text.Render(e.label))
	}
	return agentDashboardPadLine(" "+strings.Join(parts, agentDashboardKeyBarGap), width)
}

func (th *agentDashboardTheme) keyHint(keys []string) string {
	names := make([]string, 0, 2)
	for _, key := range keys[:min(2, len(keys))] {
		names = append(names, th.keyName(key))
	}
	return strings.Join(names, "/")
}

func (th *agentDashboardTheme) keyName(key string) string {
	switch key {
	case "up":
		return th.glyph.arrowUp
	case "down":
		return th.glyph.arrowDown
	case "left":
		return th.glyph.arrowLeft
	case "right":
		return th.glyph.arrowRight
	}
	if name, ok := agentDashboardKeyNames[key]; ok {
		return name
	}
	if len(key) > 1 && key[0] == 'f' && key[1] >= '0' && key[1] <= '9' {
		return strings.ToUpper(key)
	}
	return key
}
