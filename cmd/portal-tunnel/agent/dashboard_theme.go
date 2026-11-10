package agent

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
)

// DefaultDashboardTheme is the default of the --theme flags.
const DefaultDashboardTheme = "amber"

type agentDashboardPalette struct {
	text    string
	bright  string
	dim     string
	rule    string
	pending string
	failed  string
	onText  string
}

var agentDashboardPalettes = map[string]agentDashboardPalette{
	"amber": {text: "214", bright: "220", dim: "136", rule: "94", pending: "214", failed: "202", onText: "16"},
	"green": {text: "77", bright: "120", dim: "65", rule: "28", pending: "214", failed: "202", onText: "16"},
}

type agentDashboardTerminal struct {
	unicode bool
}

func detectAgentDashboardTerminal() agentDashboardTerminal {
	term := os.Getenv("TERM")
	return agentDashboardTerminal{unicode: term != "dumb" && term != "linux" && localeIsUTF8()}
}

func localeIsUTF8() bool {
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if value := strings.ToLower(os.Getenv(name)); value != "" {
			return strings.Contains(value, "utf-8") || strings.Contains(value, "utf8")
		}
	}
	return false
}

type agentDashboardGlyphs struct {
	topLeft, topRight, bottomLeft, bottomRight string
	horizontal, vertical, divider              string

	ledLive, ledIdle, ledFailed, ledConnecting string

	selected, unselected                      string
	buttonOpen, buttonClose                   string
	buttonOffOpen, buttonOffClose             string
	promptFocused, promptBlurred              string
	mask                                      string
	activeOpen, activeClose                   string
	arrowUp, arrowDown, arrowLeft, arrowRight string
}

type agentDashboardTheme struct {
	glyph agentDashboardGlyphs

	text, muted, rule, bright, strong, selected, pending, failed lipgloss.Style
}

// ValidateDashboardTheme reports whether name selects a palette, so a command
// can refuse a bad name right after parsing it, before it starts anything.
func ValidateDashboardTheme(name string) error {
	if _, ok := agentDashboardPalettes[name]; !ok {
		return fmt.Errorf("%q: supported values are amber and green", name)
	}
	return nil
}

func newAgentDashboardTheme(name string, term agentDashboardTerminal) agentDashboardTheme {
	palette := agentDashboardPalettes[name]
	theme := agentDashboardTheme{glyph: agentDashboardGlyphSet(term.unicode)}
	fg := func(color string) lipgloss.Style { return lipgloss.NewStyle().Foreground(lipgloss.Color(color)) }
	theme.text = fg(palette.text)
	theme.muted = fg(palette.dim)
	theme.rule = fg(palette.rule)
	theme.bright = fg(palette.bright)
	theme.strong = fg(palette.bright).Bold(true)
	theme.selected = fg(palette.onText).Background(lipgloss.Color(palette.text)).Bold(true)
	theme.pending = fg(palette.pending)
	theme.failed = fg(palette.failed)
	return theme
}

func agentDashboardGlyphSet(unicode bool) agentDashboardGlyphs {
	glyphs := agentDashboardGlyphs{
		topLeft: "+", topRight: "+", bottomLeft: "+", bottomRight: "+",
		horizontal: "=", vertical: "|", divider: "-",
		ledLive: "[*]", ledIdle: "[ ]", ledFailed: "[!]", ledConnecting: "[~]",
		selected: ">", unselected: " ",
		buttonOpen: "[ ", buttonClose: " ]", buttonOffOpen: "( ", buttonOffClose: " )",
		promptFocused: "> ", promptBlurred: "  ",
		mask:       "*",
		activeOpen: "[ ", activeClose: " ]",
		arrowUp: "^", arrowDown: "v", arrowLeft: "<", arrowRight: ">",
	}
	if unicode {
		glyphs.topLeft, glyphs.topRight, glyphs.bottomLeft, glyphs.bottomRight = "╔", "╗", "╚", "╝"
		glyphs.horizontal, glyphs.vertical, glyphs.divider = "═", "║", "─"
		glyphs.arrowUp, glyphs.arrowDown, glyphs.arrowLeft, glyphs.arrowRight = "↑", "↓", "←", "→"
		glyphs.mask = "•"
	}
	return glyphs
}

func (th *agentDashboardTheme) newInput(placeholder string) textinput.Model {
	input := textinput.New()
	input.CharLimit = 512
	input.Placeholder = placeholder
	input.PromptStyle = th.strong
	input.TextStyle = th.bright
	input.PlaceholderStyle = th.muted
	input.Cursor.Style = th.text
	input.Cursor.TextStyle = th.bright
	return input
}

func (th *agentDashboardTheme) newSecretInput() textinput.Model {
	input := th.newInput("")
	input.EchoMode = textinput.EchoPassword
	input.EchoCharacter = []rune(th.glyph.mask)[0]
	return input
}
