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

// agentDashboardPalette lists ANSI-256 color indices. lipgloss downgrades them
// to the 16 ANSI colors on terminals that cannot show 256.
type agentDashboardPalette struct {
	text    string // body text and active frames
	bright  string // live state, typed input, titles
	dim     string // secondary text and idle state
	rule    string // inactive frames and dividers
	pending string // connecting and starting
	failed  string // errors
	onText  string // text drawn on a text-colored fill, such as the selection
}

var agentDashboardPalettes = map[string]agentDashboardPalette{
	// CRT amber: one hue, told apart by brightness.
	"amber": {text: "214", bright: "220", dim: "136", rule: "94", pending: "214", failed: "202", onText: "16"},
	// Phosphor green with amber warnings.
	"green": {text: "77", bright: "120", dim: "65", rule: "28", pending: "214", failed: "202", onText: "16"},
}

// agentDashboardTerminal is what the terminal environment allows.
type agentDashboardTerminal struct {
	unicode bool // box-drawing and arrow characters are safe to print
}

// detectAgentDashboardTerminal decides from TERM and the locale whether the
// frames can use box-drawing characters. Color is left to lipgloss, whose
// renderer drops every style when NO_COLOR is set or CLICOLOR is 0.
func detectAgentDashboardTerminal() agentDashboardTerminal {
	term := os.Getenv("TERM")
	return agentDashboardTerminal{unicode: term != "dumb" && term != "linux" && localeIsUTF8()}
}

// localeIsUTF8 follows the POSIX precedence: the first of LC_ALL, LC_CTYPE and
// LANG that is set decides, and an unset locale does not say UTF-8.
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

	selected, unselected                      string // row markers
	buttonOpen, buttonClose                   string
	buttonOffOpen, buttonOffClose             string
	promptFocused, promptBlurred              string
	activeOpen, activeClose                   string // around the title of the active frame
	arrowUp, arrowDown, arrowLeft, arrowRight string // key names in the key bar
}

// agentDashboardTheme holds every color and glyph the dashboard draws with.
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

func newAgentDashboardTheme(name string, term agentDashboardTerminal) (agentDashboardTheme, error) {
	if err := ValidateDashboardTheme(name); err != nil {
		return agentDashboardTheme{}, err
	}
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
	return theme, nil
}

func agentDashboardGlyphSet(unicode bool) agentDashboardGlyphs {
	glyphs := agentDashboardGlyphs{
		topLeft: "+", topRight: "+", bottomLeft: "+", bottomRight: "+",
		horizontal: "=", vertical: "|", divider: "-",
		ledLive: "[*]", ledIdle: "[ ]", ledFailed: "[!]", ledConnecting: "[~]",
		selected: ">", unselected: " ",
		buttonOpen: "[ ", buttonClose: " ]", buttonOffOpen: "( ", buttonOffClose: " )",
		promptFocused: "> ", promptBlurred: "  ",
		activeOpen: "[ ", activeClose: " ]",
		arrowUp: "^", arrowDown: "v", arrowLeft: "<", arrowRight: ">",
	}
	if unicode {
		glyphs.topLeft, glyphs.topRight, glyphs.bottomLeft, glyphs.bottomRight = "╔", "╗", "╚", "╝"
		glyphs.horizontal, glyphs.vertical, glyphs.divider = "═", "║", "─"
		glyphs.arrowUp, glyphs.arrowDown, glyphs.arrowLeft, glyphs.arrowRight = "↑", "↓", "←", "→"
	}
	return glyphs
}

// newInput returns a text input drawn with the theme.
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
