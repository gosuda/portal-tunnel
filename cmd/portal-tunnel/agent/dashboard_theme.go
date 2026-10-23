package agent

import (
	"cmp"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
)

// DefaultDashboardTheme is the palette used when none is chosen.
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
	color bool // NO_COLOR is not set
}

// detectAgentDashboardTerminal is the only place that reads the environment
// for terminal capabilities.
func detectAgentDashboardTerminal() agentDashboardTerminal {
	return agentDashboardTerminal{color: os.Getenv("NO_COLOR") == ""}
}

// agentDashboardTheme holds every color the dashboard draws with. Without
// color every style is empty, so nothing but the text itself reaches the terminal.
type agentDashboardTheme struct {
	color bool

	text, muted, rule, bright, strong, selected, pending, failed lipgloss.Style
}

func newAgentDashboardTheme(name string, term agentDashboardTerminal) (agentDashboardTheme, error) {
	name = cmp.Or(strings.ToLower(strings.TrimSpace(name)), DefaultDashboardTheme)
	palette, ok := agentDashboardPalettes[name]
	if !ok {
		return agentDashboardTheme{}, fmt.Errorf("--theme %q: supported values are amber and green", name)
	}

	theme := agentDashboardTheme{color: term.color}
	if !term.color {
		return theme, nil
	}
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
	if !th.color {
		// The cursor is drawn in reverse video, which a colorless theme must not emit.
		input.Cursor.SetMode(cursor.CursorHide)
	}
	return input
}
