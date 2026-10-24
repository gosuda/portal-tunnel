package agent

import (
	"fmt"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestAgentDashboardFit(t *testing.T) {
	tests := []struct {
		name  string
		value string
		width int
		want  string
	}{
		{name: "fits", value: "abc", width: 5, want: "abc"},
		{name: "fits exactly", value: "abcde", width: 5, want: "abcde"},
		{name: "surrounding space is trimmed", value: "  abc  ", width: 5, want: "abc"},
		{name: "truncated with marker", value: "abcdef", width: 4, want: "abc~"},
		{name: "single cell is the marker", value: "abcdef", width: 1, want: "~"},
		{name: "zero width", value: "abcdef", width: 0, want: ""},
		{name: "negative width", value: "abcdef", width: -3, want: ""},
		{name: "empty value", value: "", width: 5, want: ""},
		{name: "wide runes that fit", value: "日本語", width: 6, want: "日本語"},
		{name: "wide runes keep whole cells", value: "日本語", width: 5, want: "日本~"},
		{name: "wide rune is not split", value: "日本語", width: 4, want: "日~"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := agentDashboardFit(tt.value, tt.width); got != tt.want {
				t.Fatalf("agentDashboardFit(%q, %d) = %q, want %q", tt.value, tt.width, got, tt.want)
			}
		})
	}

	for _, value := range []string{"abcdefghij", "日本語日本語", "mixed 日本 text"} {
		for width := 1; width <= 14; width++ {
			if got := lipgloss.Width(agentDashboardFit(value, width)); got > width {
				t.Fatalf("agentDashboardFit(%q, %d) is %d cells wide", value, width, got)
			}
		}
	}
}

func TestAgentDashboardCellPadsToWidth(t *testing.T) {
	tests := []struct {
		name  string
		value string
		width int
		want  string
	}{
		{name: "ascii", value: "ab", width: 5, want: "ab   "},
		{name: "wide runes count two cells", value: "日本", width: 6, want: "日本  "},
		{name: "truncated", value: "abcdef", width: 4, want: "abc~"},
		{name: "truncation that leaves a spare cell is padded", value: "日本語", width: 4, want: "日~ "},
		{name: "empty", value: "", width: 3, want: "   "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := agentDashboardCell(tt.value, tt.width)
			if got != tt.want {
				t.Fatalf("agentDashboardCell(%q, %d) = %q, want %q", tt.value, tt.width, got, tt.want)
			}
			if lipgloss.Width(got) != tt.width {
				t.Fatalf("agentDashboardCell(%q, %d) is %d cells wide", tt.value, tt.width, lipgloss.Width(got))
			}
		})
	}
}

func TestAgentDashboardPadLine(t *testing.T) {
	if got := agentDashboardPadLine("日本", 6); got != "日本  " {
		t.Fatalf("pad = %q, want two trailing spaces", got)
	}
	if got := agentDashboardPadLine("abcdef", 3); got != "abcdef" {
		t.Fatalf("a line wider than the target must stay untouched, got %q", got)
	}
}

func TestAgentDashboardWindow(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		offset int
		width  int
		want   string
	}{
		{name: "fits", value: "abc", width: 5, want: "abc"},
		{name: "clipped on the right", value: "abcdef", width: 4, want: "abcd"},
		{name: "scrolled", value: "abcdef", offset: 2, width: 3, want: "cde"},
		{name: "scrolled to the end", value: "abcdef", offset: 4, width: 5, want: "ef"},
		{name: "scrolled past the end", value: "abcdef", offset: 9, width: 5, want: ""},
		{name: "negative offset is the start", value: "abcdef", offset: -3, width: 3, want: "abc"},
		{name: "tabs become spaces", value: "a\tb", width: 5, want: "a b"},
		{name: "empty", value: "", width: 5, want: ""},
		{name: "zero width", value: "abc", width: 0, want: ""},
		{name: "wide rune cut by the offset is dropped", value: "日本語", offset: 1, width: 4, want: "本語"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := agentDashboardWindow(tt.value, tt.offset, tt.width); got != tt.want {
				t.Fatalf("agentDashboardWindow(%q, %d, %d) = %q, want %q", tt.value, tt.offset, tt.width, got, tt.want)
			}
		})
	}
}

func TestAgentDashboardRelayWindowKeepsSelectionVisible(t *testing.T) {
	tests := []struct {
		name                 string
		selected, total, row int
		wantStart, wantEnd   int
	}{
		{name: "everything fits", selected: 2, total: 3, row: 5, wantStart: 0, wantEnd: 3},
		{name: "selection at the top", selected: 0, total: 10, row: 3, wantStart: 0, wantEnd: 3},
		{name: "selection in the middle is centered", selected: 5, total: 10, row: 3, wantStart: 4, wantEnd: 7},
		{name: "selection at the bottom", selected: 9, total: 10, row: 3, wantStart: 7, wantEnd: 10},
		{name: "selection below zero", selected: -1, total: 10, row: 3, wantStart: 0, wantEnd: 3},
		{name: "selection past the end", selected: 99, total: 10, row: 3, wantStart: 7, wantEnd: 10},
		{name: "no items", selected: 0, total: 0, row: 3, wantStart: 0, wantEnd: 0},
		{name: "no rows", selected: 0, total: 4, row: 0, wantStart: 0, wantEnd: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end := agentDashboardRelayWindow(tt.selected, tt.total, tt.row)
			if start != tt.wantStart || end != tt.wantEnd {
				t.Fatalf("agentDashboardRelayWindow(%d, %d, %d) = (%d, %d), want (%d, %d)",
					tt.selected, tt.total, tt.row, start, end, tt.wantStart, tt.wantEnd)
			}
		})
	}
}

func TestAgentDashboardColumnWidths(t *testing.T) {
	for _, width := range []int{80, 100, 132} {
		t.Run(fmt.Sprintf("width %d", width), func(t *testing.T) {
			main, gutter, sidebar := agentDashboardColumnWidths(width)
			if sidebar != agentDashboardSidebarWidth || gutter != agentDashboardSidebarGutter {
				t.Fatalf("sidebar = %d, gutter = %d, want the fixed sidebar and gutter", sidebar, gutter)
			}
			if main+gutter+sidebar != width {
				t.Fatalf("columns %d+%d+%d do not add up to %d", main, gutter, sidebar, width)
			}
		})
	}

	for width := 2; width <= 200; width++ {
		main, gutter, sidebar := agentDashboardColumnWidths(width)
		if main < 1 || sidebar < 1 || gutter < 0 || main+gutter+sidebar != width {
			t.Fatalf("width %d: columns %d+%d+%d", width, main, gutter, sidebar)
		}
	}

	if main, _, _ := agentDashboardColumnWidths(0); main < 1 {
		t.Fatalf("an unknown width must still produce a usable main column, got %d", main)
	}
}
