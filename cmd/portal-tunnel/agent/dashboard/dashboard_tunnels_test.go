package dashboard

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestAgentDashboardTunnelRowFitsAndKeepsName(t *testing.T) {
	for width := 3; width <= 140; width++ {
		row := agentDashboardTunnelRow(width, "running", "127.0.0.1:3000", "web")
		if got := lipgloss.Width(row); got > width {
			t.Fatalf("width %d: row %q is %d cells wide", width, row, got)
		}
		if fields := strings.Fields(row); fields[len(fields)-1] != "web" {
			t.Fatalf("width %d: row %q must end with the name", width, row)
		}
	}
}

func TestAgentDashboardTunnelRowTruncatesLongNames(t *testing.T) {
	name := "a-tunnel-name-that-is-much-longer-than-the-name-column-can-hold"
	row := agentDashboardTunnelRow(60, "running", "127.0.0.1:3000", name)
	if lipgloss.Width(row) > 60 {
		t.Fatalf("row %q is %d cells wide", row, lipgloss.Width(row))
	}
	if !strings.HasSuffix(row, "~") {
		t.Fatalf("row %q should end with the truncation marker", row)
	}
}

func TestAgentDashboardTunnelLookTellsStatesApartWithoutColor(t *testing.T) {
	theme := newAgentDashboardTheme("amber", agentDashboardTerminal{})
	leds := make(map[string]string)
	for _, state := range []string{"running", "starting", "error", "stopped"} {
		led, _ := agentDashboardTunnelLook(&theme, state)
		if other, ok := leds[led]; ok {
			t.Fatalf("states %q and %q share the LED %q", other, state, led)
		}
		leds[led] = state
	}
	if led, _ := agentDashboardTunnelLook(&theme, "unknown"); leds[led] != "stopped" {
		t.Fatalf("an unknown state must look idle, got LED %q", led)
	}
}
