package agent

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// agentDashboardRelayLead is the width of the row marker and the space after it.
const agentDashboardRelayLead = 2

type relayAttemptKey struct {
	tunnelID string
	relayURL string
}

func (m *agentDashboardModel) trackRelayAttempt(tunnelID, relayURL string) {
	key := agentDashboardRelayKey(tunnelID, relayURL)
	if key == (relayAttemptKey{}) {
		return
	}
	if m.relayAttempts == nil {
		m.relayAttempts = make(map[relayAttemptKey]bool)
	}
	m.relayAttempts[key] = false
}

func (m *agentDashboardModel) clearRelayAttempt(tunnelID, relayURL string) {
	key := agentDashboardRelayKey(tunnelID, relayURL)
	delete(m.relayAttempts, key)
	if len(m.relayAttempts) == 0 {
		m.relayAttempts = nil
	}
}

func (m *agentDashboardModel) syncRelayAttempts() {
	if len(m.relayAttempts) == 0 {
		return
	}
	seen := make(map[relayAttemptKey]struct{})
	for _, tunnel := range m.status.Tunnels {
		for _, relay := range tunnel.Relays {
			key := agentDashboardRelayKey(tunnel.ID, relay.RelayURL)
			if key == (relayAttemptKey{}) {
				continue
			}
			seen[key] = struct{}{}
			if _, ok := m.relayAttempts[key]; !ok {
				continue
			}
			if relayDashboardConnected(tunnel, relay) {
				delete(m.relayAttempts, key)
				continue
			}
			if relay.Connecting {
				m.relayAttempts[key] = false
			} else {
				m.relayAttempts[key] = true
			}
		}
	}
	for key := range m.relayAttempts {
		if _, ok := seen[key]; !ok {
			delete(m.relayAttempts, key)
		}
	}
	if len(m.relayAttempts) == 0 {
		m.relayAttempts = nil
	}
}

func (m agentDashboardModel) relayDashboardFailed(tunnel AgentTunnelStatus, relay AgentRelayStatus) bool {
	if relayDashboardConnected(tunnel, relay) || relay.Connecting {
		return false
	}
	failed, ok := m.relayAttempts[agentDashboardRelayKey(tunnel.ID, relay.RelayURL)]
	return ok && failed
}

func (m agentDashboardModel) relayDashboardConnecting(tunnel AgentTunnelStatus, relay AgentRelayStatus) bool {
	if relayDashboardConnected(tunnel, relay) || relay.Connecting {
		return relay.Connecting
	}
	failed, ok := m.relayAttempts[agentDashboardRelayKey(tunnel.ID, relay.RelayURL)]
	return ok && !failed
}

func agentDashboardRelayKey(tunnelID, relayURL string) relayAttemptKey {
	tunnelID = strings.TrimSpace(tunnelID)
	relayURL = strings.TrimSpace(relayURL)
	if tunnelID == "" || relayURL == "" {
		return relayAttemptKey{}
	}
	return relayAttemptKey{tunnelID: tunnelID, relayURL: relayURL}
}

func (m agentDashboardModel) connectSelectedRelay() (tea.Model, tea.Cmd) {
	tunnel, relay, ok := m.selectedTunnelRelay()
	if !ok {
		return m, nil
	}
	if relay.Banned || relayDashboardActive(tunnel, relay) || m.relayDashboardConnecting(tunnel, relay) {
		return m, nil
	}
	m.trackRelayAttempt(tunnel.ID, relay.RelayURL)
	return m, agentDashboardRun(func(ctx context.Context) error {
		return ConnectRelay(ctx, m.stateDir, tunnel.ID, relay.RelayURL)
	})
}

func (m agentDashboardModel) disconnectSelectedRelay() (tea.Model, tea.Cmd) {
	tunnel, relay, ok := m.selectedTunnelRelay()
	if !ok {
		return m, nil
	}
	if relay.Banned || !relayDashboardActive(tunnel, relay) {
		return m, nil
	}
	m.clearRelayAttempt(tunnel.ID, relay.RelayURL)
	return m, agentDashboardRun(func(ctx context.Context) error {
		return DisconnectRelay(ctx, m.stateDir, tunnel.ID, relay.RelayURL)
	})
}

func (m agentDashboardModel) openRelayTunnelURL(tunnelID, relayURL string) (tea.Model, tea.Cmd) {
	if tunnelID != "" {
		m.selectTunnel(tunnelID)
	}
	if relayURL != "" {
		m.selectRelay(relayURL)
	}
	_, relay, ok := m.selectedTunnelRelay()
	publicURL := relayDashboardPublicURL(cmp.Or(relay.AliasURL, relay.PublicURL))
	if !ok || publicURL == "" {
		return m, nil
	}
	return m, agentDashboardRun(func(context.Context) error {
		return openDashboardURL(publicURL)
	})
}

func (m agentDashboardModel) renderRelaysSection(width, rows int) agentDashboardView {
	th := &m.theme
	var pane agentDashboardView
	tunnel, ok := m.selectedTunnelStatus()
	if !ok {
		pane.addStyled(width, th.muted, "select a tunnel")
		return pane
	}

	relay, hasRelay := m.selectedRelayStatus()
	connectDisabled := !hasRelay || relay.Banned || relayDashboardActive(tunnel, relay) || m.relayDashboardConnecting(tunnel, relay)
	disconnectDisabled := !hasRelay || relay.Banned || !relayDashboardActive(tunnel, relay)
	pane.addButtons(th, width,
		agentDashboardButton{label: "Connect", action: agentDashboardActionConnectRelay, disabled: connectDisabled},
		agentDashboardButton{label: "Disconnect", action: agentDashboardActionDisconnectRelay, disabled: disconnectDisabled},
	)
	rowWidth := width - agentDashboardRelayLead
	header := agentDashboardRelayRow(rowWidth, "STATUS", "VERSION", "FEATURES", "TUNNEL URL")
	pane.addLine(th.strong.Render(strings.Repeat(" ", agentDashboardRelayLead) + header))

	if len(tunnel.Relays) == 0 {
		pane.addStyled(width, th.muted, "no relays")
		return pane
	}
	tableRows := len(tunnel.Relays)
	if rows > 0 {
		tableRows = max(1, rows-len(pane.lines))
	}
	selected := m.selectedRelayIndex(tunnel)
	start, end := agentDashboardRowWindow(selected, len(tunnel.Relays), tableRows)
	for i := start; i < end; i++ {
		relay := tunnel.Relays[i]
		marker := th.glyph.unselected
		if i == selected {
			marker = th.glyph.selected
		}
		line := marker + " " + agentDashboardRelayRow(rowWidth,
			m.relayDashboardMode(tunnel, relay),
			relayDashboardVersion(relay),
			relayDashboardFeatures(relay),
			relayDashboardURL(relay),
		)
		style := agentDashboardRelayStyle(th, i == selected, tunnel, relay, m.relayDashboardFailed(tunnel, relay), m.relayDashboardConnecting(tunnel, relay))
		pane.addClickRow(line, width, style, agentDashboardActionOpenTunnelURL, tunnel.ID, relay.RelayURL)
	}
	return pane
}

func agentDashboardRelayStyle(th *agentDashboardTheme, selected bool, tunnel AgentTunnelStatus, relay AgentRelayStatus, failed, connecting bool) lipgloss.Style {
	if selected {
		return th.selected
	}
	if relay.Banned || failed {
		return th.failed
	}
	if relayDashboardConnected(tunnel, relay) {
		return th.bright
	}
	if connecting {
		return th.pending
	}
	return th.muted
}

func relayDashboardActive(tunnel AgentTunnelStatus, relay AgentRelayStatus) bool {
	return relayDashboardConnected(tunnel, relay) || relay.Connecting
}

func relayDashboardConnected(tunnel AgentTunnelStatus, relay AgentRelayStatus) bool {
	return relay.PublicURL != ""
}

func relayDashboardFeatures(relay AgentRelayStatus) string {
	var features []string
	if relay.SupportsUDP {
		features = append(features, "udp")
	}
	if relay.SupportsTCP {
		features = append(features, "tcp")
	}
	if len(features) == 0 {
		return "-"
	}
	return strings.Join(features, ",")
}

func relayDashboardVersion(relay AgentRelayStatus) string {
	if version := strings.TrimSpace(relay.Version); version != "" {
		return version
	}
	return "-"
}

func relayDashboardURL(relay AgentRelayStatus) string {
	if publicURL := relayDashboardPublicURL(cmp.Or(relay.AliasURL, relay.PublicURL)); publicURL != "" {
		return publicURL
	}
	return relayDashboardRelayLabel(relay.RelayURL)
}

func relayDashboardPublicURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return rawURL
	}
	host := parsed.Hostname()
	host = cmp.Or(host, parsed.Host)
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	parsed.Host = host
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func relayDashboardRelayLabel(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "-"
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return rawURL
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return strings.TrimSpace(parsed.Host)
	}
	return host
}

func (m agentDashboardModel) relayDashboardMode(tunnel AgentTunnelStatus, relay AgentRelayStatus) string {
	var modes []string
	if relay.Banned {
		modes = append(modes, "banned")
	} else if relay.PublicURL != "" {
		modes = append(modes, "direct")
	} else if relay.Connecting || m.relayDashboardConnecting(tunnel, relay) {
		modes = append(modes, "connecting...")
	} else if m.relayDashboardFailed(tunnel, relay) {
		modes = append(modes, "failed")
	}
	if len(modes) > 0 {
		return strings.Join(modes, ",")
	}
	return "-"
}

func agentDashboardRelayRow(width int, mode, version, features, displayURL string) string {
	if width < 28 {
		modeW := lipgloss.Width(mode)
		urlW := max(1, width-modeW-1)
		return agentDashboardFit(mode+" "+agentDashboardURLCell(displayURL, urlW), width)
	}
	if width < 56 {
		modeW := 13
		return agentDashboardCell(mode, modeW) + " " +
			agentDashboardURLCell(displayURL, width-modeW-1)
	}
	modeW := 13
	versionW := 8
	featuresW := 15
	relayW := max(1, width-modeW-versionW-featuresW-3)
	return agentDashboardCell(mode, modeW) + " " +
		agentDashboardCell(version, versionW) + " " +
		agentDashboardCell(features, featuresW) + " " +
		agentDashboardURLCell(displayURL, relayW)
}

func agentDashboardURLCell(value string, width int) string {
	value = strings.TrimSpace(value)
	if value == "" || width <= 0 {
		return ""
	}
	if lipgloss.Width(value) <= width {
		return value
	}
	parsed, err := url.Parse(value)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		host := strings.TrimSpace(parsed.Hostname())
		host = cmp.Or(host, strings.TrimSpace(parsed.Host))
		if host != "" {
			return agentDashboardFit("open "+host, width)
		}
	}
	return agentDashboardFit(value, width)
}

func openDashboardURL(rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("unsupported url scheme %q", parsed.Scheme)
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return fmt.Errorf("url host is required")
	}

	var cmd *exec.Cmd
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", rawURL)
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", rawURL)
	default:
		cmd = exec.CommandContext(ctx, "xdg-open", rawURL)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		_ = cmd.Wait()
	}()
	return nil
}
