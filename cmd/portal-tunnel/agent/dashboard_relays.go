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

	"github.com/gosuda/portal-tunnel/v2/sdk"
)

const agentDashboardRelayLead = 2

func (m agentDashboardModel) connectSelectedRelay() (tea.Model, tea.Cmd) {
	tunnel, relay, ok := m.selectedTunnelRelay()
	if !ok {
		return m, nil
	}
	if tunnel.State != "running" || relay.State == sdk.RelayReady || relay.State == sdk.RelayConnecting {
		return m, nil
	}
	return m, agentDashboardRun(func(ctx context.Context) error {
		return ConnectRelay(ctx, m.stateDir, tunnel.ID, relay.RelayURL)
	})
}

func (m agentDashboardModel) disconnectSelectedRelay() (tea.Model, tea.Cmd) {
	tunnel, relay, ok := m.selectedTunnelRelay()
	if !ok {
		return m, nil
	}
	if tunnel.State != "running" {
		return m, nil
	}
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
	publicURL := relayDashboardPublicURL(relayDashboardEndpoint(relay))
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
	connectDisabled := !hasRelay || tunnel.State != "running" || relay.State == sdk.RelayReady || relay.State == sdk.RelayConnecting
	disconnectDisabled := !hasRelay || tunnel.State != "running"
	pane.addButtons(th, width,
		agentDashboardButton{label: "Connect", action: agentDashboardActionConnectRelay, disabled: connectDisabled},
		agentDashboardButton{label: "Disconnect", action: agentDashboardActionDisconnectRelay, disabled: disconnectDisabled},
	)
	rowWidth := width - agentDashboardRelayLead
	header := agentDashboardRelayRow(rowWidth, "STATUS", "VERSION", "TUNNEL URL")
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
		line := marker + " " + agentDashboardRelayRow(width-agentDashboardRelayLead, relayDashboardMode(relay), relayDashboardVersion(relay), relayDashboardURL(relay))
		style := agentDashboardRelayStyle(th, i == selected, relay)
		pane.addClickRow(line, width, style, agentDashboardActionOpenTunnelURL, tunnel.ID, relay.RelayURL)
	}
	return pane
}

func agentDashboardRelayStyle(th *agentDashboardTheme, selected bool, relay AgentRelayStatus) lipgloss.Style {
	if selected {
		return th.selected
	}
	if relay.State == sdk.RelayFailed {
		return th.failed
	}
	if relay.State == sdk.RelayReady {
		return th.bright
	}
	if relay.State == sdk.RelayConnecting {
		return th.pending
	}
	return th.muted
}

func relayDashboardVersion(relay AgentRelayStatus) string {
	if version := strings.TrimSpace(relay.Version); version != "" {
		return version
	}
	return "-"
}

func relayDashboardURL(relay AgentRelayStatus) string {
	if publicURL := relayDashboardPublicURL(relayDashboardEndpoint(relay)); publicURL != "" {
		return publicURL
	}
	return relayDashboardRelayLabel(relay.RelayURL)
}

func relayDashboardEndpoint(relay AgentRelayStatus) string {
	if relay.State == sdk.RelayReady {
		return cmp.Or(relay.AliasURL, relay.PublicURL, relay.LegacyURL)
	}
	return cmp.Or(relay.AliasURL, relay.PublicURL)
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

func relayDashboardMode(relay AgentRelayStatus) string {
	switch {
	case relay.Approval == sdk.RelayApprovalPending:
		return "waiting"
	case relay.Approval == sdk.RelayApprovalRefused:
		return "refused"
	case relay.State == sdk.RelayFailed:
		return "failed"
	case relay.State == sdk.RelayReady && relay.PublicURL == "" && relay.CertificateError != "":
		return "legacy TLS"
	case relay.State == sdk.RelayReady:
		return "direct"
	case relay.State == sdk.RelayConnecting:
		return "connecting..."
	default:
		return "-"
	}
}

func agentDashboardRelayRow(width int, mode, version, displayURL string) string {
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
	relayW := max(1, width-modeW-versionW-2)
	return agentDashboardCell(mode, modeW) + " " +
		agentDashboardCell(version, versionW) + " " +
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return startDashboardURLProcess(ctx, rawURL)
}

func startDashboardURLProcess(ctx context.Context, rawURL string) error {
	var cmd *exec.Cmd
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
