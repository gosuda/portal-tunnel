package agent

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	agentDashboardAddFieldName = iota
	agentDashboardAddFieldTarget
	agentDashboardAddFieldHTTPRoutes
	agentDashboardAddFieldX402PayTo
	agentDashboardAddFieldX402Testnet
	agentDashboardAddFieldX402Network
	agentDashboardAddFieldX402Asset
	agentDashboardAddFieldX402Endpoints
	agentDashboardAddFieldRelays
	agentDashboardAddFieldDiscovery
	agentDashboardAddFieldMaxRelays
	agentDashboardAddFieldCount
)

func (m *agentDashboardModel) focusAddTunnelField(field int) {
	fieldCount := agentDashboardAddFieldCount
	if field < 0 {
		field = fieldCount - 1
	}
	if field >= fieldCount {
		field = 0
	}
	m.blurSettingsInputs()
	m.addFocus = field
	m.blurAddTunnelInputs()
	if input := m.focusedAddTunnelInput(); input != nil {
		_ = input.Focus()
	}
}

func (m *agentDashboardModel) focusedAddTunnelInput() *textinput.Model {
	switch m.addFocus {
	case agentDashboardAddFieldName:
		return &m.addName
	case agentDashboardAddFieldTarget:
		return &m.addTarget
	case agentDashboardAddFieldHTTPRoutes:
		return &m.addHTTPRoutes
	case agentDashboardAddFieldX402PayTo:
		return &m.addX402PayTo
	case agentDashboardAddFieldX402Testnet:
		return &m.addX402Testnet
	case agentDashboardAddFieldX402Network:
		return &m.addX402Network
	case agentDashboardAddFieldX402Asset:
		return &m.addX402Asset
	case agentDashboardAddFieldX402Endpoints:
		return &m.addX402Endpoints
	case agentDashboardAddFieldRelays:
		return &m.addRelays
	case agentDashboardAddFieldDiscovery:
		return &m.addDiscovery
	case agentDashboardAddFieldMaxRelays:
		return &m.addMaxRelays
	default:
		return nil
	}
}

func (m *agentDashboardModel) blurAddTunnelInputs() {
	for _, input := range []*textinput.Model{
		&m.addName,
		&m.addTarget,
		&m.addHTTPRoutes,
		&m.addX402PayTo,
		&m.addX402Testnet,
		&m.addX402Network,
		&m.addX402Asset,
		&m.addX402Endpoints,
		&m.addRelays,
		&m.addDiscovery,
		&m.addMaxRelays,
	} {
		input.Blur()
	}
}

func (m *agentDashboardModel) resetAddTunnelForm() {
	for _, input := range []*textinput.Model{
		&m.addName,
		&m.addTarget,
		&m.addHTTPRoutes,
		&m.addX402PayTo,
		&m.addX402Testnet,
		&m.addX402Network,
		&m.addX402Asset,
		&m.addX402Endpoints,
		&m.addRelays,
	} {
		input.Reset()
	}
	m.addX402Testnet.SetValue("false")
	m.addDiscovery.SetValue("true")
	m.addMaxRelays.SetValue("3")
	m.addX402Testnet.CursorEnd()
	m.addDiscovery.CursorEnd()
	m.addMaxRelays.CursorEnd()
	m.addFocus = agentDashboardAddFieldName
	m.blurAddTunnelInputs()
}

func (m agentDashboardModel) addTunnelFromInput() (tea.Model, tea.Cmd) {
	req, err := m.addTunnelRequest()
	if err != nil {
		m.err = err
		return m, nil
	}

	m.err = nil
	m.addingTunnel = false
	m.resetAddTunnelForm()
	return m, agentDashboardRun(func(ctx context.Context) error {
		return AddTunnel(ctx, m.stateDir, req)
	})
}

func (m agentDashboardModel) addTunnelRequest() (AgentTunnelRequest, error) {
	name := strings.TrimSpace(m.addName.Value())
	if agentTunnelID(name) == "" {
		return AgentTunnelRequest{}, fmt.Errorf("tunnel name is required")
	}

	targetInput := strings.TrimSpace(m.addTarget.Value())
	routesInput := strings.TrimSpace(m.addHTTPRoutes.Value())
	if targetInput != "" && routesInput != "" {
		return AgentTunnelRequest{}, fmt.Errorf("target cannot be combined with routes")
	}
	if targetInput == "" && routesInput == "" {
		return AgentTunnelRequest{}, fmt.Errorf("target or routes is required")
	}

	var target string
	if targetInput != "" {
		var err error
		target, err = utils.NormalizeLoopbackTarget(targetInput)
		if err != nil || target == "" {
			return AgentTunnelRequest{}, fmt.Errorf("invalid target %q", targetInput)
		}
	}

	routes, err := agentDashboardParseAddHTTPRoutes(routesInput)
	if err != nil {
		return AgentTunnelRequest{}, err
	}
	payTo := strings.TrimSpace(m.addX402PayTo.Value())
	hasPaidRoute := false
	for _, route := range routes {
		if strings.TrimSpace(route.Amount) != "" {
			hasPaidRoute = true
			break
		}
	}
	if hasPaidRoute && payTo == "" {
		return AgentTunnelRequest{}, fmt.Errorf("paid routes require X402 Pay To")
	}
	if len(routes) == 0 && payTo != "" {
		return AgentTunnelRequest{}, fmt.Errorf("X402 Pay To requires routes")
	}
	x402TestnetRaw := strings.TrimSpace(m.addX402Testnet.Value())
	x402TestnetRaw = cmp.Or(x402TestnetRaw, "false")
	x402Testnet, err := strconv.ParseBool(x402TestnetRaw)
	if err != nil {
		return AgentTunnelRequest{}, fmt.Errorf("X402 Testnet must be true or false")
	}
	if x402Testnet && !hasPaidRoute {
		return AgentTunnelRequest{}, fmt.Errorf("X402 Testnet requires paid routes")
	}
	x402Network := strings.ToLower(strings.TrimSpace(m.addX402Network.Value()))
	x402Asset := strings.TrimSpace(m.addX402Asset.Value())
	x402Endpoints := utils.SplitCSV(m.addX402Endpoints.Value())
	if x402Network != "" && !hasPaidRoute {
		return AgentTunnelRequest{}, fmt.Errorf("X402 Network requires paid routes")
	}
	if strings.HasPrefix(x402Network, "casper:") && x402Asset == "" {
		return AgentTunnelRequest{}, fmt.Errorf("casper payments require X402 Asset")
	}

	discoveryRaw := strings.TrimSpace(m.addDiscovery.Value())
	discoveryRaw = cmp.Or(discoveryRaw, "true")
	discovery, err := strconv.ParseBool(discoveryRaw)
	if err != nil {
		return AgentTunnelRequest{}, fmt.Errorf("discovery must be true or false")
	}

	maxRelaysRaw := strings.TrimSpace(m.addMaxRelays.Value())
	maxRelaysRaw = cmp.Or(maxRelaysRaw, "3")
	maxRelays, err := strconv.Atoi(maxRelaysRaw)
	if err != nil || maxRelays <= 0 {
		return AgentTunnelRequest{}, fmt.Errorf("max relays must be a positive integer")
	}

	return AgentTunnelRequest{
		Name:            name,
		TargetAddr:      target,
		HTTPRoutes:      routes,
		RelayURLs:       utils.SplitCSV(m.addRelays.Value()),
		Discovery:       &discovery,
		MaxActiveRelays: maxRelays,
		X402Config: gateway.X402Config{
			PayTo: payTo, Testnet: x402Testnet, Network: x402Network,
			Asset: x402Asset, Endpoints: x402Endpoints,
		},
	}, nil
}

func agentDashboardParseAddHTTPRoutes(value string) ([]tunnel.HTTPRoute, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	var routes []tunnel.HTTPRoute
	seen := make(map[string]struct{})

	for rawSegment := range strings.SplitSeq(value, ";") {
		segment := strings.TrimSpace(rawSegment)
		if segment == "" {
			continue
		}
		key, rest, ok := strings.Cut(segment, "=")
		if !ok {
			return nil, fmt.Errorf("route %q must be PATH=UPSTREAM [METHOD[,METHOD...]:USDC_AMOUNT]", segment)
		}
		key = strings.TrimSpace(key)
		rest = strings.TrimSpace(rest)
		if strings.EqualFold(key, "payto") || strings.EqualFold(key, "x402_pay_to") {
			return nil, fmt.Errorf("use the X402 Pay To field instead of %q in routes", key)
		}
		if key == "" {
			return nil, fmt.Errorf("route path is required")
		}
		if !strings.HasPrefix(key, "/") {
			return nil, fmt.Errorf("route path %q must start with /", key)
		}

		parts := strings.Fields(rest)
		if len(parts) == 0 || len(parts) > 2 {
			return nil, fmt.Errorf("route %q must be PATH=UPSTREAM [METHOD[,METHOD...]:USDC_AMOUNT]", segment)
		}
		if parts[0] == "" {
			return nil, fmt.Errorf("route %q upstream is required", key)
		}

		prefix := utils.NormalizeURLPath(key)
		if _, ok := seen[prefix]; ok {
			return nil, fmt.Errorf("duplicate route path %q", prefix)
		}
		seen[prefix] = struct{}{}

		route := tunnel.HTTPRoute{
			Prefix:   prefix,
			Upstream: parts[0],
		}
		if len(parts) == 2 {
			methods, amount, err := agentDashboardParseAddRoutePayment(parts[1])
			if err != nil {
				return nil, fmt.Errorf("route %q: %w", prefix, err)
			}
			route.Methods = methods
			route.Amount = amount
		}
		routes = append(routes, route)
	}

	if len(routes) == 0 {
		return nil, fmt.Errorf("at least one http route is required")
	}
	return routes, nil
}

func agentDashboardParseAddRoutePayment(value string) ([]string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, "", fmt.Errorf("payment amount is required")
	}
	methodPart, amount, hasMethods := strings.Cut(value, ":")
	if !hasMethods {
		amount = value
		methodPart = ""
	}
	amount = strings.TrimSpace(amount)
	if amount == "" {
		return nil, "", fmt.Errorf("payment amount is required")
	}
	if !hasMethods {
		return nil, amount, nil
	}

	methods := []string(nil)
	for rawMethod := range strings.SplitSeq(methodPart, ",") {
		method := strings.ToUpper(strings.TrimSpace(rawMethod))
		if method == "" {
			return nil, "", fmt.Errorf("payment method is required")
		}
		if !slices.Contains(methods, method) {
			methods = append(methods, method)
		}
	}
	if len(methods) == 0 {
		return nil, "", fmt.Errorf("payment methods are required before ':'")
	}
	return methods, amount, nil
}

func (m agentDashboardModel) startOrAddTunnel() (tea.Model, tea.Cmd) {
	if !m.addingTunnel {
		m.addingTunnel = true
		m.resetAddTunnelForm()
		m.setActivePane(agentDashboardPaneTunnels)
		m.focusAddTunnelField(agentDashboardAddFieldName)
		return m, nil
	}
	return m.addTunnelFromInput()
}

func (m *agentDashboardModel) cancelTunnelInput() {
	m.addingTunnel = false
	m.resetAddTunnelForm()
}

func (m agentDashboardModel) renderAddTunnelForm(pane *agentDashboardView, width int) {
	rows := []struct {
		label string
		input textinput.Model
		field int
	}{
		{label: "Name", input: m.addName, field: agentDashboardAddFieldName},
		{label: "Target", input: m.addTarget, field: agentDashboardAddFieldTarget},
		{label: "Routes", input: m.addHTTPRoutes, field: agentDashboardAddFieldHTTPRoutes},
		{label: "X402 Pay To", input: m.addX402PayTo, field: agentDashboardAddFieldX402PayTo},
		{label: "X402 Testnet", input: m.addX402Testnet, field: agentDashboardAddFieldX402Testnet},
		{label: "X402 Network", input: m.addX402Network, field: agentDashboardAddFieldX402Network},
		{label: "X402 Asset", input: m.addX402Asset, field: agentDashboardAddFieldX402Asset},
		{label: "X402 Endpoints", input: m.addX402Endpoints, field: agentDashboardAddFieldX402Endpoints},
		{label: "Relays", input: m.addRelays, field: agentDashboardAddFieldRelays},
		{label: "Discovery", input: m.addDiscovery, field: agentDashboardAddFieldDiscovery},
		{label: "Max Relays", input: m.addMaxRelays, field: agentDashboardAddFieldMaxRelays},
	}
	for _, row := range rows {
		pane.addInputRow(&m.theme, width, row.label, row.input, agentDashboardActionFocusAddTunnelField, row.field, m.addFocus == row.field)
	}
}
