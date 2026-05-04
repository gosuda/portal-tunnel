package types

type AgentStatusResponse struct {
	ControlAddr string              `json:"control_addr"`
	Tunnels     []AgentTunnelStatus `json:"tunnels,omitempty"`
}

type AgentTunnelStatus struct {
	ID         string             `json:"id"`
	Name       string             `json:"name,omitempty"`
	State      string             `json:"state"`
	TargetAddr string             `json:"target_addr,omitempty"`
	LastError  string             `json:"last_error,omitempty"`
	MultiHop   []string           `json:"multi_hop,omitempty"`
	Relays     []AgentRelayStatus `json:"relays,omitempty"`
}

type AgentRelayStatus struct {
	RelayURL        string `json:"relay_url"`
	PublicURL       string `json:"public_url,omitempty"`
	Connecting      bool   `json:"connecting"`
	Bootstrap       bool   `json:"bootstrap"`
	Banned          bool   `json:"banned"`
	SupportsOverlay bool   `json:"supports_overlay"`
	SupportsUDP     bool   `json:"supports_udp"`
	SupportsTCP     bool   `json:"supports_tcp"`
}

type AgentTunnelRequest struct {
	ID         string   `json:"id"`
	Name       string   `json:"name,omitempty"`
	TargetAddr string   `json:"target_addr,omitempty"`
	RelayURLs  []string `json:"relays,omitempty"`
}

type AgentRelayRequest struct {
	RelayURL string `json:"relay_url"`
}

type AgentMultiHopRequest struct {
	Relays []string `json:"relays"`
}
