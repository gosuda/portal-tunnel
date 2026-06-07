package types

type AgentStatusResponse struct {
	ConfigPath    string              `json:"config_path,omitempty"`
	ControlAddr   string              `json:"control_addr"`
	WalletAddress string              `json:"wallet_address,omitempty"`
	Tunnels       []AgentTunnelStatus `json:"tunnels,omitempty"`
}

type AgentTunnelStatus struct {
	ID                 string             `json:"id"`
	Name               string             `json:"name,omitempty"`
	Address            string             `json:"address,omitempty"`
	State              string             `json:"state"`
	TargetAddr         string             `json:"target_addr,omitempty"`
	LastError          string             `json:"last_error,omitempty"`
	MaxActiveRelays    int                `json:"max_active_relays,omitempty"`
	Metadata           LeaseMetadata      `json:"metadata,omitempty"`
	X402Enabled        bool               `json:"x402_enabled,omitempty"`
	X402FacilitatorURL string             `json:"x402_facilitator_url,omitempty"`
	MultiHop           []string           `json:"multi_hop,omitempty"`
	Relays             []AgentRelayStatus `json:"relays,omitempty"`
}

type AgentRelayStatus struct {
	RelayURL        string `json:"relay_url"`
	PublicURL       string `json:"public_url,omitempty"`
	Version         string `json:"version,omitempty"`
	Explicit        bool   `json:"explicit,omitempty"`
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

type AgentTunnelUpdateRequest struct {
	MaxActiveRelays    *int                  `json:"max_active_relays,omitempty"`
	Metadata           *AgentMetadataRequest `json:"metadata,omitempty"`
	X402FacilitatorURL *string               `json:"x402_facilitator_url,omitempty"`
}

func (r AgentTunnelUpdateRequest) Empty() bool {
	return r.MaxActiveRelays == nil &&
		(r.Metadata == nil || r.Metadata.Empty()) &&
		r.X402FacilitatorURL == nil
}

type AgentMetadataRequest struct {
	Description *string   `json:"description,omitempty"`
	Owner       *string   `json:"owner,omitempty"`
	Thumbnail   *string   `json:"thumbnail,omitempty"`
	Tags        *[]string `json:"tags,omitempty"`
	Hide        *bool     `json:"hide,omitempty"`
}

func (r AgentMetadataRequest) Empty() bool {
	return r.Description == nil &&
		r.Owner == nil &&
		r.Thumbnail == nil &&
		r.Tags == nil &&
		r.Hide == nil
}
