package types

// AgentStatusResponse contains the current status of the portal-tunnel agent daemon.
type AgentStatusResponse struct {
	ConfigPath    string              `json:"config_path,omitempty"`
	ControlAddr   string              `json:"control_addr"`
	WalletAddress string              `json:"wallet_address,omitempty"`
	Tunnels       []AgentTunnelStatus `json:"tunnels,omitempty"`
}

// AgentTunnelStatus represents the runtime state of a single managed tunnel.
type AgentTunnelStatus struct {
	ID              string             `json:"id"`
	Name            string             `json:"name,omitempty"`
	Address         string             `json:"address,omitempty"`
	State           string             `json:"state"`
	TargetAddr      string             `json:"target_addr,omitempty"`
	LastError       string             `json:"last_error,omitempty"`
	Discovery       bool               `json:"discovery"`
	MaxActiveRelays int                `json:"max_active_relays,omitempty"`
	ECH             bool               `json:"ech,omitempty"`
	Metadata        LeaseMetadata      `json:"metadata"`
	MultiHop        []string           `json:"multi_hop,omitempty"`
	X402PayTo       string             `json:"x402_pay_to,omitempty"`
	X402Testnet     bool               `json:"x402_testnet,omitempty"`
	X402Network     string             `json:"x402_network,omitempty"`
	X402Asset       string             `json:"x402_asset,omitempty"`
	X402Endpoints   []string           `json:"x402_endpoints,omitempty"`
	HTTPRoutes      []AgentHTTPRoute   `json:"http_routes,omitempty"`
	Relays          []AgentRelayStatus `json:"relays,omitempty"`
}

// AgentHTTPRoute defines an HTTP routing rule for paid or public endpoints.
type AgentHTTPRoute struct {
	Prefix   string   `json:"prefix"`
	Upstream string   `json:"upstream"`
	Methods  []string `json:"methods,omitempty"`
	Amount   string   `json:"amount,omitempty"`
}

// AgentRelayStatus reports the connection state and capabilities of a relay.
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

// AgentTunnelRequest describes a tunnel configuration submitted to the agent API.
type AgentTunnelRequest struct {
	ID              string           `json:"id"`
	Name            string           `json:"name,omitempty"`
	TargetAddr      string           `json:"target_addr,omitempty"`
	HTTPRoutes      []AgentHTTPRoute `json:"http_routes,omitempty"`
	RelayURLs       []string         `json:"relays,omitempty"`
	Discovery       *bool            `json:"discovery,omitempty"`
	MaxActiveRelays int              `json:"max_active_relays,omitempty"`
	ECH             bool             `json:"ech,omitempty"`
	X402PayTo       string           `json:"x402_pay_to,omitempty"`
	X402Testnet     bool             `json:"x402_testnet,omitempty"`
	X402Network     string           `json:"x402_network,omitempty"`
	X402Asset       string           `json:"x402_asset,omitempty"`
	X402Endpoints   []string         `json:"x402_endpoints,omitempty"`
}

// AgentRelayRequest identifies a relay by URL for add/remove operations.
type AgentRelayRequest struct {
	RelayURL string `json:"relay_url"`
}

// AgentMultiHopRequest configures explicit multi-hop relay paths.
type AgentMultiHopRequest struct {
	Relays []string `json:"relays"`
}

// AgentTunnelUpdateRequest applies partial updates to a running tunnel's configuration.
type AgentTunnelUpdateRequest struct {
	MaxActiveRelays *int                  `json:"max_active_relays,omitempty"`
	Metadata        *AgentMetadataRequest `json:"metadata,omitempty"`
}

func (r AgentTunnelUpdateRequest) Empty() bool {
	return r.MaxActiveRelays == nil &&
		(r.Metadata == nil || r.Metadata.Empty())
}

// AgentMetadataRequest holds partial metadata updates for a tunnel.
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
