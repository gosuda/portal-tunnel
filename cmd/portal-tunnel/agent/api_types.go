package agent

import (
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// Agent control-plane DTOs. These live in the agent package because both
// their producers (the manager and control API in this package) and their
// consumers (the agent CLI and dashboard) are application surfaces; shared
// types stay agent-blind.

type AgentStatusResponse struct {
	ConfigPath    string              `json:"config_path,omitempty"`
	ControlAddr   string              `json:"control_addr"`
	WalletAddress string              `json:"wallet_address,omitempty"`
	Tunnels       []AgentTunnelStatus `json:"tunnels,omitempty"`
}

type AgentTunnelStatus struct {
	ID                  string              `json:"id"`
	Name                string              `json:"name,omitempty"`
	Address             string              `json:"address,omitempty"`
	State               string              `json:"state"`
	TargetAddr          string              `json:"target_addr,omitempty"`
	Serve               string              `json:"serve,omitempty"`
	LastError           string              `json:"last_error,omitempty"`
	Discovery           bool                `json:"discovery"`
	Overlay             bool                `json:"overlay"`
	MaxActiveRelays     int                 `json:"max_active_relays,omitempty"`
	Metadata            types.LeaseMetadata `json:"metadata"`
	Auth                string              `json:"auth,omitempty"`
	AuthIdentityHeaders bool                `json:"auth_identity_headers,omitempty"`
	gateway.X402Config
	HTTPRoutes []tunnel.HTTPRoute `json:"http_routes,omitempty"`
	Relays     []AgentRelayStatus `json:"relays,omitempty"`
}

type AgentRelayStatus struct {
	RelayURL    string `json:"relay_url"`
	PublicURL   string `json:"public_url,omitempty"`
	TCPAddr     string `json:"tcp_addr,omitempty"`
	Version     string `json:"version,omitempty"`
	Explicit    bool   `json:"explicit,omitempty"`
	Connecting  bool   `json:"connecting"`
	Bootstrap   bool   `json:"bootstrap"`
	Banned      bool   `json:"banned"`
	SupportsUDP bool   `json:"supports_udp"`
	SupportsTCP bool   `json:"supports_tcp"`
}

type AgentTunnelRequest struct {
	ID                  string             `json:"id"`
	Name                string             `json:"name,omitempty"`
	TargetAddr          string             `json:"target_addr,omitempty"`
	HTTPRoutes          []tunnel.HTTPRoute `json:"http_routes,omitempty"`
	StripRequestHeaders []string           `json:"strip_request_headers,omitempty"`
	RelayURLs           []string           `json:"relays,omitempty"`
	Discovery           *bool              `json:"discovery,omitempty"`
	Overlay             bool               `json:"overlay,omitempty"`
	MaxActiveRelays     int                `json:"max_active_relays,omitempty"`
	Auth                string             `json:"auth,omitempty"`
	AuthAllowedWallets  []string           `json:"auth_allowed_wallets,omitempty"`
	AuthIdentityHeaders bool               `json:"auth_identity_headers,omitempty"`
	gateway.X402Config
}

type AgentRelayRequest struct {
	RelayURL string `json:"relay_url"`
}

type AgentTunnelUpdateRequest struct {
	MaxActiveRelays *int                  `json:"max_active_relays,omitempty"`
	Metadata        *AgentMetadataRequest `json:"metadata,omitempty"`
}

func (r AgentTunnelUpdateRequest) Empty() bool {
	return r.MaxActiveRelays == nil &&
		(r.Metadata == nil || r.Metadata.Empty())
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
