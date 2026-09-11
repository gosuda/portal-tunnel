package protocol

import (
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

type RegisterRequest struct {
	ChallengeID   string `json:"challenge_id"`
	SIWEMessage   string `json:"siwe_message"`
	SIWESignature string `json:"siwe_signature"`
	ReportedIP    string `json:"reported_ip,omitempty"`
}

type RegisterChallengeRequest struct {
	Identity      types.Identity      `json:"identity"`
	Metadata      types.LeaseMetadata `json:"metadata"`
	Overlay       bool                `json:"overlay,omitempty"`
	TTL           int                 `json:"ttl,omitempty"`
	UDPEnabled    bool                `json:"udp_enabled,omitempty"`
	TCPEnabled    bool                `json:"tcp_enabled,omitempty"`
	RouteHostname string              `json:"route_hostname,omitempty"`
	HostnameHash  string              `json:"hostname_hash,omitempty"`
	ECHConfigList []byte              `json:"ech_config_list,omitempty"`
}

type RegisterChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	SIWEMessage string    `json:"siwe_message"`
}

// ReverseEndpoint authorizes one class of operation: opening reverse streams.
// Capability is opaque to SDK callers and cannot mutate the owning lease.
type ReverseEndpoint struct {
	URL        string    `json:"url"`
	Capability string    `json:"capability"`
	ExpiresAt  time.Time `json:"expires_at"`
	Overlay    bool      `json:"overlay,omitempty"`
}

type RegisterResponse struct {
	Identity        types.Identity  `json:"identity"`
	ExpiresAt       time.Time       `json:"expires_at"`
	AccessToken     string          `json:"access_token"`
	ReverseEndpoint ReverseEndpoint `json:"reverse_endpoint"`
	SNIPort         int             `json:"sni_port,omitempty"`
	UDPAddr         string          `json:"udp_addr,omitempty"`
	UDPEnabled      bool            `json:"udp_enabled,omitempty"`
	TCPAddr         string          `json:"tcp_addr,omitempty"`
	TCPEnabled      bool            `json:"tcp_enabled,omitempty"`
}

type DiscoveryResponse struct {
	ProtocolVersion string                  `json:"protocol_version"`
	GeneratedAt     time.Time               `json:"generated_at"`
	Relays          []types.RelayDescriptor `json:"relays"`
}

type DiscoveryAnnounceRequest struct {
	ProtocolVersion string                `json:"protocol_version"`
	Descriptor      types.RelayDescriptor `json:"descriptor"`
}

type DiscoveryAnnounceResponse struct {
	ProtocolVersion string `json:"protocol_version"`
	Accepted        bool   `json:"accepted"`
}

type RenewRequest struct {
	AccessToken string              `json:"access_token"`
	TTL         int                 `json:"ttl,omitempty"`
	ReportedIP  string              `json:"reported_ip,omitempty"`
	Metadata    types.LeaseMetadata `json:"metadata"`
}

type RenewResponse struct {
	ExpiresAt       time.Time       `json:"expires_at"`
	AccessToken     string          `json:"access_token"`
	ReverseEndpoint ReverseEndpoint `json:"reverse_endpoint"`
}

type ReverseEndpointRequest struct {
	AccessToken string `json:"access_token"`
	FailedURL   string `json:"failed_url,omitempty"`
}

type UnregisterRequest struct {
	AccessToken string `json:"access_token"`
}

type DomainResponse struct {
	ProtocolVersion string                    `json:"protocol_version"`
	ReleaseVersion  string                    `json:"release_version"`
	ENS             ENSStatus                 `json:"ens"`
	X402            types.X402FacilitatorInfo `json:"x402"`
}

type ENSStatus struct {
	Enabled     bool   `json:"enabled"`
	Verified    bool   `json:"verified"`
	Provider    string `json:"provider,omitempty"`
	Address     string `json:"address,omitempty"`
	DNSSECState string `json:"dnssec_state,omitempty"`
	DSRecord    string `json:"ds_record,omitempty"`
	Message     string `json:"message,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

type PublicStateResponse struct {
	Leases             []types.Lease `json:"leases,omitempty"`
	LandingPageEnabled bool          `json:"landing_page_enabled"`
}

type AdminAuthLoginRequest struct {
	Token string `json:"token"`
}

type AdminAuthLoginResponse struct {
	AccessToken string `json:"access_token,omitempty"`
}

type AdminAuthStatusResponse struct {
	Authenticated bool `json:"authenticated"`
}

type WalletAuthChallengeRequest struct {
	Address string `json:"address"`
}

type WalletAuthChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	SIWEMessage string    `json:"siwe_message"`
}

type WalletAuthLoginRequest struct {
	ChallengeID   string `json:"challenge_id"`
	SIWEMessage   string `json:"siwe_message"`
	SIWESignature string `json:"siwe_signature"`
}

type WalletAuthLoginResponse struct {
	AccessToken   string `json:"access_token,omitempty"`
	WalletAddress string `json:"wallet_address,omitempty"`
}

type WalletAuthStatusResponse struct {
	Authenticated bool   `json:"authenticated"`
	WalletAddress string `json:"wallet_address,omitempty"`
}

type PolicyStateResponse struct {
	Policy PolicySettings      `json:"policy"`
	Leases []types.PolicyLease `json:"leases,omitempty"`
}

type PolicySettings struct {
	ApprovalMode       string             `json:"approval_mode"`
	LandingPageEnabled bool               `json:"landing_page_enabled"`
	UDP                PolicyPortSettings `json:"udp"`
	TCPPort            PolicyPortSettings `json:"tcp_port"`
}

type LeasePolicyUpdate struct {
	IdentityKey string `json:"identity_key"`
	BPS         *int64 `json:"bps,omitempty"`
	IsApproved  *bool  `json:"is_approved,omitempty"`
	IsBanned    *bool  `json:"is_banned,omitempty"`
	IsDenied    *bool  `json:"is_denied,omitempty"`
}

type PolicyPortSettings struct {
	Enabled   bool `json:"enabled"`
	MaxLeases int  `json:"max_leases"`
}

type IPPolicyUpdate struct {
	IP       string `json:"ip"`
	IsBanned bool   `json:"is_banned"`
}
