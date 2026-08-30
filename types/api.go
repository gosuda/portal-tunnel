package types

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// APIEnvelope wraps API responses with a consistent success/error envelope structure.
type APIEnvelope[T any] struct {
	Data  T         `json:"data,omitempty"`
	Error *APIError `json:"error,omitempty"`
	OK    bool      `json:"ok"`
}

// APIError represents an error returned in an API envelope response.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// APIRequestError represents an HTTP API request failure with status code and error details.
type APIRequestError struct {
	StatusCode int    `json:"-"`
	Code       string `json:"code,omitempty"`
	Message    string `json:"message,omitempty"`
}

func (e *APIRequestError) Error() string {
	if e == nil {
		return ""
	}
	code := strings.TrimSpace(e.Code)
	message := strings.TrimSpace(e.Message)
	if code != "" {
		return code + ": " + message
	}
	if message != "" {
		return message
	}
	if e.StatusCode > 0 {
		return fmt.Sprintf("api request failed with status %d", e.StatusCode)
	}
	return "api request failed"
}

func (e *APIRequestError) Is(target error) bool {
	other, ok := target.(*APIRequestError)
	if !ok {
		return false
	}
	if other.Code != "" && e.Code != other.Code {
		return false
	}
	if other.StatusCode != 0 && e.StatusCode != other.StatusCode {
		return false
	}
	return true
}

// RegisterRequest contains the signed challenge response for lease registration.
type RegisterRequest struct {
	ChallengeID   string `json:"challenge_id"`
	SIWEMessage   string `json:"siwe_message"`
	SIWESignature string `json:"siwe_signature"`
	ReportedIP    string `json:"reported_ip,omitempty"`
}

// RegisterChallengeRequest initiates lease registration by requesting a SIWE challenge.
type RegisterChallengeRequest struct {
	Identity      Identity      `json:"identity"`
	Metadata      LeaseMetadata `json:"metadata"`
	TTL           int           `json:"ttl,omitempty"`
	UDPEnabled    bool          `json:"udp_enabled,omitempty"`
	TCPEnabled    bool          `json:"tcp_enabled,omitempty"`
	HopToken      string        `json:"hop_token,omitempty"`
	RouteHostname string        `json:"route_hostname,omitempty"`
	HostnameHash  string        `json:"hostname_hash,omitempty"`
	ECHConfigList []byte        `json:"ech_config_list,omitempty"`
}

// RegisterChallengeResponse provides the SIWE challenge for client signature.
type RegisterChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	SIWEMessage string    `json:"siwe_message"`
}

// RegisterResponse returns the lease access token and connectivity details upon successful registration.
type RegisterResponse struct {
	Identity    Identity  `json:"identity"`
	ExpiresAt   time.Time `json:"expires_at"`
	AccessToken string    `json:"access_token"`
	SNIPort     int       `json:"sni_port,omitempty"`
	UDPAddr     string    `json:"udp_addr,omitempty"`
	UDPEnabled  bool      `json:"udp_enabled,omitempty"`
	TCPAddr     string    `json:"tcp_addr,omitempty"`
	TCPEnabled  bool      `json:"tcp_enabled,omitempty"`
}

// DiscoveryResponse provides the relay's view of the discovery protocol state.
type DiscoveryResponse struct {
	ProtocolVersion string            `json:"protocol_version"`
	GeneratedAt     time.Time         `json:"generated_at"`
	Relays          []RelayDescriptor `json:"relays"`
}

// DiscoveryAnnounceRequest submits a relay descriptor for announcement to discovery peers.
type DiscoveryAnnounceRequest struct {
	ProtocolVersion string          `json:"protocol_version"`
	Descriptor      RelayDescriptor `json:"descriptor"`
}

// DiscoveryAnnounceResponse indicates whether the relay descriptor was accepted.
type DiscoveryAnnounceResponse struct {
	ProtocolVersion string `json:"protocol_version"`
	Accepted        bool   `json:"accepted"`
}

// RenewRequest extends an active lease before expiration.
type RenewRequest struct {
	AccessToken string        `json:"access_token"`
	TTL         int           `json:"ttl,omitempty"`
	ReportedIP  string        `json:"reported_ip,omitempty"`
	Metadata    LeaseMetadata `json:"metadata"`
}

// RenewResponse returns the updated lease expiration and access token.
type RenewResponse struct {
	ExpiresAt   time.Time `json:"expires_at"`
	AccessToken string    `json:"access_token"`
}

// UnregisterRequest terminates an active lease.
type UnregisterRequest struct {
	AccessToken string `json:"access_token"`
}

// HopRoute describes a multi-hop relay route configuration.
type HopRoute struct {
	OwnerPublicKey string          `json:"owner_public_key,omitempty"`
	RelayURL       string          `json:"relay_url"`
	PublicHostname string          `json:"public_hostname,omitempty"`
	RouteHostname  string          `json:"route_hostname,omitempty"`
	HostnameHash   string          `json:"hostname_hash,omitempty"`
	ECHConfigList  []byte          `json:"ech_config_list,omitempty"`
	MatchToken     string          `json:"match_token,omitempty"`
	Metadata       LeaseMetadata   `json:"metadata"`
	ForwardRelay   RelayDescriptor `json:"forward_relay"`
	ForwardToken   string          `json:"forward_token"`
	FirstSeenAt    time.Time       `json:"first_seen_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	Signature      string          `json:"signature,omitempty"`
}

// HopRouteResponse returns connectivity details for a hop-route registration.
type HopRouteResponse struct {
	AccessToken string `json:"access_token,omitempty"`
	SNIPort     int    `json:"sni_port,omitempty"`
}

// HopRouteBytes serializes a hop route into canonical JSON bytes for signing.
func HopRouteBytes(method string, route HopRoute) ([]byte, error) {
	forwardRelay, err := CanonicalBytes(route.ForwardRelay)
	if err != nil {
		return nil, err
	}
	payload := struct {
		Purpose             string          `json:"purpose"`
		Method              string          `json:"method"`
		OwnerPublicKey      string          `json:"owner_public_key"`
		RelayURL            string          `json:"relay_url"`
		PublicHostname      string          `json:"public_hostname"`
		RouteHostname       string          `json:"route_hostname"`
		HostnameHash        string          `json:"hostname_hash"`
		ECHConfigList       string          `json:"ech_config_list"`
		MatchToken          string          `json:"match_token"`
		ForwardRelay        json.RawMessage `json:"forward_relay"`
		ForwardToken        string          `json:"forward_token"`
		FirstSeenAtUnixNano int64           `json:"first_seen_at_unix_nano"`
		ExpiresAtUnixNano   int64           `json:"expires_at_unix_nano"`
	}{
		Purpose:             "portal hop route v1",
		Method:              strings.ToUpper(strings.TrimSpace(method)),
		OwnerPublicKey:      strings.TrimSpace(route.OwnerPublicKey),
		RelayURL:            strings.TrimSpace(route.RelayURL),
		PublicHostname:      strings.TrimSpace(route.PublicHostname),
		RouteHostname:       strings.TrimSpace(route.RouteHostname),
		HostnameHash:        strings.TrimSpace(route.HostnameHash),
		ECHConfigList:       base64.StdEncoding.EncodeToString(route.ECHConfigList),
		MatchToken:          strings.TrimSpace(route.MatchToken),
		ForwardRelay:        json.RawMessage(forwardRelay),
		ForwardToken:        strings.TrimSpace(route.ForwardToken),
		FirstSeenAtUnixNano: route.FirstSeenAt.UTC().UnixNano(),
		ExpiresAtUnixNano:   route.ExpiresAt.UTC().UnixNano(),
	}
	return json.Marshal(payload)
}

// DomainResponse provides domain-level metadata including ENS and payment facilitator information.
type DomainResponse struct {
	ProtocolVersion string              `json:"protocol_version"`
	ReleaseVersion  string              `json:"release_version"`
	ENS             ENSStatus           `json:"ens"`
	X402            X402FacilitatorInfo `json:"x402"`
}

// ENSStatus reports the Ethereum Name Service configuration and verification status.
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

// PublicStateResponse lists publicly visible leases for the relay.
type PublicStateResponse struct {
	Leases             []Lease `json:"leases,omitempty"`
	LandingPageEnabled bool    `json:"landing_page_enabled"`
}

// AdminAuthLoginRequest submits the relay admin token for authentication.
type AdminAuthLoginRequest struct {
	Token string `json:"token"`
}

// AdminAuthLoginResponse returns the admin session access token.
type AdminAuthLoginResponse struct {
	AccessToken string `json:"access_token,omitempty"`
}

// AdminAuthStatusResponse indicates whether the current session is authenticated as admin.
type AdminAuthStatusResponse struct {
	Authenticated bool `json:"authenticated"`
}

// WalletAuthChallengeRequest initiates wallet-based authentication by requesting a SIWE challenge.
type WalletAuthChallengeRequest struct {
	Address string `json:"address"`
}

// WalletAuthChallengeResponse provides the SIWE challenge for wallet signature.
type WalletAuthChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	SIWEMessage string    `json:"siwe_message"`
}

// WalletAuthLoginRequest submits the signed SIWE challenge for authentication.
type WalletAuthLoginRequest struct {
	ChallengeID   string `json:"challenge_id"`
	SIWEMessage   string `json:"siwe_message"`
	SIWESignature string `json:"siwe_signature"`
}

// WalletAuthLoginResponse returns the wallet-authenticated session access token.
type WalletAuthLoginResponse struct {
	AccessToken   string `json:"access_token,omitempty"`
	WalletAddress string `json:"wallet_address,omitempty"`
}

// WalletAuthStatusResponse reports the wallet authentication status and address.
type WalletAuthStatusResponse struct {
	Authenticated bool   `json:"authenticated"`
	WalletAddress string `json:"wallet_address,omitempty"`
}

// PolicyStateResponse provides the relay's policy configuration and active leases.
type PolicyStateResponse struct {
	Policy PolicySettings `json:"policy"`
	Leases []PolicyLease  `json:"leases,omitempty"`
}

// PolicySettings contains relay policy enforcement configuration.
type PolicySettings struct {
	ApprovalMode       string             `json:"approval_mode"`
	LandingPageEnabled bool               `json:"landing_page_enabled"`
	UDP                PolicyPortSettings `json:"udp"`
	TCPPort            PolicyPortSettings `json:"tcp_port"`
}

// LeasePolicyUpdate applies policy changes to a specific lease identity.
type LeasePolicyUpdate struct {
	IdentityKey string `json:"identity_key"`
	BPS         *int64 `json:"bps,omitempty"`
	IsApproved  *bool  `json:"is_approved,omitempty"`
	IsBanned    *bool  `json:"is_banned,omitempty"`
	IsDenied    *bool  `json:"is_denied,omitempty"`
}

// PolicyPortSettings defines port-specific policy limits.
type PolicyPortSettings struct {
	Enabled   bool `json:"enabled"`
	MaxLeases int  `json:"max_leases"`
}

// IPPolicyUpdate applies policy changes to a specific client IP address.
type IPPolicyUpdate struct {
	IP       string `json:"ip"`
	IsBanned bool   `json:"is_banned"`
}
