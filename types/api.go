package types

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type APIEnvelope[T any] struct {
	Data  T         `json:"data,omitempty"`
	Error *APIError `json:"error,omitempty"`
	OK    bool      `json:"ok"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

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

type RegisterRequest struct {
	ChallengeID   string `json:"challenge_id"`
	SIWEMessage   string `json:"siwe_message"`
	SIWESignature string `json:"siwe_signature"`
	ReportedIP    string `json:"reported_ip,omitempty"`
}

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

type RegisterChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	SIWEMessage string    `json:"siwe_message"`
}

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

type DiscoveryResponse struct {
	ProtocolVersion string            `json:"protocol_version"`
	GeneratedAt     time.Time         `json:"generated_at"`
	Relays          []RelayDescriptor `json:"relays"`
}

type DiscoveryAnnounceRequest struct {
	ProtocolVersion string          `json:"protocol_version"`
	Descriptor      RelayDescriptor `json:"descriptor"`
}

type DiscoveryAnnounceResponse struct {
	ProtocolVersion string `json:"protocol_version"`
	Accepted        bool   `json:"accepted"`
}

type RenewRequest struct {
	AccessToken string        `json:"access_token"`
	TTL         int           `json:"ttl,omitempty"`
	ReportedIP  string        `json:"reported_ip,omitempty"`
	Metadata    LeaseMetadata `json:"metadata,omitempty"`
}

type RenewResponse struct {
	ExpiresAt   time.Time `json:"expires_at"`
	AccessToken string    `json:"access_token"`
}

type UnregisterRequest struct {
	AccessToken string `json:"access_token"`
}

type HopRoute struct {
	OwnerPublicKey string          `json:"owner_public_key,omitempty"`
	RelayURL       string          `json:"relay_url"`
	PublicHostname string          `json:"public_hostname,omitempty"`
	RouteHostname  string          `json:"route_hostname,omitempty"`
	HostnameHash   string          `json:"hostname_hash,omitempty"`
	ECHConfigList  []byte          `json:"ech_config_list,omitempty"`
	MatchToken     string          `json:"match_token,omitempty"`
	Metadata       LeaseMetadata   `json:"metadata,omitempty"`
	ForwardRelay   RelayDescriptor `json:"forward_relay"`
	ForwardToken   string          `json:"forward_token"`
	FirstSeenAt    time.Time       `json:"first_seen_at,omitempty"`
	ExpiresAt      time.Time       `json:"expires_at,omitempty"`
	Signature      string          `json:"signature,omitempty"`
}

type HopRouteResponse struct {
	AccessToken string `json:"access_token,omitempty"`
	SNIPort     int    `json:"sni_port,omitempty"`
}

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

type DomainResponse struct {
	ProtocolVersion string    `json:"protocol_version"`
	ReleaseVersion  string    `json:"release_version"`
	ENS             ENSStatus `json:"ens"`
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

type TunnelStatusResponse struct {
	Hostname     string `json:"hostname"`
	Registered   bool   `json:"registered"`
	ServiceAlive bool   `json:"service_alive"`
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
	WalletAddress string `json:"wallet_address,omitempty"`
}

type WalletAuthStatusResponse struct {
	Authenticated bool   `json:"authenticated"`
	WalletAddress string `json:"wallet_address,omitempty"`
}

type AdminSnapshotResponse struct {
	ApprovalMode       string                       `json:"approval_mode"`
	LandingPageEnabled bool                         `json:"landing_page_enabled"`
	Leases             []AdminLease                 `json:"leases,omitempty"`
	UDP                AdminUDPSettingsResponse     `json:"udp"`
	TCPPort            AdminTCPPortSettingsResponse `json:"tcp_port"`
}

type AdminApprovalModeRequest struct {
	Mode string `json:"mode"`
}

type AdminApprovalModeResponse struct {
	ApprovalMode string `json:"approval_mode"`
}

type AdminLandingPageSettingsRequest struct {
	Enabled bool `json:"enabled"`
}

type AdminLandingPageSettingsResponse struct {
	Enabled bool `json:"enabled"`
}

type AdminBPSRequest struct {
	BPS int64 `json:"bps"`
}

type AdminUDPSettingsRequest struct {
	Enabled   bool `json:"enabled"`
	MaxLeases int  `json:"max_leases"`
}

type AdminUDPSettingsResponse struct {
	Enabled   bool `json:"enabled"`
	MaxLeases int  `json:"max_leases"`
}

type AdminTCPPortSettingsRequest struct {
	Enabled   bool `json:"enabled"`
	MaxLeases int  `json:"max_leases"`
}

type AdminTCPPortSettingsResponse struct {
	Enabled   bool `json:"enabled"`
	MaxLeases int  `json:"max_leases"`
}
