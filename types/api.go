package types

import (
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
	Identity   Identity      `json:"identity"`
	Metadata   LeaseMetadata `json:"metadata"`
	TTL        int           `json:"ttl,omitempty"`
	UDPEnabled bool          `json:"udp_enabled,omitempty"`
	TCPEnabled bool          `json:"tcp_enabled,omitempty"`
}

type RegisterChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	SIWEMessage string    `json:"siwe_message"`
}

type RegisterResponse struct {
	Identity    Identity  `json:"identity"`
	ExpiresAt   time.Time `json:"expires_at"`
	Hostname    string    `json:"hostname"`
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

type QUICControlMessage struct {
	AccessToken string `json:"access_token"`
}

type QUICControlResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type RenewRequest struct {
	AccessToken string `json:"access_token"`
	TTL         int    `json:"ttl,omitempty"`
	ReportedIP  string `json:"reported_ip,omitempty"`
}

type RenewResponse struct {
	ExpiresAt   time.Time `json:"expires_at"`
	AccessToken string    `json:"access_token"`
}

type UnregisterRequest struct {
	AccessToken string `json:"access_token"`
}

type DomainResponse struct {
	ProtocolVersion string `json:"protocol_version"`
	ReleaseVersion  string `json:"release_version"`
}

type TunnelStatusResponse struct {
	Hostname     string `json:"hostname"`
	Registered   bool   `json:"registered"`
	ServiceAlive bool   `json:"service_alive"`
}

type AdminLoginRequest struct {
	Key string `json:"key"`
}

type AdminLoginResponse struct {
	Success bool `json:"success,omitempty"`
}

type AdminAuthStatusResponse struct {
	Authenticated bool `json:"authenticated"`
	AuthEnabled   bool `json:"auth_enabled"`
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
