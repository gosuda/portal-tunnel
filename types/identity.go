package types

import (
	"strings"
	"time"
)

const (
	IdentityKeySeparator  = ":"
	RelayIdentityFilename = "identity.json"
	RelayPolicyFilename   = "policy.json"
	DNSSECKeyFileName     = "dnssec-csk.json"
	SIWEVersion            = "1"
	SIWEChainID            = 1
)

type SIWEMessage struct {
	Domain     string
	Address    string
	URI        string
	Statement  string
	Nonce      string
	RequestID  string
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

type Identity struct {
	Name           string `json:"name,omitempty"`
	Address        string `json:"address,omitempty"`
	PublicKey      string `json:"-"`
	PrivateKey     string `json:"-"`
	Mnemonic       string `json:"-"`
	DerivationPath string `json:"-"`
	TokenSecret    string `json:"-"`
}

func (i Identity) Copy() Identity {
	return Identity{
		Name:           i.Name,
		Address:        i.Address,
		PublicKey:      i.PublicKey,
		PrivateKey:     i.PrivateKey,
		Mnemonic:       i.Mnemonic,
		DerivationPath: i.DerivationPath,
		TokenSecret:    i.TokenSecret,
	}
}

func (i Identity) Key() string {
	name := strings.TrimSpace(strings.ToLower(i.Name))
	address := strings.TrimSpace(strings.ToLower(i.Address))
	if name == "" && address == "" {
		return ""
	}
	return name + IdentityKeySeparator + address
}

type LeaseMetadata struct {
	Description string   `json:"description,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	Thumbnail   string   `json:"thumbnail,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Hide        bool     `json:"hide,omitempty"`
}

func (m LeaseMetadata) Copy() LeaseMetadata {
	return LeaseMetadata{
		Description: m.Description,
		Owner:       m.Owner,
		Thumbnail:   m.Thumbnail,
		Tags:        append([]string(nil), m.Tags...),
		Hide:        m.Hide,
	}
}

type Lease struct {
	Name        string        `json:"name,omitempty"`
	ExpiresAt   time.Time     `json:"expires_at"`
	FirstSeenAt time.Time     `json:"first_seen_at"`
	LastSeenAt  time.Time     `json:"last_seen_at"`
	Hostname    string        `json:"hostname"`
	UDPEnabled  bool          `json:"udp_enabled,omitempty"`
	UDPAddr     string        `json:"udp_addr,omitempty"`
	TCPEnabled  bool          `json:"tcp_enabled,omitempty"`
	TCPAddr     string        `json:"tcp_addr,omitempty"`
	Metadata    LeaseMetadata `json:"metadata"`
	Ready       int           `json:"ready"`
}

type PolicyLease struct {
	Lease
	IdentityKey string `json:"identity_key,omitempty"`
	Address     string `json:"address,omitempty"`
	BPS         int64  `json:"bps"`
	ClientIP    string `json:"client_ip"`
	ReportedIP  string `json:"reported_ip,omitempty"`
	IsApproved  bool   `json:"is_approved"`
	IsBanned    bool   `json:"is_banned"`
	IsDenied    bool   `json:"is_denied"`
	IsIPBanned  bool   `json:"is_ip_banned"`
}

type RelayDescriptor struct {
	Address           string    `json:"address"`
	Version           string    `json:"version"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	APIHTTPSAddr      string    `json:"api_https_addr"`
	IVNPDestination   string    `json:"ivnp_destination,omitempty"`
	SupportsUDP       bool      `json:"supports_udp,omitempty"`
	SupportsTCP       bool      `json:"supports_tcp,omitempty"`
	ActiveConnections int64     `json:"active_connections,omitempty"`
	TCPBPS            float64   `json:"tcp_bps,omitempty"`
	Signature         string    `json:"signature,omitempty"`
}
