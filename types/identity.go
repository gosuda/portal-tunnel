package types

import (
	"fmt"
	"strings"
	"time"
)

const (
	IdentityKeySeparator  = ":"
	RelayIdentityFilename = "identity.json"
	RelayPolicyFilename   = "policy.json"
	DNSSECKeyFileName     = "dnssec-csk.json"
)

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

// canonicalIdentityPart lowercases and trims one identity key part; it is the
// single home of the canonicalization rule shared by the key constructor and
// parser.
func canonicalIdentityPart(part string) string {
	return strings.TrimSpace(strings.ToLower(part))
}

// CanonicalIdentityKey returns the canonical identity key for the given name
// and address: both parts are canonicalized, the result is "" when both parts
// are empty, and "name:address" otherwise.
func CanonicalIdentityKey(name, address string) string {
	name = canonicalIdentityPart(name)
	address = canonicalIdentityPart(address)
	if name == "" && address == "" {
		return ""
	}
	return name + IdentityKeySeparator + address
}

// ParseIdentityKey parses a raw identity key in "name:address" form and
// returns its canonical form. The key is split on the first separator and both
// parts are canonicalized; parsing fails when the raw value does not contain
// exactly one separator or either part is empty after canonicalization.
func ParseIdentityKey(raw string) (string, error) {
	name, address, ok := strings.Cut(raw, IdentityKeySeparator)
	if !ok || strings.Contains(address, IdentityKeySeparator) {
		return "", fmt.Errorf("invalid identity key %q: expected \"name%saddress\" with non-empty lowercase name and address", raw, IdentityKeySeparator)
	}
	name = canonicalIdentityPart(name)
	address = canonicalIdentityPart(address)
	if name == "" || address == "" {
		return "", fmt.Errorf("invalid identity key %q: expected \"name%saddress\" with non-empty lowercase name and address", raw, IdentityKeySeparator)
	}
	return CanonicalIdentityKey(name, address), nil
}

func (i Identity) Key() string {
	return CanonicalIdentityKey(i.Name, i.Address)
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
