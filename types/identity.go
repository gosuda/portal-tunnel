package types

import (
	"fmt"
	"strings"
	"time"
)

// RegisterLeaseSIWEStatement is the canonical purpose signed for Portal lease registration.
const RegisterLeaseSIWEStatement = "Register a portal lease"

const (
	IdentityKeySeparator  = ":"
	RelayIdentityFilename = "identity.json"
	RelayPolicyFilename   = "policy.json"
	DNSSECKeyFileName     = "dnssec-csk.json"
)

// Canonical lease labels keep the full 40-character address as their suffix
// within the 63-octet DNS label limit. A service name of up to
// CanonicalLeaseNameMaxLength octets is embedded as is ("<name>-<address>");
// a longer one is replaced by the first CanonicalLeaseNameHashLength
// characters of a domain-separated SHA-256 of the name
// ("<hash>--<address>"). A normalized name never ends with a hyphen, so the
// two forms cannot produce the same label.
const (
	CanonicalLeaseNameMaxLength  = 22
	CanonicalLeaseNameHashLength = 21
	CanonicalLeaseNameHashDomain = "portal-canonical-name-v1"
)

// Identity-bound TLS channel binding runs on a native client's own TLS
// connection to a canonical hostname, before any application data, between a
// client and a tunnel that may run different versions. The client sends the
// request magic and a fresh nonce. The tunnel answers with its exporter under
// TLSChannelBindingExporterLabel and a compact secp256k1 signature, made with
// the identity embedded in the hostname, over
// TLSChannelBindingDomain || 0 || hostname || 0 || nonce || exporter.
//
// A stream whose first five bytes are the request magic is taken for a binding
// request, so an application that opens with exactly these bytes would be
// answered as one. TLS and HTTP never start that way, and the magic is not a
// secret.
const (
	TLSChannelBindingExporterLabel = "EXPORTER-Portal-TLS-Channel-Binding-v1"
	TLSChannelBindingDomain        = "portal-tls-channel-binding-v1"
	TLSChannelBindingRequestMagic  = "PTCB\x01"
	TLSChannelBindingNonceSize     = 32
	TLSChannelBindingExporterSize  = 32
	TLSChannelBindingSignatureSize = 65
	TLSChannelBindingRequestSize   = len(TLSChannelBindingRequestMagic) + TLSChannelBindingNonceSize
	TLSChannelBindingAnswerSize    = TLSChannelBindingExporterSize + TLSChannelBindingSignatureSize
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

// ServiceIdentityKey is the comparable in-process identity of a service.
// String serialization belongs at API, persistence, token, and log boundaries.
type ServiceIdentityKey struct {
	name    string
	address string
}

func NewServiceIdentityKey(name, address string) ServiceIdentityKey {
	return ServiceIdentityKey{
		name:    strings.TrimSpace(strings.ToLower(name)),
		address: strings.TrimSpace(strings.ToLower(address)),
	}
}

func ParseServiceIdentityKey(raw string) (ServiceIdentityKey, error) {
	name, address, ok := strings.Cut(raw, IdentityKeySeparator)
	if !ok || strings.Contains(address, IdentityKeySeparator) {
		return ServiceIdentityKey{}, fmt.Errorf("invalid identity key %q: expected \"name%saddress\" or \"%saddress\" with non-empty lowercase address", raw, IdentityKeySeparator, IdentityKeySeparator)
	}
	key := NewServiceIdentityKey(name, address)
	if !key.Valid() {
		return ServiceIdentityKey{}, fmt.Errorf("invalid identity key %q: expected \"name%saddress\" or \"%saddress\" with non-empty lowercase address", raw, IdentityKeySeparator, IdentityKeySeparator)
	}
	return key, nil
}

func (k ServiceIdentityKey) Valid() bool {
	return k.address != ""
}

func (k ServiceIdentityKey) String() string {
	if k.name == "" && k.address == "" {
		return ""
	}
	return k.name + IdentityKeySeparator + k.address
}

// CanonicalIdentityKey returns the canonical identity key for the given name
// and address: both parts are canonicalized, the result is "" when both parts
// are empty, and "name:address" (or ":address" when name is empty) otherwise.
func CanonicalIdentityKey(name, address string) string {
	return NewServiceIdentityKey(name, address).String()
}

// ParseIdentityKey parses a raw identity key in "name:address" or ":address"
// form and returns its canonical form. The key is split on the first separator
// and both parts are canonicalized; parsing fails when the raw value does not
// contain exactly one separator or the address is empty after canonicalization.
func ParseIdentityKey(raw string) (string, error) {
	key, err := ParseServiceIdentityKey(raw)
	if err != nil {
		return "", err
	}
	return key.String(), nil
}

func (i Identity) ServiceKey() ServiceIdentityKey {
	return NewServiceIdentityKey(i.Name, i.Address)
}

func (i Identity) Key() string {
	return i.ServiceKey().String()
}

type LeaseMetadata struct {
	Description string   `json:"description,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	Thumbnail   string   `json:"thumbnail,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Hide        bool     `json:"hide,omitempty"`
}

// Validate bounds metadata retained by the relay, including unauthenticated challenges.
func (m LeaseMetadata) Validate() error {
	if len(m.Description) > 4096 || len(m.Owner) > 256 || len(m.Thumbnail) > 2048 || len(m.Tags) > 32 {
		return fmt.Errorf("lease metadata exceeds limits")
	}
	total := len(m.Description) + len(m.Owner) + len(m.Thumbnail)
	for _, tag := range m.Tags {
		if len(tag) > 128 {
			return fmt.Errorf("lease metadata tag exceeds limit")
		}
		total += len(tag)
	}
	if total > 8192 {
		return fmt.Errorf("lease metadata exceeds aggregate limit")
	}
	return nil
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
	Name              string        `json:"name,omitempty"`
	Address           string        `json:"address"`
	ExpiresAt         time.Time     `json:"expires_at"`
	FirstSeenAt       time.Time     `json:"first_seen_at"`
	LastSeenAt        time.Time     `json:"last_seen_at"`
	Hostname          string        `json:"hostname"`
	CanonicalHostname string        `json:"canonical_hostname"`
	UDPEnabled        bool          `json:"udp_enabled,omitempty"`
	UDPAddr           string        `json:"udp_addr,omitempty"`
	TCPEnabled        bool          `json:"tcp_enabled,omitempty"`
	TCPAddr           string        `json:"tcp_addr,omitempty"`
	Metadata          LeaseMetadata `json:"metadata"`
	Ready             int           `json:"ready"`
}

type PolicyLease struct {
	Lease
	IdentityKey string `json:"identity_key,omitempty"`
	BPS         int64  `json:"bps"`
	ClientIP    string `json:"client_ip"`
	ReportedIP  string `json:"reported_ip,omitempty"`
	IsApproved  bool   `json:"is_approved"`
	IsBanned    bool   `json:"is_banned"`
	IsDenied    bool   `json:"is_denied"`
}

// Relay descriptor addresses must stay small enough to share the discovery budget.
const (
	MaxRelayDescriptorURLBytes         = 2048
	MaxRelayDescriptorDestinationBytes = 60 // 52-character hash plus .b32.i2p.
	MaxRelayDescriptorSignatureBytes   = 88 // Base64-encoded 65-byte compact signature.
)

// RelayDescriptor is a signed statement. For the same Address and APIHTTPSAddr,
// changing signed contents requires a newer IssuedAt; identical retransmissions
// remain valid until ExpiresAt.
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
