package types

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

const (
	IdentityKeySeparator       = ":"
	RelayIdentityFilename      = "identity.json"
	RelayAdminSettingsFilename = "admin_settings.json"
)

type Identity struct {
	Name       string `json:"name,omitempty"`
	Address    string `json:"address,omitempty"`
	PublicKey  string `json:"-"`
	PrivateKey string `json:"-"`
}

func (i Identity) Copy() Identity {
	return Identity{
		Name:       i.Name,
		Address:    i.Address,
		PublicKey:  i.PublicKey,
		PrivateKey: i.PrivateKey,
	}
}

type RelayIdentity struct {
	Identity
	AdminSecretKey           string `json:"-"`
	WireGuardPublicKey       string `json:"-"`
	WireGuardPrivateKey      string `json:"-"`
	EncryptedClientHelloSeed string `json:"-"`
}

func (i RelayIdentity) Copy() RelayIdentity {
	return RelayIdentity{
		Identity:                 i.Identity.Copy(),
		AdminSecretKey:           i.AdminSecretKey,
		WireGuardPublicKey:       i.WireGuardPublicKey,
		WireGuardPrivateKey:      i.WireGuardPrivateKey,
		EncryptedClientHelloSeed: i.EncryptedClientHelloSeed,
	}
}

func (i RelayIdentity) Base() Identity {
	return i.Identity.Copy()
}

func (i Identity) Key() string {
	name := strings.TrimSpace(strings.ToLower(i.Name))
	address := strings.TrimSpace(strings.ToLower(i.Address))
	if name == "" && address == "" {
		return ""
	}
	return name + IdentityKeySeparator + address
}

// DeriveToken derives a deterministic identity-scoped token from ordered
// length-prefixed token parts. The first part should identify the token family.
func (i Identity) DeriveToken(parts ...string) (string, error) {
	privateKey := strings.TrimSpace(i.PrivateKey)
	if privateKey == "" {
		return "", errors.New("identity private key is required")
	}

	mac := hmac.New(sha256.New, []byte(privateKey))
	_, _ = mac.Write([]byte("Portal identity token v1\n"))
	_, _ = mac.Write([]byte(i.Key()))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		_, _ = mac.Write([]byte("\n"))
		_, _ = mac.Write([]byte(strconv.Itoa(len(part))))
		_, _ = mac.Write([]byte(":"))
		_, _ = mac.Write([]byte(part))
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
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
	Name        string `json:"name,omitempty"`
	ExpiresAt   time.Time
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	Hostname    string
	UDPEnabled  bool
	TCPEnabled  bool
	TCPAddr     string
	Metadata    LeaseMetadata
	Ready       int
}

type AdminLease struct {
	Lease
	IdentityKey string `json:"identity_key,omitempty"`
	Address     string `json:"address,omitempty"`
	BPS         int64
	ClientIP    string
	ReportedIP  string
	IsApproved  bool
	IsBanned    bool
	IsDenied    bool
	IsIPBanned  bool
}

type RelayDescriptor struct {
	Address            string    `json:"address"`
	Version            string    `json:"version"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	APIHTTPSAddr       string    `json:"api_https_addr"`
	WireGuardPublicKey string    `json:"wireguard_public_key,omitempty"`
	WireGuardPort      int       `json:"wireguard_port,omitempty"`
	SupportsOverlay    bool      `json:"supports_overlay,omitempty"`
	SupportsUDP        bool      `json:"supports_udp,omitempty"`
	SupportsTCP        bool      `json:"supports_tcp,omitempty"`
	ActiveConnections  int64     `json:"active_connections,omitempty"`
	TCPBPS             float64   `json:"tcp_bps,omitempty"`
	Signature          string    `json:"signature,omitempty"`
}

func (desc RelayDescriptor) HasOverlayPeer() bool {
	return desc.SupportsOverlay &&
		strings.TrimSpace(desc.WireGuardPublicKey) != "" &&
		desc.WireGuardPort > 0 &&
		desc.WireGuardPort <= 65535
}

// CanonicalBytes returns the deterministic byte representation of a relay
// descriptor used for signing and signature verification.
//
// The encoding is JSON over a fixed struct schema (no maps, no omitempty),
// which guarantees field order and presence regardless of input variation.
func CanonicalBytes(desc RelayDescriptor) ([]byte, error) {
	canonical := struct {
		Address            string  `json:"address"`
		Version            string  `json:"version"`
		IssuedAtUnixNano   int64   `json:"issued_at_unix_nano"`
		ExpiresAtUnixNano  int64   `json:"expires_at_unix_nano"`
		APIHTTPSAddr       string  `json:"api_https_addr"`
		WireGuardPublicKey string  `json:"wireguard_public_key"`
		WireGuardPort      int     `json:"wireguard_port"`
		SupportsOverlay    bool    `json:"supports_overlay"`
		SupportsUDP        bool    `json:"supports_udp"`
		SupportsTCP        bool    `json:"supports_tcp"`
		ActiveConnections  int64   `json:"active_connections"`
		TCPBPS             float64 `json:"tcp_bps"`
	}{
		Address:            desc.Address,
		Version:            desc.Version,
		IssuedAtUnixNano:   desc.IssuedAt.UTC().UnixNano(),
		ExpiresAtUnixNano:  desc.ExpiresAt.UTC().UnixNano(),
		APIHTTPSAddr:       desc.APIHTTPSAddr,
		WireGuardPublicKey: desc.WireGuardPublicKey,
		WireGuardPort:      desc.WireGuardPort,
		SupportsOverlay:    desc.SupportsOverlay,
		SupportsUDP:        desc.SupportsUDP,
		SupportsTCP:        desc.SupportsTCP,
		ActiveConnections:  desc.ActiveConnections,
		TCPBPS:             desc.TCPBPS,
	}
	return json.Marshal(canonical)
}
