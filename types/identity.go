package types

import (
	"encoding/json"
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
	AdminSecretKey      string `json:"-"`
	WireGuardPublicKey  string `json:"-"`
	WireGuardPrivateKey string `json:"-"`
}

func (i RelayIdentity) Copy() RelayIdentity {
	return RelayIdentity{
		Identity:            i.Identity.Copy(),
		AdminSecretKey:      i.AdminSecretKey,
		WireGuardPublicKey:  i.WireGuardPublicKey,
		WireGuardPrivateKey: i.WireGuardPrivateKey,
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
	Identity

	RelayID             string    `json:"relay_id,omitempty"`
	OwnerAddress        string    `json:"owner_address,omitempty"`
	Version             uint32    `json:"version"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	APIHTTPSAddr        string    `json:"api_https_addr"`
	IngressTLSAddr      string    `json:"ingress_tls_addr,omitempty"`
	WireGuardPublicKey  string    `json:"wireguard_public_key,omitempty"`
	WireGuardEndpoint   string    `json:"wireguard_endpoint,omitempty"`
	OverlayIPv4         string    `json:"overlay_ipv4,omitempty"`
	OverlayCIDRs        []string  `json:"overlay_cidrs,omitempty"`
	Discovery           bool      `json:"discovery,omitempty"`
	SupportsUDP         bool      `json:"supports_udp,omitempty"`
	SupportsTCP         bool      `json:"supports_tcp,omitempty"`
	SupportsOverlayPeer bool      `json:"supports_overlay_peer,omitempty"`
	Load                float64   `json:"load,omitempty"`
	LoadScore           float64   `json:"load_score,omitempty"`
	LastUpdated         int64     `json:"last_updated,omitempty"`
	Signature           string    `json:"signature,omitempty"`
}

// canonicalRelayDescriptor mirrors the subset of RelayDescriptor fields that
// participate in the cryptographic signature. Only fields that uniquely
// identify the relay or affect routing are signed; mutable telemetry (Load,
// LoadScore, LastUpdated) and the Signature itself are deliberately excluded
// so that observers may update telemetry without invalidating the signature.
//
// All slice fields are normalized to non-nil to keep encoding deterministic
// (json.Marshal encodes nil slices as `null` and empty slices as `[]`). Time
// fields are encoded as Unix nanoseconds to avoid any RFC3339 round-trip
// ambiguity.
type canonicalRelayDescriptor struct {
	Name                string   `json:"name"`
	Address             string   `json:"address"`
	RelayID             string   `json:"relay_id"`
	OwnerAddress        string   `json:"owner_address"`
	Version             uint32   `json:"version"`
	IssuedAtUnixNano    int64    `json:"issued_at_unix_nano"`
	ExpiresAtUnixNano   int64    `json:"expires_at_unix_nano"`
	APIHTTPSAddr        string   `json:"api_https_addr"`
	IngressTLSAddr      string   `json:"ingress_tls_addr"`
	WireGuardPublicKey  string   `json:"wireguard_public_key"`
	WireGuardEndpoint   string   `json:"wireguard_endpoint"`
	OverlayIPv4         string   `json:"overlay_ipv4"`
	OverlayCIDRs        []string `json:"overlay_cidrs"`
	Discovery           bool     `json:"discovery"`
	SupportsUDP         bool     `json:"supports_udp"`
	SupportsTCP         bool     `json:"supports_tcp"`
	SupportsOverlayPeer bool     `json:"supports_overlay_peer"`
}

// CanonicalBytes returns the deterministic byte representation of a relay
// descriptor used for signing and signature verification. Two descriptors
// that differ only in mutable telemetry fields produce identical bytes.
//
// The encoding is JSON over a fixed struct schema (no maps, no omitempty),
// which guarantees field order and presence regardless of input variation.
func CanonicalBytes(desc RelayDescriptor) ([]byte, error) {
	overlayCIDRs := desc.OverlayCIDRs
	if overlayCIDRs == nil {
		overlayCIDRs = []string{}
	}
	canonical := canonicalRelayDescriptor{
		Name:                desc.Name,
		Address:             desc.Address,
		RelayID:             desc.RelayID,
		OwnerAddress:        desc.OwnerAddress,
		Version:             desc.Version,
		IssuedAtUnixNano:    desc.IssuedAt.UTC().UnixNano(),
		ExpiresAtUnixNano:   desc.ExpiresAt.UTC().UnixNano(),
		APIHTTPSAddr:        desc.APIHTTPSAddr,
		IngressTLSAddr:      desc.IngressTLSAddr,
		WireGuardPublicKey:  desc.WireGuardPublicKey,
		WireGuardEndpoint:   desc.WireGuardEndpoint,
		OverlayIPv4:         desc.OverlayIPv4,
		OverlayCIDRs:        overlayCIDRs,
		Discovery:           desc.Discovery,
		SupportsUDP:         desc.SupportsUDP,
		SupportsTCP:         desc.SupportsTCP,
		SupportsOverlayPeer: desc.SupportsOverlayPeer,
	}
	return json.Marshal(canonical)
}
