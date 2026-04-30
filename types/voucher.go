package types

import (
	"encoding/json"
	"time"
)

// ReservationVoucher is a signed claim from a relay that a client has reserved
// capacity on it until ExpiresAt.
//
// WARNING: EXPERIMENTAL — the voucher mechanism ships ahead of production
// telemetry. Do not enable in production until oversubscription data justifies
// it. Phase 4 delivers the negotiation surface only; dataplane enforcement is
// NOT wired and is deferred to a future phase.
//
// The Signature field holds a compact secp256k1 recoverable ECDSA signature
// (base64-encoded) over CanonicalBytes(). It is signed by the relay whose
// Address matches the RelayDescriptor.Address of RelayURL.
type ReservationVoucher struct {
	// ClientAddress matches ClientState.LocalAddress for the reserving client.
	ClientAddress string `json:"client_address"`
	// RelayURL matches a RelayDescriptor.APIHTTPSAddr.
	RelayURL  string    `json:"relay_url"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Signature is a compact secp256k1 recoverable signature over
	// CanonicalBytes(), base64-encoded. Signed by the relay's secp256k1 key
	// (the same key that signs RelayDescriptor).
	Signature []byte `json:"signature,omitempty"`
}

// voucherCanonical is the fixed-schema signing input for ReservationVoucher.
// Using a separate named type with explicit json tags (no omitempty, no maps)
// guarantees stable field order across Go versions.
type voucherCanonical struct {
	ClientAddress     string `json:"client_address"`
	RelayURL          string `json:"relay_url"`
	IssuedAtUnixNano  int64  `json:"issued_at_unix_nano"`
	ExpiresAtUnixNano int64  `json:"expires_at_unix_nano"`
}

// CanonicalBytes returns the deterministic signing-input bytes for the voucher.
// Used by both signing (relay) and verification (client). Excludes Signature
// itself to allow round-trip verification.
func (v ReservationVoucher) CanonicalBytes() []byte {
	canonical := voucherCanonical{
		ClientAddress:     v.ClientAddress,
		RelayURL:          v.RelayURL,
		IssuedAtUnixNano:  v.IssuedAt.UTC().UnixNano(),
		ExpiresAtUnixNano: v.ExpiresAt.UTC().UnixNano(),
	}
	b, _ := json.Marshal(canonical)
	return b
}
