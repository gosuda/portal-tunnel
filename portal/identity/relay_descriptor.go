package identity

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// SignRelayDescriptor returns a copy of desc with its Signature field
// populated by signing the canonical bytes with authority. The signature is
// recoverable, so verifiers do not need to know the public key out of band;
// they recover it from the signature and check it derives the descriptor's
// Address field.
func SignRelayDescriptor(desc types.RelayDescriptor, authority Authority) (types.RelayDescriptor, error) {
	if authority == nil {
		return types.RelayDescriptor{}, errors.New("relay descriptor signing authority is required")
	}
	signingIdentity := authority.Identity()
	if desc.Address == "" {
		desc.Address = signingIdentity.Address
	}

	desc.Signature = ""
	normalized, err := NormalizeRelayDescriptor(desc)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("normalize relay descriptor for signing: %w", err)
	}
	if signingIdentity.Address != "" && !strings.EqualFold(strings.TrimSpace(signingIdentity.Address), strings.TrimSpace(normalized.Address)) {
		return types.RelayDescriptor{}, errors.New("relay descriptor address does not match signing authority")
	}
	desc = normalized

	canonical, err := types.CanonicalBytes(desc)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("canonicalize relay descriptor: %w", err)
	}
	signature, err := authority.SignSHA256Secp256k1(canonical)
	if err != nil {
		return types.RelayDescriptor{}, err
	}
	compactSignature, err := signature.Compact()
	if err != nil {
		return types.RelayDescriptor{}, err
	}

	desc.Signature = base64.StdEncoding.EncodeToString(compactSignature)
	return desc, nil
}

// VerifyRelayDescriptor checks the descriptor's signature against its
// canonical bytes and confirms that the recovered signing key corresponds to
// the descriptor's Address field. It returns the verified normalized
// descriptor on success.
func VerifyRelayDescriptor(desc types.RelayDescriptor) (types.RelayDescriptor, error) {
	rawSignature := strings.TrimSpace(desc.Signature)
	if rawSignature == "" {
		return types.RelayDescriptor{}, errors.New("relay descriptor is not signed")
	}

	signature, err := base64.StdEncoding.DecodeString(rawSignature)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("relay descriptor signature is invalid: base64 decode: %w", err)
	}

	unsignedCopy := desc
	unsignedCopy.Signature = ""
	normalized, err := NormalizeRelayDescriptor(unsignedCopy)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("relay descriptor signature is invalid: normalize: %w", err)
	}
	canonical, err := types.CanonicalBytes(normalized)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("canonicalize relay descriptor: %w", err)
	}

	publicKey, err := RecoverSHA256Secp256k1Compact(canonical, signature)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("relay descriptor signature is invalid: %w", err)
	}

	publicKeyHex := hex.EncodeToString(publicKey.SerializeCompressed())
	derivedAddress, err := AddressFromCompressedPublicKeyHex(publicKeyHex)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("derive address from recovered key: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(derivedAddress), strings.TrimSpace(normalized.Address)) {
		return types.RelayDescriptor{}, errors.New("relay descriptor address does not match recovered signing key")
	}
	normalized.Signature = rawSignature
	return normalized, nil
}

// NormalizeRelayDescriptor validates and canonicalizes a relay descriptor:
// trims fields, defaults the version, normalizes the API address and the
// signer address, and rejects inconsistent or incomplete entries.
func NormalizeRelayDescriptor(desc types.RelayDescriptor) (types.RelayDescriptor, error) {
	desc.Address = strings.TrimSpace(desc.Address)
	desc.Version = strings.TrimSpace(desc.Version)
	desc.APIHTTPSAddr = strings.TrimSpace(desc.APIHTTPSAddr)
	if desc.Version == "" {
		desc.Version = types.DiscoveryVersion
	}
	if !desc.IssuedAt.IsZero() {
		desc.IssuedAt = desc.IssuedAt.UTC()
	}
	if !desc.ExpiresAt.IsZero() {
		desc.ExpiresAt = desc.ExpiresAt.UTC()
	}

	if desc.APIHTTPSAddr != "" {
		normalized, err := utils.NormalizeRelayURL(desc.APIHTTPSAddr)
		if err != nil {
			return types.RelayDescriptor{}, fmt.Errorf("normalize api https addr: %w", err)
		}
		desc.APIHTTPSAddr = normalized
	}
	if desc.Address != "" {
		normalized, err := NormalizeEVMAddress(desc.Address)
		if err != nil {
			return types.RelayDescriptor{}, fmt.Errorf("normalize address: %w", err)
		}
		desc.Address = normalized
	}
	if desc.ActiveConnections < 0 {
		return types.RelayDescriptor{}, errors.New("active_connections is invalid")
	}
	if desc.TCPBPS < 0 || math.IsNaN(desc.TCPBPS) || math.IsInf(desc.TCPBPS, 0) {
		return types.RelayDescriptor{}, errors.New("tcp_bps is invalid")
	}

	switch {
	case desc.Address == "":
		return types.RelayDescriptor{}, errors.New("address is required")
	case desc.Version != types.DiscoveryVersion:
		return types.RelayDescriptor{}, fmt.Errorf("unsupported relay descriptor version %q", desc.Version)
	case desc.APIHTTPSAddr == "":
		return types.RelayDescriptor{}, errors.New("api_https_addr is required")
	case desc.ExpiresAt.IsZero():
		return types.RelayDescriptor{}, errors.New("expires_at is required")
	case desc.IssuedAt.After(desc.ExpiresAt):
		return types.RelayDescriptor{}, errors.New("issued_at must be before expires_at")
	}

	return desc, nil
}
