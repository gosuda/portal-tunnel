package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

const suiEd25519SignatureScheme byte = 0x00

// SignRelayDescriptor returns a copy of desc with its Signature field
// populated by signing the canonical bytes with authority. The signature uses
// Sui's serialized Ed25519 shape: scheme || signature || public_key.
func SignRelayDescriptor(desc types.RelayDescriptor, authority identity.Authority) (types.RelayDescriptor, error) {
	if authority == nil {
		return types.RelayDescriptor{}, errors.New("relay descriptor signing authority is required")
	}
	signingIdentity := authority.Identity()
	if desc.Address == "" {
		desc.Address = signingIdentity.Address
	}

	desc.Signature = ""
	normalized, err := identity.NormalizeRelayDescriptor(desc)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("normalize relay descriptor for signing: %w", err)
	}
	if signingIdentity.Address != "" && !strings.EqualFold(strings.TrimSpace(signingIdentity.Address), strings.TrimSpace(normalized.Address)) {
		return types.RelayDescriptor{}, errors.New("relay descriptor address does not match signing authority")
	}
	publicKeyHex := strings.ToLower(strings.TrimSpace(signingIdentity.PublicKey))
	if publicKeyHex == "" {
		publicKeyHex = strings.ToLower(strings.TrimSpace(signingIdentity.SuiPublicKey))
	}
	publicKeyHex = strings.TrimPrefix(publicKeyHex, "0x")
	if publicKeyHex == "" {
		return types.RelayDescriptor{}, errors.New("relay descriptor signing authority public key is required")
	}
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return types.RelayDescriptor{}, errors.New("relay descriptor signing authority public key must be hex encoded")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return types.RelayDescriptor{}, fmt.Errorf("relay descriptor signing authority public key must be %d bytes", ed25519.PublicKeySize)
	}
	derivedAddress, err := identity.SuiAddressFromEd25519PublicKeyHex(publicKeyHex)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("derive address from signing authority public key: %w", err)
	}
	if !strings.EqualFold(derivedAddress, normalized.Address) {
		return types.RelayDescriptor{}, errors.New("relay descriptor address does not match signing authority public key")
	}
	desc = normalized

	canonical, err := types.CanonicalBytes(desc)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("canonicalize relay descriptor: %w", err)
	}
	signatureHex, err := authority.SignEd25519(canonical)
	if err != nil {
		return types.RelayDescriptor{}, err
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("decode relay descriptor signature: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return types.RelayDescriptor{}, fmt.Errorf("relay descriptor signature must be %d bytes", ed25519.SignatureSize)
	}

	serialized := make([]byte, 0, 1+len(signature)+len(publicKey))
	serialized = append(serialized, suiEd25519SignatureScheme)
	serialized = append(serialized, signature...)
	serialized = append(serialized, publicKey...)
	desc.Signature = base64.StdEncoding.EncodeToString(serialized)
	return desc, nil
}

// VerifyRelayDescriptor checks the descriptor's signature against its
// canonical bytes and confirms that the public key embedded in the serialized
// signature corresponds to the descriptor's Sui address. It returns the
// verified normalized descriptor on success.
func VerifyRelayDescriptor(desc types.RelayDescriptor) (types.RelayDescriptor, error) {
	rawSignature := strings.TrimSpace(desc.Signature)
	if rawSignature == "" {
		return types.RelayDescriptor{}, errors.New("relay descriptor is not signed")
	}

	serialized, err := base64.StdEncoding.DecodeString(rawSignature)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("relay descriptor signature is invalid: base64 decode: %w", err)
	}
	expectedSize := 1 + ed25519.SignatureSize + ed25519.PublicKeySize
	if len(serialized) != expectedSize {
		return types.RelayDescriptor{}, fmt.Errorf("relay descriptor signature is invalid: serialized Ed25519 signature must be %d bytes", expectedSize)
	}
	if serialized[0] != suiEd25519SignatureScheme {
		return types.RelayDescriptor{}, errors.New("relay descriptor signature is invalid: unsupported signature scheme")
	}
	signature := serialized[1 : 1+ed25519.SignatureSize]
	publicKey := serialized[1+ed25519.SignatureSize:]
	publicKeyHex := hex.EncodeToString(publicKey)

	unsignedCopy := desc
	unsignedCopy.Signature = ""
	normalized, err := identity.NormalizeRelayDescriptor(unsignedCopy)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("relay descriptor signature is invalid: normalize: %w", err)
	}
	canonical, err := types.CanonicalBytes(normalized)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("canonicalize relay descriptor: %w", err)
	}

	derivedAddress, err := identity.SuiAddressFromEd25519PublicKeyHex(publicKeyHex)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("derive address from relay descriptor signature public key: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(derivedAddress), strings.TrimSpace(normalized.Address)) {
		return types.RelayDescriptor{}, errors.New("relay descriptor address does not match signature public key")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), canonical, signature) {
		return types.RelayDescriptor{}, errors.New("relay descriptor signature is invalid")
	}
	normalized.Signature = rawSignature
	return normalized, nil
}
