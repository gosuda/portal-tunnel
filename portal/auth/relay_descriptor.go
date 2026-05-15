package auth

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// SignRelayDescriptor returns a copy of desc with its Signature field
// populated by signing the canonical bytes with authority. The signature is
// recoverable, so verifiers do not need to know the public key out of band;
// they recover it from the signature and check it derives the descriptor's
// Address field.
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
	normalized, err := identity.NormalizeRelayDescriptor(unsignedCopy)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("relay descriptor signature is invalid: normalize: %w", err)
	}
	canonical, err := types.CanonicalBytes(normalized)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("canonicalize relay descriptor: %w", err)
	}

	publicKey, err := identity.RecoverSHA256Secp256k1Compact(canonical, signature)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("relay descriptor signature is invalid: %w", err)
	}

	publicKeyHex := hex.EncodeToString(publicKey.SerializeCompressed())
	derivedAddress, err := identity.AddressFromCompressedPublicKeyHex(publicKeyHex)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("derive address from recovered key: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(derivedAddress), strings.TrimSpace(normalized.Address)) {
		return types.RelayDescriptor{}, errors.New("relay descriptor address does not match recovered signing key")
	}
	normalized.Signature = rawSignature
	return normalized, nil
}
