package auth

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// SignRelayDescriptor returns a copy of desc with its Signature field
// populated by signing the canonical bytes with the supplied secp256k1
// private key (hex encoded). The signature is recoverable, so verifiers do
// not need to know the public key out of band; they recover it from the
// signature and check it derives the descriptor's Address field.
//
// Mutable telemetry fields (Load, LoadScore, LastUpdated) are NOT covered by
// the signature, so callers may update them after signing without
// invalidating the signature.
func SignRelayDescriptor(desc types.RelayDescriptor, privateKeyHex string) (types.RelayDescriptor, error) {
	privateKey, _, err := utils.ParseSecp256k1PrivateKeyHex(privateKeyHex, true)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("relay descriptor signing key: %w", err)
	}

	desc.Signature = ""
	normalized, err := utils.NormalizeDescriptor(desc)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("normalize relay descriptor for signing: %w", err)
	}
	if strings.TrimSpace(normalized.Address) == "" {
		return types.RelayDescriptor{}, errors.New("relay descriptor address is required for signature verification")
	}
	desc = normalized

	canonical, err := types.CanonicalBytes(desc)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("canonicalize relay descriptor: %w", err)
	}
	signature, err := utils.SignSHA256Secp256k1Compact(canonical, privateKey, true)
	if err != nil {
		return types.RelayDescriptor{}, err
	}

	desc.Signature = base64.StdEncoding.EncodeToString(signature)
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
	normalized, err := utils.NormalizeDescriptor(unsignedCopy)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("relay descriptor signature is invalid: normalize: %w", err)
	}
	if strings.TrimSpace(normalized.Address) == "" {
		return types.RelayDescriptor{}, errors.New("relay descriptor address is required for signature verification")
	}
	canonical, err := types.CanonicalBytes(normalized)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("canonicalize relay descriptor: %w", err)
	}

	publicKey, err := utils.RecoverSHA256Secp256k1Compact(canonical, signature)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("relay descriptor signature is invalid: %w", err)
	}

	publicKeyHex := hex.EncodeToString(publicKey.SerializeCompressed())
	derivedAddress, err := utils.AddressFromCompressedPublicKeyHex(publicKeyHex)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("derive address from recovered key: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(derivedAddress), strings.TrimSpace(normalized.Address)) {
		return types.RelayDescriptor{}, errors.New("relay descriptor address does not match recovered signing key")
	}
	normalized.Signature = rawSignature
	return normalized, nil
}
