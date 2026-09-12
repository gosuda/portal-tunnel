package identity

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// NormalizeIdentity returns the canonical comparison form of a wire identity:
// the name as a DNS label and the address in EVM checksum form. It does not
// derive or verify key material.
func NormalizeIdentity(identity types.Identity) (types.Identity, error) {
	normalized := identity.Copy()

	name, err := utils.NormalizeDNSLabel(identity.Name)
	if err != nil {
		return types.Identity{}, err
	}
	address, err := NormalizeEVMAddress(identity.Address)
	if err != nil {
		return types.Identity{}, err
	}

	normalized.Name = name
	normalized.Address = address
	return normalized, nil
}

// resolve returns the canonical Portal identity for id: it trims the fields,
// derives the private key from a mnemonic when provided, requires key
// material, derives the public key and address from the private key exactly
// once, verifies explicitly supplied address and public key against the
// derived values exactly once, normalizes the name as a DNS label, and fills
// the token secret when missing. It never generates key material; use
// Generate for that. Valid identities leave the package only through Parse
// and Generate; callers trust them from there on.
func resolve(id types.Identity) (types.Identity, error) {
	resolved, err := resolveKeyMaterial(id)
	if err != nil {
		return types.Identity{}, err
	}

	name, err := utils.NormalizeDNSLabel(resolved.Name)
	if err != nil {
		return types.Identity{}, err
	}
	resolved.Name = name

	return ensureTokenSecret(resolved)
}

// Generate creates a fresh Portal identity for name with a new private key,
// passing the new key through resolve exactly once.
func Generate(name string) (types.Identity, error) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return types.Identity{}, fmt.Errorf("generate secp256k1 private key: %w", err)
	}
	return resolve(types.Identity{
		Name:       name,
		PrivateKey: hex.EncodeToString(privateKey.Serialize()),
	})
}

func decode(data []byte) (types.Identity, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return types.Identity{}, errors.New("identity json is required")
	}

	var payload storedIdentity
	if err := json.Unmarshal(data, &payload); err != nil {
		return types.Identity{}, fmt.Errorf("decode identity json: %w", err)
	}
	return types.Identity(payload), nil
}

// Parse decodes an identity JSON document and validates it once through
// resolve. It never generates key material; a document without key material
// is an error.
func Parse(data []byte) (types.Identity, error) {
	decoded, err := decode(data)
	if err != nil {
		return types.Identity{}, err
	}
	return resolve(decoded)
}

// Marshal serializes a valid identity in the canonical identity file format.
// id must come from Generate or Parse; Marshal does not validate it. An
// identity carrying a mnemonic omits the derived private key.
func Marshal(id types.Identity) ([]byte, error) {
	return json.MarshalIndent(storedIdentityFromIdentity(id), "", "  ")
}

// resolveKeyMaterial trims the identity fields, derives the private key from
// a mnemonic when provided, requires key material, derives the public key and
// address from the private key exactly once, and verifies supplied address
// and public key values against the derived values exactly once. Lease
// identities (Resolve), relay identities, and local authorities share this
// one derivation path; each applies its own naming and policy on top.
func resolveKeyMaterial(id types.Identity) (types.Identity, error) {
	resolved := id.Copy()

	resolved.Name = strings.TrimSpace(resolved.Name)
	resolved.Address = strings.TrimSpace(resolved.Address)
	resolved.PublicKey = strings.TrimSpace(resolved.PublicKey)
	resolved.PrivateKey = strings.TrimSpace(resolved.PrivateKey)
	resolved.Mnemonic = normalizeMnemonic(resolved.Mnemonic)
	resolved.DerivationPath = strings.TrimSpace(resolved.DerivationPath)
	resolved.TokenSecret = strings.TrimSpace(resolved.TokenSecret)

	if resolved.Mnemonic != "" {
		privateKey, derivationPath, err := deriveSecp256k1PrivateKeyFromMnemonic(resolved.Mnemonic, resolved.DerivationPath)
		if err != nil {
			return types.Identity{}, err
		}
		resolved.DerivationPath = derivationPath
		if resolved.PrivateKey == "" {
			resolved.PrivateKey = privateKey
		} else if !strings.EqualFold(utils.TrimHexPrefix(resolved.PrivateKey), privateKey) {
			return types.Identity{}, errors.New("identity private key does not match mnemonic")
		}
	} else if resolved.DerivationPath != "" {
		return types.Identity{}, errors.New("identity derivation_path requires mnemonic")
	}

	if resolved.PrivateKey == "" {
		return types.Identity{}, errors.New("identity private key is required")
	}

	signingIdentity, err := ResolveSecp256k1Identity(resolved.PrivateKey)
	if err != nil {
		return types.Identity{}, err
	}
	if resolved.Address != "" {
		address, err := NormalizeEVMAddress(resolved.Address)
		if err != nil {
			return types.Identity{}, err
		}
		if address != signingIdentity.Address {
			return types.Identity{}, errors.New("identity address does not match private key")
		}
		resolved.Address = address
	} else {
		resolved.Address = signingIdentity.Address
	}
	if resolved.PublicKey != "" && !strings.EqualFold(utils.TrimHexPrefix(resolved.PublicKey), signingIdentity.PublicKey) {
		return types.Identity{}, errors.New("identity public key does not match private key")
	}
	resolved.PublicKey = signingIdentity.PublicKey
	resolved.PrivateKey = signingIdentity.PrivateKey

	return resolved, nil
}

// storedIdentity is the canonical identity file format: the same fields as
// types.Identity in the same order, so values convert directly. The JSON tags
// control which fields are exposed in the at-rest format.
type storedIdentity struct {
	Name           string `json:"name,omitempty"`
	Address        string `json:"address,omitempty"`
	PublicKey      string `json:"public_key,omitempty"`
	PrivateKey     string `json:"private_key,omitempty"`
	Mnemonic       string `json:"mnemonic,omitempty"`
	DerivationPath string `json:"derivation_path,omitempty"`
	TokenSecret    string `json:"token_secret,omitempty"`
}

// storedIdentityFromIdentity serializes a resolved identity, hiding the
// derived private key when a mnemonic can regenerate it.
func storedIdentityFromIdentity(id types.Identity) storedIdentity {
	stored := storedIdentity(id)
	if id.Mnemonic != "" {
		stored.PrivateKey = ""
	}
	return stored
}
