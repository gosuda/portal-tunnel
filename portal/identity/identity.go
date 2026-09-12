package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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

// Resolve returns the canonical Portal identity for id. It normalizes the
// name and key material, derives the private key from a mnemonic when no
// private key is supplied, derives the public key and address from the
// private key (generating a fresh key when no key material is supplied),
// verifies explicitly supplied address and public key against the derived
// values once, and fills the token secret when missing.
func Resolve(id types.Identity) (types.Identity, error) {
	resolved, err := normalizeStoredIdentity(id)
	if err != nil {
		return types.Identity{}, err
	}

	name, err := utils.NormalizeDNSLabel(resolved.Name)
	if err != nil {
		return types.Identity{}, err
	}
	resolved.Name = name

	signingIdentity, err := ResolveSecp256k1Identity(resolved.PrivateKey)
	if err != nil {
		return types.Identity{}, err
	}
	if resolved.Address == "" {
		resolved.Address = signingIdentity.Address
	} else {
		address, err := NormalizeEVMAddress(resolved.Address)
		if err != nil {
			return types.Identity{}, err
		}
		if address != signingIdentity.Address {
			return types.Identity{}, errors.New("identity address does not match private key")
		}
		resolved.Address = address
	}

	resolved.PublicKey = signingIdentity.PublicKey
	resolved.PrivateKey = signingIdentity.PrivateKey
	return ensureTokenSecret(resolved)
}

// Generate creates a fresh Portal identity for name.
func Generate(name string) (types.Identity, error) {
	return Resolve(types.Identity{Name: name})
}

// Parse decodes an identity JSON document in the canonical identity file
// format and resolves it through Resolve.
func Parse(data []byte) (types.Identity, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return types.Identity{}, errors.New("identity json is required")
	}

	var payload storedIdentity
	if err := json.Unmarshal(data, &payload); err != nil {
		return types.Identity{}, fmt.Errorf("decode identity json: %w", err)
	}
	return Resolve(storedIdentityToIdentity(payload))
}

// Marshal resolves id and encodes it in the canonical identity file format.
// An identity carrying a mnemonic omits the derived private key.
func Marshal(id types.Identity) ([]byte, error) {
	resolved, err := Resolve(id)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(storedIdentityFromIdentity(resolved), "", "  ")
}

type storedIdentity struct {
	Name           string `json:"name,omitempty"`
	Address        string `json:"address,omitempty"`
	PublicKey      string `json:"public_key,omitempty"`
	PrivateKey     string `json:"private_key,omitempty"`
	Mnemonic       string `json:"mnemonic,omitempty"`
	DerivationPath string `json:"derivation_path,omitempty"`
	TokenSecret    string `json:"token_secret,omitempty"`
}

func storedIdentityToIdentity(payload storedIdentity) types.Identity {
	return types.Identity{
		Name:           payload.Name,
		Address:        payload.Address,
		PublicKey:      payload.PublicKey,
		PrivateKey:     payload.PrivateKey,
		Mnemonic:       payload.Mnemonic,
		DerivationPath: payload.DerivationPath,
		TokenSecret:    payload.TokenSecret,
	}
}

// normalizeStoredIdentity trims identity fields, derives the private key
// from a mnemonic when provided, and verifies supplied address/public-key
// values against the derived key material.
func normalizeStoredIdentity(identity types.Identity) (types.Identity, error) {
	normalized := identity.Copy()
	normalized.Name = strings.TrimSpace(normalized.Name)
	normalized.Address = strings.TrimSpace(normalized.Address)
	normalized.PublicKey = strings.TrimSpace(normalized.PublicKey)
	normalized.PrivateKey = strings.TrimSpace(normalized.PrivateKey)
	normalized.Mnemonic = normalizeMnemonic(normalized.Mnemonic)
	normalized.DerivationPath = strings.TrimSpace(normalized.DerivationPath)
	normalized.TokenSecret = strings.TrimSpace(normalized.TokenSecret)

	if normalized.Mnemonic != "" {
		privateKey, derivationPath, err := deriveSecp256k1PrivateKeyFromMnemonic(normalized.Mnemonic, normalized.DerivationPath)
		if err != nil {
			return types.Identity{}, err
		}
		normalized.DerivationPath = derivationPath
		if normalized.PrivateKey == "" {
			normalized.PrivateKey = privateKey
		} else if !strings.EqualFold(utils.TrimHexPrefix(normalized.PrivateKey), privateKey) {
			return types.Identity{}, errors.New("identity private key does not match mnemonic")
		}
	} else if normalized.DerivationPath != "" {
		return types.Identity{}, errors.New("identity derivation_path requires mnemonic")
	}

	switch {
	case normalized.PrivateKey != "":
		resolved, err := ResolveSecp256k1Identity(normalized.PrivateKey)
		if err != nil {
			return types.Identity{}, err
		}
		if normalized.PublicKey != "" && !strings.EqualFold(utils.TrimHexPrefix(normalized.PublicKey), resolved.PublicKey) {
			return types.Identity{}, errors.New("identity public key does not match private key")
		}
		if normalized.Address != "" && !strings.EqualFold(normalized.Address, resolved.Address) {
			return types.Identity{}, errors.New("identity address does not match private key")
		}
		normalized.Address = resolved.Address
		normalized.PublicKey = resolved.PublicKey
		normalized.PrivateKey = resolved.PrivateKey
	case normalized.PublicKey != "":
		address, err := AddressFromCompressedPublicKeyHex(normalized.PublicKey)
		if err != nil {
			return types.Identity{}, err
		}
		normalized.PublicKey = strings.ToLower(utils.TrimHexPrefix(normalized.PublicKey))
		if normalized.Address == "" {
			normalized.Address = address
			break
		}
		if !strings.EqualFold(normalized.Address, address) {
			return types.Identity{}, errors.New("identity address does not match public key")
		}
		normalized.Address = address
	case normalized.Address != "":
		address, err := NormalizeEVMAddress(normalized.Address)
		if err != nil {
			return types.Identity{}, err
		}
		normalized.Address = address
	}
	return normalized, nil
}
func storedIdentityFromIdentity(identity types.Identity) storedIdentity {
	privateKey := identity.PrivateKey
	if strings.TrimSpace(identity.Mnemonic) != "" {
		privateKey = ""
	}
	return storedIdentity{
		Name:           identity.Name,
		Address:        identity.Address,
		PublicKey:      identity.PublicKey,
		PrivateKey:     privateKey,
		Mnemonic:       identity.Mnemonic,
		DerivationPath: identity.DerivationPath,
		TokenSecret:    identity.TokenSecret,
	}
}
