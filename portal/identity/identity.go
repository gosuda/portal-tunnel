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

// Resolve returns the canonical Portal identity for id: it trims the fields,
// derives the private key from a mnemonic when provided, requires key
// material, derives the public key and address from the private key exactly
// once, verifies explicitly supplied address and public key against the
// derived values exactly once, normalizes the name as a DNS label, and fills
// the token secret when missing. Resolve never generates key material; use
// Generate for that.
func Resolve(id types.Identity) (types.Identity, error) {
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

// Generate creates a fresh Portal identity for name with a new private key.
func Generate(name string) (types.Identity, error) {
	signingIdentity, err := ResolveSecp256k1Identity("")
	if err != nil {
		return types.Identity{}, fmt.Errorf("generate identity: %w", err)
	}
	return Resolve(types.Identity{Name: name, PrivateKey: signingIdentity.PrivateKey})
}

// Decode unmarshals an identity JSON document in the canonical identity file
// format without validating it. Callers that need to adjust fields before
// validation decode, adjust, and pass the result to Resolve.
func Decode(data []byte) (types.Identity, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return types.Identity{}, errors.New("identity json is required")
	}

	var payload storedIdentity
	if err := json.Unmarshal(data, &payload); err != nil {
		return types.Identity{}, fmt.Errorf("decode identity json: %w", err)
	}
	return storedIdentityToIdentity(payload), nil
}

// Parse decodes an identity JSON document and resolves it through Resolve.
// It never generates key material; a document without key material is an
// error.
func Parse(data []byte) (types.Identity, error) {
	decoded, err := Decode(data)
	if err != nil {
		return types.Identity{}, err
	}
	return Resolve(decoded)
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
