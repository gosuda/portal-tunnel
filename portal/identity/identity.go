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

var (
	errIdentityJSONIsRequired                 = errors.New("identity json is required")
	errIdentityPrivateKeyDoesNotMatch         = errors.New("identity private key does not match mnemonic")
	errIdentityDerivationPathRequiresMnemonic = errors.New("identity derivation_path requires mnemonic")
	errIdentityPrivateKeyIsRequired           = errors.New("identity private key is required")
	errIdentityAddressDoesNotMatchPrivate     = errors.New("identity address does not match private key")
	errIdentityPublicKeyDoesNotMatch          = errors.New("identity public key does not match private key")
)

func normalizeOptionalName(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	return utils.NormalizeServiceName(trimmed)
}

// NormalizeIdentity returns the canonical comparison form of a wire identity:
// the name as a DNS label (or empty for the unnamed service) and the address
// in EVM checksum form. It does not derive or verify key material.
func NormalizeIdentity(identity types.Identity) (types.Identity, error) {
	normalized := identity

	name, err := normalizeOptionalName(identity.Name)
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

func resolve(id types.Identity) (types.Identity, error) {
	resolved, err := resolveKeyMaterial(id)
	if err != nil {
		return types.Identity{}, err
	}

	name, err := normalizeOptionalName(resolved.Name)
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
		return types.Identity{}, errIdentityJSONIsRequired
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

func resolveKeyMaterial(id types.Identity) (types.Identity, error) {
	trimmed := trimmedIdentityCopy(id)
	return keyedIdentityFromTrimmed(trimmed)
}

func trimmedIdentityCopy(id types.Identity) types.Identity {
	id.Name = strings.TrimSpace(id.Name)
	id.Address = strings.TrimSpace(id.Address)
	id.PublicKey = strings.TrimSpace(id.PublicKey)
	id.PrivateKey = strings.TrimSpace(id.PrivateKey)
	id.Mnemonic = normalizeMnemonic(id.Mnemonic)
	id.DerivationPath = strings.TrimSpace(id.DerivationPath)
	id.TokenSecret = strings.TrimSpace(id.TokenSecret)
	return id
}

func keyedIdentityFromTrimmed(trimmed types.Identity) (types.Identity, error) {
	resolved := trimmed
	if err := applyMnemonicKeyMaterial(&resolved); err != nil {
		return types.Identity{}, err
	}
	if resolved.PrivateKey == "" {
		return types.Identity{}, errIdentityPrivateKeyIsRequired
	}
	signingIdentity, err := ResolveSecp256k1Identity(resolved.PrivateKey)
	if err != nil {
		return types.Identity{}, err
	}
	if err := resolveIdentityAddress(&resolved, signingIdentity.Address); err != nil {
		return types.Identity{}, err
	}
	if resolved.PublicKey != "" && !strings.EqualFold(utils.TrimHexPrefix(resolved.PublicKey), signingIdentity.PublicKey) {
		return types.Identity{}, errIdentityPublicKeyDoesNotMatch
	}
	resolved.PublicKey = signingIdentity.PublicKey
	resolved.PrivateKey = signingIdentity.PrivateKey
	return resolved, nil
}

func applyMnemonicKeyMaterial(resolved *types.Identity) error {
	if resolved.Mnemonic == "" {
		if resolved.DerivationPath != "" {
			return errIdentityDerivationPathRequiresMnemonic
		}
		return nil
	}
	privateKey, derivationPath, err := deriveSecp256k1PrivateKeyFromMnemonic(resolved.Mnemonic, resolved.DerivationPath)
	if err != nil {
		return err
	}
	resolved.DerivationPath = derivationPath
	if resolved.PrivateKey == "" {
		resolved.PrivateKey = privateKey
	} else if !strings.EqualFold(utils.TrimHexPrefix(resolved.PrivateKey), privateKey) {
		return errIdentityPrivateKeyDoesNotMatch
	}
	return nil
}

func resolveIdentityAddress(resolved *types.Identity, signingAddress string) error {
	if resolved.Address == "" {
		resolved.Address = signingAddress
		return nil
	}
	address, err := NormalizeEVMAddress(resolved.Address)
	if err != nil {
		return err
	}
	if address != signingAddress {
		return errIdentityAddressDoesNotMatchPrivate
	}
	resolved.Address = address
	return nil
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

func storedIdentityFromIdentity(id types.Identity) storedIdentity {
	stored := storedIdentity(id)
	if id.Mnemonic != "" {
		stored.PrivateKey = ""
	}
	return stored
}
