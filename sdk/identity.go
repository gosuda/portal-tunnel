package sdk

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/internal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// GenerateIdentity creates a validated ephemeral client identity.
func GenerateIdentity(name string) (types.Identity, error) {
	if strings.TrimSpace(name) == "" {
		return types.Identity{}, errors.New("generate identity: name is required")
	}
	value, _, err := identity.ResolveListenerIdentity(types.Identity{Name: name}, "", "", "")
	if err != nil {
		return types.Identity{}, fmt.Errorf("generate identity: %w", err)
	}
	return value, nil
}

// IdentityFromPrivateKey creates and validates an identity from a hexadecimal
// secp256k1 private key.
func IdentityFromPrivateKey(name, privateKey string) (types.Identity, error) {
	if strings.TrimSpace(name) == "" {
		return types.Identity{}, errors.New("parse private key identity: name is required")
	}
	value, _, err := identity.ResolveListenerIdentity(types.Identity{
		Name:       name,
		PrivateKey: privateKey,
	}, "", "", "")
	if err != nil {
		return types.Identity{}, fmt.Errorf("parse private key identity: %w", err)
	}
	return value, nil
}

// ParseIdentity parses and validates persisted identity JSON.
func ParseIdentity(data []byte) (types.Identity, error) {
	value, err := identity.ParseIdentityJSON(data)
	if err != nil {
		return types.Identity{}, err
	}
	if strings.TrimSpace(value.Name) == "" {
		return types.Identity{}, errors.New("parse identity: name is required")
	}
	value, _, err = identity.ResolveListenerIdentity(value, "", "", "")
	return value, err
}

// MarshalIdentity serializes an identity for persistence. The result contains
// private key material and must be stored securely.
func MarshalIdentity(value types.Identity) ([]byte, error) {
	return identity.MarshalIdentityJSON(value)
}
