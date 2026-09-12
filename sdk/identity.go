package sdk

import (
	"github.com/gosuda/portal-tunnel/v2/internal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// GenerateIdentity creates a fresh lease identity for name without
// persisting it.
func GenerateIdentity(name string) (types.Identity, error) {
	return identity.GenerateIdentity(name)
}

// ParseIdentity decodes and validates an identity JSON document.
func ParseIdentity(data []byte) (types.Identity, error) {
	return identity.ParseIdentity(data)
}

// LoadIdentity reads and validates an identity file.
func LoadIdentity(path string) (types.Identity, error) {
	return identity.LoadIdentity(path)
}
