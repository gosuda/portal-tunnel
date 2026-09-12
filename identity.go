package portal

import (
	"github.com/gosuda/portal-tunnel/v2/internal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// GenerateIdentity creates a fresh lease identity for name without
// persisting it. Persisting is the caller's concern.
func GenerateIdentity(name string) (types.Identity, error) {
	return identity.GenerateIdentity(name)
}

// ParseIdentity decodes an identity JSON document in the same format
// LoadIdentity reads and validates it as a lease identity.
func ParseIdentity(data []byte) (types.Identity, error) {
	return identity.ParseIdentity(data)
}

// LoadIdentity reads an identity file and validates it as a lease identity.
func LoadIdentity(path string) (types.Identity, error) {
	return identity.LoadIdentity(path)
}
