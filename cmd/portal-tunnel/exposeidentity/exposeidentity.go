// Package exposeidentity owns the identity-flag policy shared by the expose
// command and the agent: how --name, --identity-json, and --identity-path
// combine into the resolved identity handed to sdk.Expose, and when an
// identity file is created or rewritten. It is CLI composition, not identity
// machinery; key derivation and the file format belong to portal/identity.
package exposeidentity

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Resolve returns the identity for the CLI flags. An --identity-json payload
// wins, then the identity file at path (created with a generated key when
// absent), then an ephemeral generated identity when no path is configured.
// An explicit name overrides the stored name before validation; the file is
// rewritten only when its content actually changes.
func Resolve(name, target, path, rawJSON string) (types.Identity, error) {
	name = strings.TrimSpace(name)
	path = strings.TrimSpace(path)

	if raw := strings.TrimSpace(rawJSON); raw != "" {
		decoded, err := identity.Decode([]byte(raw))
		if err != nil {
			return types.Identity{}, fmt.Errorf("decode identity json: %w", err)
		}
		return resolveNamed(decoded, name, path, true)
	}

	if path == "" {
		generatedName, nameErr := defaultName(name, target)
		if nameErr != nil {
			return types.Identity{}, nameErr
		}
		return identity.Generate(generatedName)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return types.Identity{}, fmt.Errorf("read identity file: %w", err)
		}
		generatedName, nameErr := defaultName(name, target)
		if nameErr != nil {
			return types.Identity{}, nameErr
		}
		generated, genErr := identity.Generate(generatedName)
		if genErr != nil {
			return types.Identity{}, genErr
		}
		if writeErr := writeIdentityFile(path, generated); writeErr != nil {
			return types.Identity{}, writeErr
		}
		log.Info().
			Str("identity_path", path).
			Str("address", generated.Address).
			Msg("generated tunnel identity and saved it to disk")
		return generated, nil
	}

	decoded, err := identity.Decode(data)
	if err != nil {
		return types.Identity{}, fmt.Errorf("decode identity file: %w", err)
	}
	return resolveNamed(decoded, name, path, false)
}

// resolveNamed applies the explicit name override before validation so an
// invalid stored name can still be replaced, resolves once through the
// canonical path, and persists only when the file content would change.
func resolveNamed(decoded types.Identity, name, path string, fromJSON bool) (types.Identity, error) {
	persist := fromJSON
	if name != "" && decoded.Name != name {
		decoded.Name = name
		persist = true
	}
	resolved, err := identity.Resolve(decoded)
	if err != nil {
		return types.Identity{}, err
	}
	if decoded.TokenSecret == "" {
		persist = true
	}
	if persist && path != "" {
		if err := writeIdentityFile(path, resolved); err != nil {
			return types.Identity{}, err
		}
	}
	return resolved, nil
}

func defaultName(name, target string) (string, error) {
	if name != "" {
		return name, nil
	}
	return utils.DefaultExposeName(target, utils.RandomID("cli_"))
}

func writeIdentityFile(path string, id types.Identity) error {
	data, err := identity.Marshal(id)
	if err != nil {
		return err
	}
	if err := utils.EnsureParentDir(path); err != nil {
		return err
	}
	return utils.WriteFileAtomic(path, data, 0o600)
}
