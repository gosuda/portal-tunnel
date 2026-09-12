// Package identityfile owns the CLI identity-resolution policy: how the
// --name, --identity-json, and --identity-path flags combine into the
// resolved identity handed to sdk.Expose, and when an identity file is
// created or rewritten. Cryptographic resolution belongs to portal/identity;
// this package only composes it with flag and file policy.
package identityfile

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

// Resolve returns the identity for the CLI flags. Precedence: an explicit
// --identity-json payload, then the identity file at path (created with a
// generated key when absent), then a generated ephemeral identity. A
// non-empty name overrides the identity name from either source.
func Resolve(name, target, path, rawJSON string) (types.Identity, error) {
	name = strings.TrimSpace(name)
	path = strings.TrimSpace(path)
	rawJSON = strings.TrimSpace(rawJSON)

	if rawJSON != "" {
		parsed, err := identity.Parse([]byte(rawJSON))
		if err != nil {
			return types.Identity{}, fmt.Errorf("parse identity json: %w", err)
		}
		parsed, err = withName(parsed, name)
		if err != nil {
			return types.Identity{}, err
		}
		if path != "" {
			if err := Write(path, parsed); err != nil {
				return types.Identity{}, err
			}
		}
		return parsed, nil
	}

	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			stored, perr := identity.Parse(data)
			if perr != nil {
				return types.Identity{}, fmt.Errorf("load identity: %w", perr)
			}
			if name == "" || stored.Name == name {
				return stored, nil
			}
			stored, perr = withName(stored, name)
			if perr != nil {
				return types.Identity{}, perr
			}
			if werr := Write(path, stored); werr != nil {
				return types.Identity{}, werr
			}
			return stored, nil
		case !errors.Is(err, fs.ErrNotExist):
			return types.Identity{}, fmt.Errorf("load identity: %w", err)
		}

		resolvedName, err := defaultName(name, target)
		if err != nil {
			return types.Identity{}, err
		}
		generated, err := identity.Generate(resolvedName)
		if err != nil {
			return types.Identity{}, err
		}
		if err := Write(path, generated); err != nil {
			return types.Identity{}, err
		}
		log.Info().
			Str("identity_path", path).
			Str("address", generated.Address).
			Msg("generated tunnel identity and saved it to disk")
		return generated, nil
	}

	resolvedName, err := defaultName(name, target)
	if err != nil {
		return types.Identity{}, err
	}
	return identity.Generate(resolvedName)
}

// Write persists a resolved identity to path.
func Write(path string, id types.Identity) error {
	data, err := identity.Marshal(id)
	if err != nil {
		return err
	}
	if err := utils.EnsureParentDir(path); err != nil {
		return err
	}
	return utils.WriteFileAtomic(path, data, 0o600)
}

func withName(id types.Identity, name string) (types.Identity, error) {
	if name == "" || id.Name == name {
		return id, nil
	}
	id.Name = name
	return identity.Resolve(id)
}

func defaultName(name, target string) (string, error) {
	if name != "" {
		return name, nil
	}
	return utils.DefaultExposeName(target, utils.RandomID("cli_"))
}
