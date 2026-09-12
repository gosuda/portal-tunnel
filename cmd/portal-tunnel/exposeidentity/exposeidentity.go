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
	fromJSON := strings.TrimSpace(rawJSON) != ""

	decoded, created, err := loadSource(path, rawJSON)
	if err != nil {
		return types.Identity{}, err
	}

	var resolved types.Identity
	persist := created || fromJSON
	if decoded == nil {
		generatedName, err := defaultName(name, target)
		if err != nil {
			return types.Identity{}, err
		}
		if resolved, err = identity.Generate(generatedName); err != nil {
			return types.Identity{}, err
		}
	} else {
		if name != "" && decoded.Name != name {
			decoded.Name = name
			persist = true
		}
		if resolved, err = identity.Resolve(*decoded); err != nil {
			return types.Identity{}, err
		}
		if decoded.TokenSecret == "" {
			persist = true
		}
	}

	if persist && path != "" {
		if err := writeIdentityFile(path, resolved); err != nil {
			return types.Identity{}, err
		}
		if created {
			log.Info().
				Str("identity_path", path).
				Str("address", resolved.Address).
				Msg("generated tunnel identity and saved it to disk")
		}
	}
	return resolved, nil
}

// loadSource returns the identity to resolve: the --identity-json payload
// when set, the identity file at path when it exists, or nil when a fresh
// identity should be generated. created reports that no stored identity
// existed yet.
func loadSource(path, rawJSON string) (decoded *types.Identity, created bool, err error) {
	if raw := strings.TrimSpace(rawJSON); raw != "" {
		parsed, err := identity.Decode([]byte(raw))
		if err != nil {
			return nil, false, fmt.Errorf("decode identity json: %w", err)
		}
		return &parsed, false, nil
	}
	if path == "" {
		return nil, false, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read identity file: %w", err)
	}
	parsed, err := identity.Decode(data)
	if err != nil {
		return nil, false, fmt.Errorf("decode identity file: %w", err)
	}
	return &parsed, false, nil
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
