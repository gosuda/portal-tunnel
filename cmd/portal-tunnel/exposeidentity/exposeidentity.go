// Package exposeidentity contains the small amount of identity source
// selection shared by the expose command and the agent.
package exposeidentity

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Resolve returns the identity for the CLI flags. An --identity-json payload
// is an in-memory source and takes precedence over the file. Otherwise an
// existing identity file is read as-is. A new identity is generated only when
// no source exists, using name (or a target-derived default), and persisted
// when path is configured.
func Resolve(name, target, path, rawJSON string) (types.Identity, error) {
	name = strings.TrimSpace(name)
	path = strings.TrimSpace(path)
	if raw := strings.TrimSpace(rawJSON); raw != "" {
		return identity.Parse([]byte(raw))
	}

	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			return identity.Parse(data)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return types.Identity{}, fmt.Errorf("read identity file: %w", err)
		}
	}

	generatedName := name
	if generatedName == "" {
		var err error
		generatedName, err = utils.DefaultExposeName(target, utils.RandomID("cli_"))
		if err != nil {
			return types.Identity{}, err
		}
	}
	generated, err := identity.Generate(generatedName)
	if err != nil {
		return types.Identity{}, err
	}
	if path == "" {
		return generated, nil
	}
	data, err := identity.Marshal(generated)
	if err != nil {
		return types.Identity{}, err
	}
	if err := utils.EnsureParentDir(path); err != nil {
		return types.Identity{}, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return types.Identity{}, fmt.Errorf("write identity file: %w", err)
	}
	return generated, nil
}
