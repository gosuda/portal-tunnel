// Package identity owns Portal identities: the single validation pipeline
// behind Parse and Generate, the canonical identity file format, and the
// client and relay identity lifecycles.
package identity

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// LoadOrCreate returns the client identity for the expose flags. A raw JSON
// payload is an in-memory source and wins; otherwise an existing identity
// file at path is parsed as-is; a new identity is generated only when no
// source exists, using name (or a target-derived default — target is used
// for nothing else) and persisted when a path is configured.
func LoadOrCreate(name, target, path, rawJSON string) (types.Identity, error) {
	name = strings.TrimSpace(name)
	path = strings.TrimSpace(path)
	if raw := strings.TrimSpace(rawJSON); raw != "" {
		return Parse([]byte(raw))
	}

	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			return Parse(data)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return types.Identity{}, fmt.Errorf("read identity file: %w", err)
		}
	}

	if name == "" {
		var err error
		name, err = utils.DefaultExposeName(target, utils.RandomID("cli_"))
		if err != nil {
			return types.Identity{}, err
		}
	}
	generated, err := Generate(name)
	if err != nil {
		return types.Identity{}, err
	}
	if path == "" {
		return generated, nil
	}
	data, err := Marshal(generated)
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
