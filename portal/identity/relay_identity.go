package identity

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type RelayIdentity struct {
	types.Identity
}

func (i RelayIdentity) Copy() RelayIdentity {
	return RelayIdentity{
		Identity: i.Identity.Copy(),
	}
}

// LoadOrCreateRelayIdentity loads the relay identity from path or creates it
// during relay startup. The file is written by the relay itself, so a
// loaded identity is trusted as-is; only the relay hostname is applied.
// The file is rewritten only when something changed.
func LoadOrCreateRelayIdentity(path, rootHost string) (RelayIdentity, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return RelayIdentity{}, errors.New("identity path is required")
	}
	rootHost = strings.TrimSpace(rootHost)
	if normalizedRootHost := utils.PortalRootHost(rootHost); normalizedRootHost != "" {
		rootHost = normalizedRootHost
	} else {
		rootHost = utils.NormalizeHostname(rootHost)
	}

	relay, err := loadRelayIdentityFile(path)
	created := errors.Is(err, os.ErrNotExist)
	switch {
	case err == nil:
		if relay.Address == "" || relay.PublicKey == "" || relay.PrivateKey == "" {
			return RelayIdentity{}, errors.New("relay identity file is incomplete")
		}
	case created:
		generated, generateErr := Generate("relay")
		if generateErr != nil {
			return RelayIdentity{}, fmt.Errorf("generate relay identity: %w", generateErr)
		}
		relay = RelayIdentity{Identity: generated}
	default:
		return RelayIdentity{}, fmt.Errorf("load identity: %w", err)
	}

	stored := relay
	if rootHost != "" {
		relay.Name = rootHost
	}
	if created || relay != stored {
		if err := saveRelayIdentity(path, relay); err != nil {
			return RelayIdentity{}, fmt.Errorf("persist identity: %w", err)
		}
	}
	return relay, nil
}

func loadRelayIdentityFile(path string) (RelayIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RelayIdentity{}, err
	}
	decoded, err := decode(data)
	if err != nil {
		return RelayIdentity{}, err
	}
	return RelayIdentity{Identity: decoded}, nil
}

func saveRelayIdentity(path string, relay RelayIdentity) error {
	data, err := Marshal(relay.Identity)
	if err != nil {
		return err
	}
	if err := utils.EnsureParentDir(path); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return nil
}
