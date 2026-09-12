package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// ResolveRelayStateDir returns the relay state directory for path, accepting
// either a directory or a path to the relay identity/policy file.
func ResolveRelayStateDir(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	switch strings.ToLower(filepath.Base(trimmed)) {
	case types.RelayIdentityFilename, types.RelayPolicyFilename:
		return filepath.Dir(trimmed)
	default:
		return trimmed
	}
}

// ResolveRelayPolicyPath returns the relay policy file inside the state dir.
func ResolveRelayPolicyPath(path string) string {
	stateDir := ResolveRelayStateDir(path)
	if stateDir == "" {
		return ""
	}
	return filepath.Join(stateDir, types.RelayPolicyFilename)
}

func resolveRelayIdentityPath(path string) string {
	stateDir := ResolveRelayStateDir(path)
	if stateDir == "" {
		return ""
	}
	return filepath.Join(stateDir, types.RelayIdentityFilename)
}

type storedRelayIdentity struct {
	storedIdentity
	EncryptedClientHelloSeed string `json:"encrypted_client_hello_seed,omitempty"`
}

// LoadOrCreateRelayIdentity loads the relay identity from the state dir and
// persists any change, or generates and persists a fresh identity when the
// file does not exist yet.
func LoadOrCreateRelayIdentity(path, rootHost string) (types.RelayIdentity, error) {
	path = resolveRelayIdentityPath(path)
	if path == "" {
		return types.RelayIdentity{}, errors.New("identity path is required")
	}
	rootHost = strings.TrimSpace(rootHost)
	if normalizedRootHost := utils.PortalRootHost(rootHost); normalizedRootHost != "" {
		rootHost = normalizedRootHost
	} else {
		rootHost = utils.NormalizeHostname(rootHost)
	}

	relay, err := loadRelayIdentity(path)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		generated, genErr := ResolveSecp256k1Identity("")
		if genErr != nil {
			return types.RelayIdentity{}, fmt.Errorf("generate identity: %w", genErr)
		}
		relay = types.RelayIdentity{Identity: generated}
	default:
		return types.RelayIdentity{}, fmt.Errorf("load identity: %w", err)
	}

	if rootHost != "" {
		relay.Name = rootHost
	}
	if err := populateRelayIdentity(&relay); err != nil {
		return types.RelayIdentity{}, err
	}
	if err := saveRelayIdentity(path, relay); err != nil {
		return types.RelayIdentity{}, fmt.Errorf("persist identity: %w", err)
	}
	return relay, nil
}

func populateRelayIdentity(identity *types.RelayIdentity) error {
	if identity == nil {
		return errors.New("relay identity is required")
	}
	baseIdentity, err := ensureTokenSecret(identity.Identity)
	if err != nil {
		return err
	}
	identity.Identity = baseIdentity

	if strings.TrimSpace(identity.EncryptedClientHelloSeed) == "" {
		identity.EncryptedClientHelloSeed = utils.RandomID("")
	}

	return nil
}

func normalizeStoredRelayIdentity(identity types.RelayIdentity) (types.RelayIdentity, error) {
	normalized := identity.Copy()
	baseIdentity, err := normalizeStoredIdentity(normalized.Identity)
	if err != nil {
		return types.RelayIdentity{}, err
	}
	normalized.Identity = baseIdentity
	normalized.EncryptedClientHelloSeed = strings.TrimSpace(normalized.EncryptedClientHelloSeed)

	return normalized, nil
}

func loadRelayIdentity(path string) (types.RelayIdentity, error) {
	path = resolveRelayIdentityPath(path)
	if path == "" {
		return types.RelayIdentity{}, errors.New("identity path is required")
	}
	var payload storedRelayIdentity
	if err := utils.ReadJSONFile(path, &payload); err != nil {
		return types.RelayIdentity{}, fmt.Errorf("read identity file: %w", err)
	}
	return normalizeStoredRelayIdentity(types.RelayIdentity{
		Identity:                 storedIdentityToIdentity(payload.storedIdentity),
		EncryptedClientHelloSeed: payload.EncryptedClientHelloSeed,
	})
}

func saveRelayIdentity(path string, identity types.RelayIdentity) error {
	path = resolveRelayIdentityPath(path)
	if path == "" {
		return errors.New("identity path is required")
	}
	normalized, err := normalizeStoredRelayIdentity(identity)
	if err != nil {
		return err
	}
	if err := utils.WriteJSONFile(path, storedRelayIdentity{
		storedIdentity:           storedIdentityFromIdentity(normalized.Identity),
		EncryptedClientHelloSeed: normalized.EncryptedClientHelloSeed,
	}, 0o600); err != nil {
		return fmt.Errorf("write identity file: %w", err)
	}
	return nil
}
