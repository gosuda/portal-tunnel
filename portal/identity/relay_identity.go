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

// LoadOrCreateRelayIdentity loads the relay identity from the state dir, or
// generates and persists a fresh one when the file does not exist. The file
// is rewritten only when loading or generation actually changed its content;
// an unchanged identity is not persisted again.
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
	var decoded types.RelayIdentity
	switch {
	case err == nil:
		decoded = relay
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
	resolved, err := resolveRelayIdentity(relay)
	if err != nil {
		return types.RelayIdentity{}, err
	}

	if !relayIdentityEqual(decoded, resolved) {
		if err := saveRelayIdentity(path, resolved); err != nil {
			return types.RelayIdentity{}, fmt.Errorf("persist identity: %w", err)
		}
	}
	return resolved, nil
}

// populateRelayIdentity fills the token secret and ECH seed when missing.
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

// resolveRelayIdentity applies the shared key-material resolution path to the
// relay identity and trims the ECH seed. Relay names are hostnames, so the
// DNS-label naming policy of Resolve does not apply.
func resolveRelayIdentity(relay types.RelayIdentity) (types.RelayIdentity, error) {
	resolved := relay.Copy()
	baseIdentity, err := resolveKeyMaterial(resolved.Identity)
	if err != nil {
		return types.RelayIdentity{}, err
	}
	resolved.Identity = baseIdentity
	resolved.EncryptedClientHelloSeed = strings.TrimSpace(resolved.EncryptedClientHelloSeed)

	return resolved, nil
}

func relayIdentityEqual(a, b types.RelayIdentity) bool {
	return a.Name == b.Name &&
		a.Address == b.Address &&
		a.PublicKey == b.PublicKey &&
		a.PrivateKey == b.PrivateKey &&
		a.Mnemonic == b.Mnemonic &&
		a.DerivationPath == b.DerivationPath &&
		a.TokenSecret == b.TokenSecret &&
		a.EncryptedClientHelloSeed == b.EncryptedClientHelloSeed
}

// loadRelayIdentity decodes the relay identity file without resolving it;
// LoadOrCreateRelayIdentity resolves once after applying its policy.
func loadRelayIdentity(path string) (types.RelayIdentity, error) {
	path = resolveRelayIdentityPath(path)
	if path == "" {
		return types.RelayIdentity{}, errors.New("identity path is required")
	}
	var payload storedRelayIdentity
	if err := utils.ReadJSONFile(path, &payload); err != nil {
		return types.RelayIdentity{}, fmt.Errorf("read identity file: %w", err)
	}
	return types.RelayIdentity{
		Identity:                 storedIdentityToIdentity(payload.storedIdentity),
		EncryptedClientHelloSeed: payload.EncryptedClientHelloSeed,
	}, nil
}

func saveRelayIdentity(path string, relay types.RelayIdentity) error {
	path = resolveRelayIdentityPath(path)
	if path == "" {
		return errors.New("identity path is required")
	}
	if err := utils.WriteJSONFile(path, storedRelayIdentity{
		storedIdentity:           storedIdentityFromIdentity(relay.Identity),
		EncryptedClientHelloSeed: relay.EncryptedClientHelloSeed,
	}, 0o600); err != nil {
		return fmt.Errorf("write identity file: %w", err)
	}
	return nil
}
