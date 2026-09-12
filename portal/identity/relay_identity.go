package identity

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

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
// generates a fresh one when the file does not exist. The file is rewritten
// only when loading or generation actually changed its content; an unchanged
// identity is not persisted again.
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
		privateKey, genErr := secp256k1.GeneratePrivateKey()
		if genErr != nil {
			return types.RelayIdentity{}, fmt.Errorf("generate secp256k1 private key: %w", genErr)
		}
		relay = types.RelayIdentity{Identity: types.Identity{
			PrivateKey: hex.EncodeToString(privateKey.Serialize()),
		}}
	default:
		return types.RelayIdentity{}, fmt.Errorf("load identity: %w", err)
	}

	if rootHost != "" {
		relay.Name = rootHost
	}
	resolved, err := canonicalizeRelayIdentity(relay)
	if err != nil {
		return types.RelayIdentity{}, err
	}

	if decoded != resolved {
		if err := saveRelayIdentity(path, resolved); err != nil {
			return types.RelayIdentity{}, fmt.Errorf("persist identity: %w", err)
		}
	}
	return resolved, nil
}

// canonicalizeRelayIdentity fills the token secret and ECH seed when missing
// and applies the shared key-material resolution path. Relay names are
// hostnames, so the DNS-label naming policy of Resolve does not apply.
func canonicalizeRelayIdentity(relay types.RelayIdentity) (types.RelayIdentity, error) {
	baseIdentity, err := ensureTokenSecret(relay.Identity)
	if err != nil {
		return types.RelayIdentity{}, err
	}
	relay.Identity = baseIdentity

	relay.EncryptedClientHelloSeed = strings.TrimSpace(relay.EncryptedClientHelloSeed)
	if relay.EncryptedClientHelloSeed == "" {
		relay.EncryptedClientHelloSeed = utils.RandomID("")
	}

	resolvedIdentity, err := resolveKeyMaterial(relay.Identity)
	if err != nil {
		return types.RelayIdentity{}, err
	}
	relay.Identity = resolvedIdentity

	return relay, nil
}

// loadRelayIdentity decodes the relay identity file at the final file path
// without resolving it; LoadOrCreateRelayIdentity resolves once after
// applying its policy.
func loadRelayIdentity(path string) (types.RelayIdentity, error) {
	var payload storedRelayIdentity
	if err := utils.ReadJSONFile(path, &payload); err != nil {
		return types.RelayIdentity{}, fmt.Errorf("read identity file: %w", err)
	}
	return types.RelayIdentity{
		Identity:                 types.Identity(payload.storedIdentity),
		EncryptedClientHelloSeed: payload.EncryptedClientHelloSeed,
	}, nil
}

func saveRelayIdentity(path string, relay types.RelayIdentity) error {
	if err := utils.WriteJSONFile(path, storedRelayIdentity{
		storedIdentity:           storedIdentityFromIdentity(relay.Identity),
		EncryptedClientHelloSeed: relay.EncryptedClientHelloSeed,
	}, 0o600); err != nil {
		return fmt.Errorf("write identity file: %w", err)
	}
	return nil
}
