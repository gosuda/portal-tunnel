package portal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	portalidentity "github.com/gosuda/portal-tunnel/v2/portal/identity"
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

type relayIdentityFile struct {
	Name                     string `json:"name,omitempty"`
	Address                  string `json:"address,omitempty"`
	PublicKey                string `json:"public_key,omitempty"`
	PrivateKey               string `json:"private_key,omitempty"`
	Mnemonic                 string `json:"mnemonic,omitempty"`
	DerivationPath           string `json:"derivation_path,omitempty"`
	TokenSecret              string `json:"token_secret,omitempty"`
	EncryptedClientHelloSeed string `json:"encrypted_client_hello_seed,omitempty"`
}

// LoadOrCreateRelayIdentity loads relay state from disk or creates it during
// relay startup. The file is written by the relay itself, so a loaded
// identity is trusted as-is; only the relay hostname is applied and a
// missing ECH seed is filled, and the file is rewritten only when that
// changed something. Persistence is kept here with the relay owner rather
// than in the identity primitives package.
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

	relay, err := loadRelayIdentityFile(path)
	created := errors.Is(err, os.ErrNotExist)
	switch {
	case err == nil:
		if relay.Address == "" || relay.PublicKey == "" || relay.PrivateKey == "" {
			return types.RelayIdentity{}, errors.New("relay identity file is incomplete")
		}
	case created:
		generated, generateErr := portalidentity.Generate("relay")
		if generateErr != nil {
			return types.RelayIdentity{}, fmt.Errorf("generate relay identity: %w", generateErr)
		}
		relay = types.RelayIdentity{Identity: generated}
	default:
		return types.RelayIdentity{}, fmt.Errorf("load identity: %w", err)
	}

	stored := relay
	if rootHost != "" {
		relay.Name = rootHost
	}
	if relay.EncryptedClientHelloSeed == "" {
		relay.EncryptedClientHelloSeed = utils.RandomID("")
	}
	if created || relay != stored {
		if err := saveRelayIdentity(path, relay); err != nil {
			return types.RelayIdentity{}, fmt.Errorf("persist identity: %w", err)
		}
	}
	return relay, nil
}

func loadRelayIdentityFile(path string) (types.RelayIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return types.RelayIdentity{}, err
	}
	var payload relayIdentityFile
	if err := json.Unmarshal(data, &payload); err != nil {
		return types.RelayIdentity{}, fmt.Errorf("decode identity file: %w", err)
	}
	return types.RelayIdentity{Identity: types.Identity{
		Name:           payload.Name,
		Address:        payload.Address,
		PublicKey:      payload.PublicKey,
		PrivateKey:     payload.PrivateKey,
		Mnemonic:       payload.Mnemonic,
		DerivationPath: payload.DerivationPath,
		TokenSecret:    payload.TokenSecret,
	}, EncryptedClientHelloSeed: payload.EncryptedClientHelloSeed}, nil
}

func saveRelayIdentity(path string, relay types.RelayIdentity) error {
	privateKey := relay.PrivateKey
	if strings.TrimSpace(relay.Mnemonic) != "" {
		privateKey = ""
	}
	data, err := json.MarshalIndent(relayIdentityFile{
		Name:                     relay.Name,
		Address:                  relay.Address,
		PublicKey:                relay.PublicKey,
		PrivateKey:               privateKey,
		Mnemonic:                 relay.Mnemonic,
		DerivationPath:           relay.DerivationPath,
		TokenSecret:              relay.TokenSecret,
		EncryptedClientHelloSeed: relay.EncryptedClientHelloSeed,
	}, "", "  ")
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
