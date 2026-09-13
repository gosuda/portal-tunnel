package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

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

type RelayIdentity struct {
	types.Identity
	EncryptedClientHelloSeed string
}

func (i RelayIdentity) Copy() RelayIdentity {
	return RelayIdentity{
		Identity:                 i.Identity.Copy(),
		EncryptedClientHelloSeed: i.EncryptedClientHelloSeed,
	}
}

// LoadOrCreateRelayIdentity loads the relay identity from path or creates it
// during relay startup. The file is written by the relay itself, so a
// loaded identity is trusted as-is; only the relay hostname is applied and a
// missing ECH seed is filled. The file is rewritten only when something
// changed.
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
	if relay.EncryptedClientHelloSeed == "" {
		relay.EncryptedClientHelloSeed = utils.RandomID("")
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
	var payload relayIdentityFile
	if err := json.Unmarshal(data, &payload); err != nil {
		return RelayIdentity{}, fmt.Errorf("decode identity file: %w", err)
	}
	return RelayIdentity{Identity: types.Identity{
		Name:           payload.Name,
		Address:        payload.Address,
		PublicKey:      payload.PublicKey,
		PrivateKey:     payload.PrivateKey,
		Mnemonic:       payload.Mnemonic,
		DerivationPath: payload.DerivationPath,
		TokenSecret:    payload.TokenSecret,
	}, EncryptedClientHelloSeed: payload.EncryptedClientHelloSeed}, nil
}

func saveRelayIdentity(path string, relay RelayIdentity) error {
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
