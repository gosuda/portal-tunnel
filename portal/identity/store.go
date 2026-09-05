package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func NormalizeIdentity(identity types.Identity) (types.Identity, error) {
	normalized := identity.Copy()

	name, err := utils.NormalizeDNSLabel(identity.Name)
	if err != nil {
		return types.Identity{}, err
	}
	address, err := NormalizeEVMAddress(identity.Address)
	if err != nil {
		return types.Identity{}, err
	}

	normalized.Name = name
	normalized.Address = address
	return normalized, nil
}

func NormalizeRelayDescriptor(desc types.RelayDescriptor) (types.RelayDescriptor, error) {
	desc.Address = strings.TrimSpace(desc.Address)
	desc.Version = strings.TrimSpace(desc.Version)
	desc.APIHTTPSAddr = strings.TrimSpace(desc.APIHTTPSAddr)
	if desc.Version == "" {
		desc.Version = types.DiscoveryVersion
	}
	if !desc.IssuedAt.IsZero() {
		desc.IssuedAt = desc.IssuedAt.UTC()
	}
	if !desc.ExpiresAt.IsZero() {
		desc.ExpiresAt = desc.ExpiresAt.UTC()
	}

	if desc.APIHTTPSAddr != "" {
		normalized, err := utils.NormalizeRelayURL(desc.APIHTTPSAddr)
		if err != nil {
			return types.RelayDescriptor{}, fmt.Errorf("normalize api https addr: %w", err)
		}
		desc.APIHTTPSAddr = normalized
	}
	if desc.Address != "" {
		normalized, err := NormalizeEVMAddress(desc.Address)
		if err != nil {
			return types.RelayDescriptor{}, fmt.Errorf("normalize address: %w", err)
		}
		desc.Address = normalized
	}
	if desc.ActiveConnections < 0 {
		return types.RelayDescriptor{}, errors.New("active_connections is invalid")
	}
	if desc.TCPBPS < 0 || math.IsNaN(desc.TCPBPS) || math.IsInf(desc.TCPBPS, 0) {
		return types.RelayDescriptor{}, errors.New("tcp_bps is invalid")
	}

	switch {
	case desc.Address == "":
		return types.RelayDescriptor{}, errors.New("address is required")
	case desc.Version != types.DiscoveryVersion:
		return types.RelayDescriptor{}, fmt.Errorf("unsupported relay descriptor version %q", desc.Version)
	case desc.APIHTTPSAddr == "":
		return types.RelayDescriptor{}, errors.New("api_https_addr is required")
	case desc.ExpiresAt.IsZero():
		return types.RelayDescriptor{}, errors.New("expires_at is required")
	case desc.IssuedAt.After(desc.ExpiresAt):
		return types.RelayDescriptor{}, errors.New("issued_at must be before expires_at")
	}

	return desc, nil
}

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

func resolveRelayIdentityPath(path string) string {
	stateDir := ResolveRelayStateDir(path)
	if stateDir == "" {
		return ""
	}
	return filepath.Join(stateDir, types.RelayIdentityFilename)
}

func ResolveRelayPolicyPath(path string) string {
	stateDir := ResolveRelayStateDir(path)
	if stateDir == "" {
		return ""
	}
	return filepath.Join(stateDir, types.RelayPolicyFilename)
}

func normalizeStoredIdentity(identity types.Identity) (types.Identity, error) {
	normalized := identity.Copy()
	normalized.Name = strings.TrimSpace(normalized.Name)
	normalized.Address = strings.TrimSpace(normalized.Address)
	normalized.PublicKey = strings.TrimSpace(normalized.PublicKey)
	normalized.PrivateKey = strings.TrimSpace(normalized.PrivateKey)
	normalized.Mnemonic = normalizeMnemonic(normalized.Mnemonic)
	normalized.DerivationPath = strings.TrimSpace(normalized.DerivationPath)
	normalized.TokenSecret = strings.TrimSpace(normalized.TokenSecret)

	if normalized.Mnemonic != "" {
		privateKey, derivationPath, err := deriveSecp256k1PrivateKeyFromMnemonic(normalized.Mnemonic, normalized.DerivationPath)
		if err != nil {
			return types.Identity{}, err
		}
		normalized.DerivationPath = derivationPath
		if normalized.PrivateKey == "" {
			normalized.PrivateKey = privateKey
		} else if !strings.EqualFold(utils.TrimHexPrefix(normalized.PrivateKey), privateKey) {
			return types.Identity{}, errors.New("identity private key does not match mnemonic")
		}
	} else if normalized.DerivationPath != "" {
		return types.Identity{}, errors.New("identity derivation_path requires mnemonic")
	}

	switch {
	case normalized.PrivateKey != "":
		resolved, err := ResolveSecp256k1Identity(normalized.PrivateKey)
		if err != nil {
			return types.Identity{}, err
		}
		if normalized.PublicKey != "" && !strings.EqualFold(utils.TrimHexPrefix(normalized.PublicKey), resolved.PublicKey) {
			return types.Identity{}, errors.New("identity public key does not match private key")
		}
		if normalized.Address != "" && !strings.EqualFold(normalized.Address, resolved.Address) {
			return types.Identity{}, errors.New("identity address does not match private key")
		}
		normalized.Address = resolved.Address
		normalized.PublicKey = resolved.PublicKey
		normalized.PrivateKey = resolved.PrivateKey
	case normalized.PublicKey != "":
		address, err := AddressFromCompressedPublicKeyHex(normalized.PublicKey)
		if err != nil {
			return types.Identity{}, err
		}
		normalized.PublicKey = strings.ToLower(utils.TrimHexPrefix(normalized.PublicKey))
		if normalized.Address == "" {
			normalized.Address = address
			break
		}
		if !strings.EqualFold(normalized.Address, address) {
			return types.Identity{}, errors.New("identity address does not match public key")
		}
		normalized.Address = address
	case normalized.Address != "":
		address, err := NormalizeEVMAddress(normalized.Address)
		if err != nil {
			return types.Identity{}, err
		}
		normalized.Address = address
	}
	return normalized, nil
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

type storedIdentity struct {
	Name           string `json:"name,omitempty"`
	Address        string `json:"address,omitempty"`
	PublicKey      string `json:"public_key,omitempty"`
	PrivateKey     string `json:"private_key,omitempty"`
	Mnemonic       string `json:"mnemonic,omitempty"`
	DerivationPath string `json:"derivation_path,omitempty"`
	TokenSecret    string `json:"token_secret,omitempty"`
}

type storedRelayIdentity struct {
	storedIdentity
	EncryptedClientHelloSeed string `json:"encrypted_client_hello_seed,omitempty"`
}

func storedIdentityFromIdentity(identity types.Identity) storedIdentity {
	privateKey := identity.PrivateKey
	if strings.TrimSpace(identity.Mnemonic) != "" {
		privateKey = ""
	}
	return storedIdentity{
		Name:           identity.Name,
		Address:        identity.Address,
		PublicKey:      identity.PublicKey,
		PrivateKey:     privateKey,
		Mnemonic:       identity.Mnemonic,
		DerivationPath: identity.DerivationPath,
		TokenSecret:    identity.TokenSecret,
	}
}

func saveIdentity(path string, identity types.Identity) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("identity path is required")
	}
	normalized, err := normalizeStoredIdentity(identity)
	if err != nil {
		return err
	}
	normalized, err = ensureTokenSecret(normalized)
	if err != nil {
		return err
	}
	if err := utils.WriteJSONFile(path, storedIdentityFromIdentity(normalized), 0o600); err != nil {
		return fmt.Errorf("write identity file: %w", err)
	}
	return nil
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
	baseIdentity, err := ensureTokenSecret(normalized.Identity)
	if err != nil {
		return err
	}
	normalized.Identity = baseIdentity
	storedBaseIdentity := storedIdentityFromIdentity(normalized.Identity)
	if err := utils.WriteJSONFile(path, storedRelayIdentity{
		storedIdentity:           storedBaseIdentity,
		EncryptedClientHelloSeed: normalized.EncryptedClientHelloSeed,
	}, 0o600); err != nil {
		return fmt.Errorf("write identity file: %w", err)
	}
	return nil
}

func loadIdentity(path string) (types.Identity, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return types.Identity{}, errors.New("identity path is required")
	}
	var payload storedIdentity
	if err := utils.ReadJSONFile(path, &payload); err != nil {
		return types.Identity{}, fmt.Errorf("read identity file: %w", err)
	}
	return normalizeStoredIdentity(types.Identity{
		Name:           payload.Name,
		Address:        payload.Address,
		PublicKey:      payload.PublicKey,
		PrivateKey:     payload.PrivateKey,
		Mnemonic:       payload.Mnemonic,
		DerivationPath: payload.DerivationPath,
		TokenSecret:    payload.TokenSecret,
	})
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
		Identity: types.Identity{
			Name:           payload.Name,
			Address:        payload.Address,
			PublicKey:      payload.PublicKey,
			PrivateKey:     payload.PrivateKey,
			Mnemonic:       payload.Mnemonic,
			DerivationPath: payload.DerivationPath,
			TokenSecret:    payload.TokenSecret,
		},
		EncryptedClientHelloSeed: payload.EncryptedClientHelloSeed,
	})
}

func parseIdentityJSON(raw string) (types.Identity, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return types.Identity{}, errors.New("identity json is required")
	}

	var payload storedIdentity
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return types.Identity{}, fmt.Errorf("decode identity json: %w", err)
	}
	return normalizeStoredIdentity(types.Identity{
		Name:           payload.Name,
		Address:        payload.Address,
		PublicKey:      payload.PublicKey,
		PrivateKey:     payload.PrivateKey,
		Mnemonic:       payload.Mnemonic,
		DerivationPath: payload.DerivationPath,
		TokenSecret:    payload.TokenSecret,
	})
}

func loadOrCreateIdentity(path string, identity types.Identity) (types.Identity, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return types.Identity{}, false, errors.New("identity path is required")
	}

	stored, err := loadIdentity(path)
	switch {
	case err == nil:
		if name := strings.TrimSpace(identity.Name); name != "" {
			stored.Name = name
		}
		if address := strings.TrimSpace(identity.Address); address != "" {
			stored.Address = address
		}
		if publicKey := strings.TrimSpace(identity.PublicKey); publicKey != "" {
			stored.PublicKey = publicKey
		}
		if privateKey := strings.TrimSpace(identity.PrivateKey); privateKey != "" {
			stored.PrivateKey = privateKey
		}
		if mnemonic := normalizeMnemonic(identity.Mnemonic); mnemonic != "" {
			stored.Mnemonic = mnemonic
		}
		if derivationPath := strings.TrimSpace(identity.DerivationPath); derivationPath != "" {
			stored.DerivationPath = derivationPath
		}
		if tokenSecret := strings.TrimSpace(identity.TokenSecret); tokenSecret != "" {
			stored.TokenSecret = tokenSecret
		}
		if strings.TrimSpace(stored.PrivateKey) == "" {
			return types.Identity{}, false, errors.New("stored identity private key is required")
		}
		if err := saveIdentity(path, stored); err != nil {
			return types.Identity{}, false, fmt.Errorf("persist identity: %w", err)
		}
		loaded, err := loadIdentity(path)
		if err != nil {
			return types.Identity{}, false, fmt.Errorf("load identity: %w", err)
		}
		return loaded, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return types.Identity{}, false, fmt.Errorf("load identity: %w", err)
	}

	created := identity.Copy()
	if strings.TrimSpace(created.Mnemonic) != "" || strings.TrimSpace(created.DerivationPath) != "" {
		created, err = normalizeStoredIdentity(created)
		if err != nil {
			return types.Identity{}, false, fmt.Errorf("resolve identity mnemonic: %w", err)
		}
	} else {
		generated, err := ResolveSecp256k1Identity(created.PrivateKey)
		if err != nil {
			return types.Identity{}, false, fmt.Errorf("generate identity: %w", err)
		}
		if strings.TrimSpace(created.Address) == "" {
			created.Address = generated.Address
		}
		if strings.TrimSpace(created.PublicKey) == "" {
			created.PublicKey = generated.PublicKey
		}
		created.PrivateKey = generated.PrivateKey
	}
	if strings.TrimSpace(created.TokenSecret) == "" {
		created, err = ensureTokenSecret(created)
		if err != nil {
			return types.Identity{}, false, err
		}
	}
	if err := saveIdentity(path, created); err != nil {
		return types.Identity{}, false, fmt.Errorf("persist identity: %w", err)
	}
	loaded, err := loadIdentity(path)
	if err != nil {
		return types.Identity{}, false, fmt.Errorf("load identity: %w", err)
	}
	return loaded, true, nil
}

func ResolveListenerIdentity(baseIdentity types.Identity, target, identityPath, identityJSON string) (types.Identity, bool, error) {
	identityPath = strings.TrimSpace(identityPath)
	identityJSON = strings.TrimSpace(identityJSON)
	resolvedName, err := resolveExposeName(baseIdentity.Name, target, identityPath, identityJSON)
	if err != nil {
		return types.Identity{}, false, err
	}
	baseIdentity.Name = resolvedName
	if identityJSON != "" {
		provided, err := parseIdentityJSON(identityJSON)
		if err != nil {
			return types.Identity{}, false, err
		}
		provided.Name = baseIdentity.Name
		if identityPath != "" {
			if err := saveIdentity(identityPath, provided); err != nil {
				return types.Identity{}, false, fmt.Errorf("persist identity: %w", err)
			}
			provided, err = loadIdentity(identityPath)
			if err != nil {
				return types.Identity{}, false, fmt.Errorf("load identity: %w", err)
			}
		}
		resolved, err := resolveLeaseIdentity(provided)
		return resolved, false, err
	}
	if identityPath == "" {
		resolved, err := resolveLeaseIdentity(baseIdentity)
		return resolved, false, err
	}

	loaded, created, err := loadOrCreateIdentity(identityPath, baseIdentity)
	if err != nil {
		return types.Identity{}, false, err
	}
	resolved, err := resolveLeaseIdentity(loaded)
	if err != nil {
		return types.Identity{}, false, err
	}
	return resolved, created, nil
}

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

	stored, err := loadRelayIdentity(path)
	switch {
	case err == nil:
		if rootHost != "" {
			stored.Name = rootHost
		}

		if err := populateRelayIdentity(&stored); err != nil {
			return types.RelayIdentity{}, err
		}
		if err := saveRelayIdentity(path, stored); err != nil {
			return types.RelayIdentity{}, fmt.Errorf("persist identity: %w", err)
		}
		loaded, err := loadRelayIdentity(path)
		if err != nil {
			return types.RelayIdentity{}, fmt.Errorf("load identity: %w", err)
		}
		return loaded, nil
	case !errors.Is(err, os.ErrNotExist):
		return types.RelayIdentity{}, fmt.Errorf("load identity: %w", err)
	}

	created := types.RelayIdentity{
		Identity: types.Identity{Name: rootHost},
	}
	generated, err := ResolveSecp256k1Identity(created.PrivateKey)
	if err != nil {
		return types.RelayIdentity{}, fmt.Errorf("generate identity: %w", err)
	}
	if strings.TrimSpace(created.Address) == "" {
		created.Address = generated.Address
	}
	if strings.TrimSpace(created.PublicKey) == "" {
		created.PublicKey = generated.PublicKey
	}
	created.PrivateKey = generated.PrivateKey
	created.Identity, err = ensureTokenSecret(created.Identity)
	if err != nil {
		return types.RelayIdentity{}, err
	}

	if err := populateRelayIdentity(&created); err != nil {
		return types.RelayIdentity{}, err
	}
	if err := saveRelayIdentity(path, created); err != nil {
		return types.RelayIdentity{}, fmt.Errorf("persist identity: %w", err)
	}
	loaded, err := loadRelayIdentity(path)
	if err != nil {
		return types.RelayIdentity{}, fmt.Errorf("load identity: %w", err)
	}
	return loaded, nil
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

func normalizeIdentityKey(raw string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	if key == "" {
		return ""
	}
	name, address, ok := strings.Cut(key, types.IdentityKeySeparator)
	if !ok || name == "" || address == "" {
		return ""
	}
	return name + types.IdentityKeySeparator + address
}

func NormalizeIdentityKeys(inputs []string) []string {
	return normalizeUniqueStrings(inputs, normalizeIdentityKey)
}

func NormalizeIdentityKeyBPS(inputs map[string]int64) map[string]int64 {
	if len(inputs) == 0 {
		return nil
	}

	out := make(map[string]int64, len(inputs))
	for input, bps := range inputs {
		key := normalizeIdentityKey(input)
		if key == "" || bps <= 0 {
			continue
		}
		out[key] = bps
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func resolveExposeName(name, target, identityPath, identityJSON string) (string, error) {
	if name = strings.TrimSpace(name); name != "" {
		return name, nil
	}
	if identityJSON = strings.TrimSpace(identityJSON); identityJSON != "" {
		providedIdentity, err := parseIdentityJSON(identityJSON)
		if err != nil {
			return "", err
		}
		if name := strings.TrimSpace(providedIdentity.Name); name != "" {
			return name, nil
		}
	}
	if identityPath = strings.TrimSpace(identityPath); identityPath != "" {
		storedIdentity, err := loadIdentity(identityPath)
		switch {
		case err == nil:
			if name := strings.TrimSpace(storedIdentity.Name); name != "" {
				return name, nil
			}
		case !errors.Is(err, os.ErrNotExist):
			return "", err
		}
	}

	return utils.DefaultExposeName(target, utils.RandomID("cli_"))
}

func resolveLeaseIdentity(identity types.Identity) (types.Identity, error) {
	resolved, err := normalizeStoredIdentity(identity)
	if err != nil {
		return types.Identity{}, err
	}

	name, err := utils.NormalizeDNSLabel(resolved.Name)
	if err != nil {
		return types.Identity{}, err
	}
	resolved.Name = name

	signingIdentity, err := ResolveSecp256k1Identity(resolved.PrivateKey)
	if err != nil {
		return types.Identity{}, err
	}
	if resolved.Address == "" {
		resolved.Address = signingIdentity.Address
	} else {
		address, err := NormalizeEVMAddress(resolved.Address)
		if err != nil {
			return types.Identity{}, err
		}
		if address != signingIdentity.Address {
			return types.Identity{}, errors.New("identity address does not match private key")
		}
		resolved.Address = address
	}

	resolved.PublicKey = signingIdentity.PublicKey
	resolved.PrivateKey = signingIdentity.PrivateKey
	return ensureTokenSecret(resolved)
}

func normalizeUniqueStrings(inputs []string, normalize func(string) string) []string {
	if len(inputs) == 0 {
		return nil
	}

	out := make([]string, 0, len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		normalized := normalize(input)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
