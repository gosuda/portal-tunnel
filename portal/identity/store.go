package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
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
	address, err := NormalizeSuiAddress(identity.Address)
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
	desc.WireGuardPublicKey = strings.TrimSpace(desc.WireGuardPublicKey)
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
		normalized, err := NormalizeSuiAddress(desc.Address)
		if err != nil {
			return types.RelayDescriptor{}, fmt.Errorf("normalize address: %w", err)
		}
		desc.Address = normalized
	}
	if desc.WireGuardPublicKey != "" {
		if err := ValidateWireGuardPublicKey(desc.WireGuardPublicKey); err != nil {
			return types.RelayDescriptor{}, err
		}
	}
	if desc.WireGuardPort < 0 || desc.WireGuardPort > 65535 {
		return types.RelayDescriptor{}, errors.New("wireguard_port is invalid")
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
	case desc.SupportsOverlay && desc.WireGuardPublicKey == "":
		return types.RelayDescriptor{}, errors.New("wireguard_public_key is required when supports_overlay is set")
	case desc.SupportsOverlay && desc.WireGuardPort == 0:
		return types.RelayDescriptor{}, errors.New("wireguard_port is required when supports_overlay is set")
	case !desc.SupportsOverlay && (desc.WireGuardPublicKey != "" || desc.WireGuardPort != 0):
		return types.RelayDescriptor{}, errors.New("supports_overlay is required when wireguard metadata is set")
	case desc.ExpiresAt.IsZero():
		return types.RelayDescriptor{}, errors.New("expires_at is required")
	case desc.IssuedAt.After(desc.ExpiresAt):
		return types.RelayDescriptor{}, errors.New("issued_at must be before expires_at")
	}

	return desc, nil
}

func RelayWireGuardEndpoint(desc types.RelayDescriptor) (string, error) {
	host := utils.PortalRootHost(desc.APIHTTPSAddr)
	if host == "" {
		return "", errors.New("api_https_addr host is required")
	}
	if desc.WireGuardPort <= 0 || desc.WireGuardPort > 65535 {
		return "", errors.New("wireguard_port is invalid")
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", desc.WireGuardPort)), nil
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
	normalized.SuiAddress = strings.TrimSpace(normalized.SuiAddress)
	normalized.SuiPublicKey = strings.TrimSpace(normalized.SuiPublicKey)
	normalized.SuiPrivateKey = strings.TrimSpace(normalized.SuiPrivateKey)
	normalized.SuiDerivationPath = strings.TrimSpace(normalized.SuiDerivationPath)
	normalized.TokenSecret = strings.TrimSpace(normalized.TokenSecret)

	if normalized.SuiAddress == "" {
		normalized.SuiAddress = normalized.Address
	}
	if normalized.SuiPublicKey == "" {
		normalized.SuiPublicKey = normalized.PublicKey
	}
	if normalized.SuiPrivateKey == "" {
		normalized.SuiPrivateKey = normalized.PrivateKey
	}
	if normalized.SuiDerivationPath == "" {
		normalized.SuiDerivationPath = normalized.DerivationPath
	}
	if err := normalizeStoredSuiIdentity(&normalized); err != nil {
		return types.Identity{}, err
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
	normalized.WireGuardPublicKey = strings.TrimSpace(normalized.WireGuardPublicKey)
	normalized.WireGuardPrivateKey = strings.TrimSpace(normalized.WireGuardPrivateKey)
	normalized.EncryptedClientHelloSeed = strings.TrimSpace(normalized.EncryptedClientHelloSeed)

	switch {
	case normalized.WireGuardPrivateKey != "":
		privateKey, err := NormalizeWireGuardPrivateKey(normalized.WireGuardPrivateKey)
		if err != nil {
			return types.RelayIdentity{}, fmt.Errorf("normalize wireguard private key: %w", err)
		}
		publicKey, err := WireGuardPublicKeyFromPrivate(privateKey)
		if err != nil {
			return types.RelayIdentity{}, fmt.Errorf("derive wireguard public key: %w", err)
		}
		if configuredPublicKey := strings.TrimSpace(normalized.WireGuardPublicKey); configuredPublicKey != "" {
			if err := ValidateWireGuardPublicKey(configuredPublicKey); err != nil {
				return types.RelayIdentity{}, err
			}
			if configuredPublicKey != publicKey {
				return types.RelayIdentity{}, errors.New("identity wireguard public key does not match private key")
			}
		}
		normalized.WireGuardPrivateKey = privateKey
		normalized.WireGuardPublicKey = publicKey
	case normalized.WireGuardPublicKey != "":
		if err := ValidateWireGuardPublicKey(normalized.WireGuardPublicKey); err != nil {
			return types.RelayIdentity{}, err
		}
	}

	return normalized, nil
}

type storedIdentity struct {
	Name              string `json:"name,omitempty"`
	Address           string `json:"address,omitempty"`
	PublicKey         string `json:"public_key,omitempty"`
	PrivateKey        string `json:"private_key,omitempty"`
	Mnemonic          string `json:"mnemonic,omitempty"`
	DerivationPath    string `json:"derivation_path,omitempty"`
	SuiAddress        string `json:"sui_address,omitempty"`
	SuiPublicKey      string `json:"sui_public_key,omitempty"`
	SuiPrivateKey     string `json:"sui_private_key,omitempty"`
	SuiDerivationPath string `json:"sui_derivation_path,omitempty"`
	TokenSecret       string `json:"token_secret,omitempty"`
}

type storedRelayIdentity struct {
	storedIdentity
	WireGuardPublicKey       string `json:"wireguard_public_key,omitempty"`
	WireGuardPrivateKey      string `json:"wireguard_private_key,omitempty"`
	EncryptedClientHelloSeed string `json:"encrypted_client_hello_seed,omitempty"`
}

func storedIdentityFromIdentity(identity types.Identity) storedIdentity {
	privateKey := identity.PrivateKey
	suiPrivateKey := identity.SuiPrivateKey
	if strings.TrimSpace(identity.Mnemonic) != "" {
		privateKey = ""
		suiPrivateKey = ""
	}
	return storedIdentity{
		Name:              identity.Name,
		Address:           identity.Address,
		PublicKey:         identity.PublicKey,
		PrivateKey:        privateKey,
		Mnemonic:          identity.Mnemonic,
		DerivationPath:    identity.DerivationPath,
		SuiAddress:        identity.SuiAddress,
		SuiPublicKey:      identity.SuiPublicKey,
		SuiPrivateKey:     suiPrivateKey,
		SuiDerivationPath: identity.SuiDerivationPath,
		TokenSecret:       identity.TokenSecret,
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
		WireGuardPublicKey:       normalized.WireGuardPublicKey,
		WireGuardPrivateKey:      normalized.WireGuardPrivateKey,
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
		Name:              payload.Name,
		Address:           payload.Address,
		PublicKey:         payload.PublicKey,
		PrivateKey:        payload.PrivateKey,
		Mnemonic:          payload.Mnemonic,
		DerivationPath:    payload.DerivationPath,
		SuiAddress:        payload.SuiAddress,
		SuiPublicKey:      payload.SuiPublicKey,
		SuiPrivateKey:     payload.SuiPrivateKey,
		SuiDerivationPath: payload.SuiDerivationPath,
		TokenSecret:       payload.TokenSecret,
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
			Name:              payload.Name,
			Address:           payload.Address,
			PublicKey:         payload.PublicKey,
			PrivateKey:        payload.PrivateKey,
			Mnemonic:          payload.Mnemonic,
			DerivationPath:    payload.DerivationPath,
			SuiAddress:        payload.SuiAddress,
			SuiPublicKey:      payload.SuiPublicKey,
			SuiPrivateKey:     payload.SuiPrivateKey,
			SuiDerivationPath: payload.SuiDerivationPath,
			TokenSecret:       payload.TokenSecret,
		},
		WireGuardPublicKey:       payload.WireGuardPublicKey,
		WireGuardPrivateKey:      payload.WireGuardPrivateKey,
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
		Name:              payload.Name,
		Address:           payload.Address,
		PublicKey:         payload.PublicKey,
		PrivateKey:        payload.PrivateKey,
		Mnemonic:          payload.Mnemonic,
		DerivationPath:    payload.DerivationPath,
		SuiAddress:        payload.SuiAddress,
		SuiPublicKey:      payload.SuiPublicKey,
		SuiPrivateKey:     payload.SuiPrivateKey,
		SuiDerivationPath: payload.SuiDerivationPath,
		TokenSecret:       payload.TokenSecret,
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
		if suiAddress := strings.TrimSpace(identity.SuiAddress); suiAddress != "" {
			stored.SuiAddress = suiAddress
		}
		if suiPublicKey := strings.TrimSpace(identity.SuiPublicKey); suiPublicKey != "" {
			stored.SuiPublicKey = suiPublicKey
		}
		if suiPrivateKey := strings.TrimSpace(identity.SuiPrivateKey); suiPrivateKey != "" {
			stored.SuiPrivateKey = suiPrivateKey
		}
		if suiDerivationPath := strings.TrimSpace(identity.SuiDerivationPath); suiDerivationPath != "" {
			stored.SuiDerivationPath = suiDerivationPath
		}
		if tokenSecret := strings.TrimSpace(identity.TokenSecret); tokenSecret != "" {
			stored.TokenSecret = tokenSecret
		}
		if strings.TrimSpace(stored.SuiPrivateKey) == "" && strings.TrimSpace(stored.PrivateKey) == "" && strings.TrimSpace(stored.Mnemonic) == "" {
			return types.Identity{}, false, errors.New("stored identity sui private key is required")
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
	if strings.TrimSpace(created.SuiPrivateKey) == "" &&
		strings.TrimSpace(created.PrivateKey) == "" &&
		strings.TrimSpace(created.Mnemonic) == "" &&
		strings.TrimSpace(created.SuiDerivationPath) == "" &&
		strings.TrimSpace(created.DerivationPath) == "" {
		mnemonic, err := GenerateMnemonic()
		if err != nil {
			return types.Identity{}, false, fmt.Errorf("generate identity mnemonic: %w", err)
		}
		created.Mnemonic = mnemonic
		created.SuiDerivationPath = DefaultSuiEd25519PaymentDerivationPath
	}
	if strings.TrimSpace(created.Mnemonic) != "" || strings.TrimSpace(created.SuiDerivationPath) != "" || strings.TrimSpace(created.DerivationPath) != "" {
		created, err = normalizeStoredIdentity(created)
		if err != nil {
			return types.Identity{}, false, fmt.Errorf("resolve identity mnemonic: %w", err)
		}
	} else {
		privateKey := strings.TrimSpace(created.SuiPrivateKey)
		if privateKey == "" {
			privateKey = strings.TrimSpace(created.PrivateKey)
		}
		generated, err := ResolveSuiEd25519Identity(privateKey)
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
		created.SuiAddress = generated.SuiAddress
		created.SuiPublicKey = generated.SuiPublicKey
		created.SuiPrivateKey = generated.SuiPrivateKey
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

func LoadOrCreateRelayIdentity(path, rootHost string, discoveryEnabled bool) (types.RelayIdentity, error) {
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

		if err := populateRelayIdentity(&stored, discoveryEnabled); err != nil {
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
	generated, err := ResolveSuiEd25519Identity(created.SuiPrivateKey)
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
	created.SuiAddress = generated.SuiAddress
	created.SuiPublicKey = generated.SuiPublicKey
	created.SuiPrivateKey = generated.SuiPrivateKey
	created.Identity, err = ensureTokenSecret(created.Identity)
	if err != nil {
		return types.RelayIdentity{}, err
	}

	if err := populateRelayIdentity(&created, discoveryEnabled); err != nil {
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

func populateRelayIdentity(identity *types.RelayIdentity, discoveryEnabled bool) error {
	if identity == nil {
		return errors.New("relay identity is required")
	}
	baseIdentity, err := ensureTokenSecret(identity.Identity)
	if err != nil {
		return err
	}
	identity.Identity = baseIdentity

	if discoveryEnabled && strings.TrimSpace(identity.WireGuardPrivateKey) == "" {
		var err error
		wireGuardPrivateKey, err := GenerateWireGuardPrivateKey()
		if err != nil {
			return fmt.Errorf("generate relay wireguard private key: %w", err)
		}
		identity.WireGuardPrivateKey = wireGuardPrivateKey
	}

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

	signingIdentity, err := ResolveSuiEd25519Identity(resolved.SuiPrivateKey)
	if err != nil {
		return types.Identity{}, err
	}
	if resolved.Address == "" {
		resolved.Address = signingIdentity.Address
	} else {
		address, err := NormalizeSuiAddress(resolved.Address)
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
	resolved.SuiAddress = signingIdentity.SuiAddress
	resolved.SuiPublicKey = signingIdentity.SuiPublicKey
	resolved.SuiPrivateKey = signingIdentity.SuiPrivateKey
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
