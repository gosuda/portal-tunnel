package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func NormalizeIdentity(identity types.Identity) (types.Identity, error) {
	normalized := identity.Copy()

	name, err := NormalizeDNSLabel(identity.Name)
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

func NormalizeDescriptor(desc types.RelayDescriptor) (types.RelayDescriptor, error) {
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
		normalized, err := NormalizeRelayURL(desc.APIHTTPSAddr)
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
	host := PortalRootHost(desc.APIHTTPSAddr)
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
	case types.RelayIdentityFilename, types.RelayAdminSettingsFilename:
		return filepath.Dir(trimmed)
	default:
		return trimmed
	}
}

func ResolveRelayIdentityPath(path string) string {
	stateDir := ResolveRelayStateDir(path)
	if stateDir == "" {
		return ""
	}
	return filepath.Join(stateDir, types.RelayIdentityFilename)
}

func ResolveRelayAdminSettingsPath(path string) string {
	stateDir := ResolveRelayStateDir(path)
	if stateDir == "" {
		return ""
	}
	return filepath.Join(stateDir, types.RelayAdminSettingsFilename)
}

func NormalizeStoredIdentity(identity types.Identity) (types.Identity, error) {
	normalized := identity.Copy()
	normalized.Name = strings.TrimSpace(normalized.Name)
	normalized.Address = strings.TrimSpace(normalized.Address)
	normalized.PublicKey = strings.TrimSpace(normalized.PublicKey)
	normalized.PrivateKey = strings.TrimSpace(normalized.PrivateKey)

	switch {
	case normalized.PrivateKey != "":
		resolved, err := ResolveSecp256k1Identity(normalized.PrivateKey)
		if err != nil {
			return types.Identity{}, err
		}
		if normalized.PublicKey != "" && !strings.EqualFold(TrimHexPrefix(normalized.PublicKey), resolved.PublicKey) {
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
		normalized.PublicKey = strings.ToLower(TrimHexPrefix(normalized.PublicKey))
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

func NormalizeStoredRelayIdentity(identity types.RelayIdentity) (types.RelayIdentity, error) {
	normalized := identity.Copy()
	baseIdentity, err := NormalizeStoredIdentity(normalized.Identity)
	if err != nil {
		return types.RelayIdentity{}, err
	}
	normalized.Identity = baseIdentity
	normalized.AdminSecretKey = strings.TrimSpace(normalized.AdminSecretKey)
	normalized.WireGuardPublicKey = strings.TrimSpace(normalized.WireGuardPublicKey)
	normalized.WireGuardPrivateKey = strings.TrimSpace(normalized.WireGuardPrivateKey)

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
	Name       string `json:"name,omitempty"`
	Address    string `json:"address,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
}

type storedRelayIdentity struct {
	storedIdentity
	AdminSecretKey      string `json:"admin_secret_key,omitempty"`
	WireGuardPublicKey  string `json:"wireguard_public_key,omitempty"`
	WireGuardPrivateKey string `json:"wireguard_private_key,omitempty"`
}

func SaveIdentity(path string, identity types.Identity) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("identity path is required")
	}
	normalized, err := NormalizeStoredIdentity(identity)
	if err != nil {
		return err
	}
	if err := WriteJSONFile(path, storedIdentity{
		Name:       normalized.Name,
		Address:    normalized.Address,
		PublicKey:  normalized.PublicKey,
		PrivateKey: normalized.PrivateKey,
	}, 0o600); err != nil {
		return fmt.Errorf("write identity file: %w", err)
	}
	return nil
}

func SaveRelayIdentity(path string, identity types.RelayIdentity) error {
	path = ResolveRelayIdentityPath(path)
	if path == "" {
		return errors.New("identity path is required")
	}
	normalized, err := NormalizeStoredRelayIdentity(identity)
	if err != nil {
		return err
	}
	if err := WriteJSONFile(path, storedRelayIdentity{
		storedIdentity: storedIdentity{
			Name:       normalized.Name,
			Address:    normalized.Address,
			PublicKey:  normalized.PublicKey,
			PrivateKey: normalized.PrivateKey,
		},
		AdminSecretKey:      normalized.AdminSecretKey,
		WireGuardPublicKey:  normalized.WireGuardPublicKey,
		WireGuardPrivateKey: normalized.WireGuardPrivateKey,
	}, 0o600); err != nil {
		return fmt.Errorf("write identity file: %w", err)
	}
	return nil
}

func LoadIdentity(path string) (types.Identity, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return types.Identity{}, errors.New("identity path is required")
	}
	var payload storedIdentity
	if err := ReadJSONFile(path, &payload); err != nil {
		return types.Identity{}, fmt.Errorf("read identity file: %w", err)
	}
	return NormalizeStoredIdentity(types.Identity{
		Name:       payload.Name,
		Address:    payload.Address,
		PublicKey:  payload.PublicKey,
		PrivateKey: payload.PrivateKey,
	})
}

func LoadRelayIdentity(path string) (types.RelayIdentity, error) {
	path = ResolveRelayIdentityPath(path)
	if path == "" {
		return types.RelayIdentity{}, errors.New("identity path is required")
	}
	var payload storedRelayIdentity
	if err := ReadJSONFile(path, &payload); err != nil {
		return types.RelayIdentity{}, fmt.Errorf("read identity file: %w", err)
	}
	return NormalizeStoredRelayIdentity(types.RelayIdentity{
		Identity: types.Identity{
			Name:       payload.Name,
			Address:    payload.Address,
			PublicKey:  payload.PublicKey,
			PrivateKey: payload.PrivateKey,
		},
		AdminSecretKey:      payload.AdminSecretKey,
		WireGuardPublicKey:  payload.WireGuardPublicKey,
		WireGuardPrivateKey: payload.WireGuardPrivateKey,
	})
}

func ParseIdentityJSON(raw string) (types.Identity, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return types.Identity{}, errors.New("identity json is required")
	}

	var payload storedIdentity
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return types.Identity{}, fmt.Errorf("decode identity json: %w", err)
	}
	return NormalizeStoredIdentity(types.Identity{
		Name:       payload.Name,
		Address:    payload.Address,
		PublicKey:  payload.PublicKey,
		PrivateKey: payload.PrivateKey,
	})
}

func LoadOrCreateIdentity(path string, identity types.Identity) (types.Identity, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return types.Identity{}, false, errors.New("identity path is required")
	}

	stored, err := LoadIdentity(path)
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
		if strings.TrimSpace(stored.PrivateKey) == "" {
			return types.Identity{}, false, errors.New("stored identity private key is required")
		}
		if err := SaveIdentity(path, stored); err != nil {
			return types.Identity{}, false, fmt.Errorf("persist identity: %w", err)
		}
		loaded, err := LoadIdentity(path)
		if err != nil {
			return types.Identity{}, false, fmt.Errorf("load identity: %w", err)
		}
		return loaded, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return types.Identity{}, false, fmt.Errorf("load identity: %w", err)
	}

	created := identity.Copy()
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
	if err := SaveIdentity(path, created); err != nil {
		return types.Identity{}, false, fmt.Errorf("persist identity: %w", err)
	}
	loaded, err := LoadIdentity(path)
	if err != nil {
		return types.Identity{}, false, fmt.Errorf("load identity: %w", err)
	}
	return loaded, true, nil
}

func LoadOrCreateRelayIdentity(path, rootHost string, discoveryEnabled bool) (types.RelayIdentity, error) {
	path = ResolveRelayIdentityPath(path)
	if path == "" {
		return types.RelayIdentity{}, errors.New("identity path is required")
	}
	rootHost = strings.TrimSpace(rootHost)
	if normalizedRootHost := PortalRootHost(rootHost); normalizedRootHost != "" {
		rootHost = normalizedRootHost
	} else {
		rootHost = NormalizeHostname(rootHost)
	}

	stored, err := LoadRelayIdentity(path)
	switch {
	case err == nil:
		if rootHost != "" {
			stored.Name = rootHost
		}

		if err := populateRelayIdentity(&stored, discoveryEnabled); err != nil {
			return types.RelayIdentity{}, err
		}
		if err := SaveRelayIdentity(path, stored); err != nil {
			return types.RelayIdentity{}, fmt.Errorf("persist identity: %w", err)
		}
		loaded, err := LoadRelayIdentity(path)
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

	if err := populateRelayIdentity(&created, discoveryEnabled); err != nil {
		return types.RelayIdentity{}, err
	}
	if err := SaveRelayIdentity(path, created); err != nil {
		return types.RelayIdentity{}, fmt.Errorf("persist identity: %w", err)
	}
	loaded, err := LoadRelayIdentity(path)
	if err != nil {
		return types.RelayIdentity{}, fmt.Errorf("load identity: %w", err)
	}
	return loaded, nil
}

func populateRelayIdentity(identity *types.RelayIdentity, discoveryEnabled bool) error {
	if identity == nil {
		return errors.New("relay identity is required")
	}

	if strings.TrimSpace(identity.AdminSecretKey) == "" {
		adminSecretKey, err := identity.DeriveToken("admin-secret")
		if err != nil {
			return fmt.Errorf("derive relay admin secret key: %w", err)
		}
		identity.AdminSecretKey = adminSecretKey
	}

	if discoveryEnabled && strings.TrimSpace(identity.WireGuardPrivateKey) == "" {
		var err error
		wireGuardPrivateKey, err := GenerateWireGuardPrivateKey()
		if err != nil {
			return fmt.Errorf("generate relay wireguard private key: %w", err)
		}
		identity.WireGuardPrivateKey = wireGuardPrivateKey
	}

	return nil
}

func ResolveListenerIdentity(identity types.Identity, target, identityPath, identityJSON string) (types.Identity, bool, error) {
	identityPath = strings.TrimSpace(identityPath)
	identityJSON = strings.TrimSpace(identityJSON)
	resolvedName, err := resolveExposeName(identity.Name, target, identityPath, identityJSON)
	if err != nil {
		return types.Identity{}, false, err
	}
	identity.Name = resolvedName
	if identityJSON != "" {
		provided, err := ParseIdentityJSON(identityJSON)
		if err != nil {
			return types.Identity{}, false, err
		}
		provided.Name = identity.Name
		if identityPath != "" {
			if err := SaveIdentity(identityPath, provided); err != nil {
				return types.Identity{}, false, fmt.Errorf("persist identity: %w", err)
			}
			provided, err = LoadIdentity(identityPath)
			if err != nil {
				return types.Identity{}, false, fmt.Errorf("load identity: %w", err)
			}
		}
		resolved, err := ResolveLeaseIdentity(provided)
		return resolved, false, err
	}
	if identityPath == "" {
		resolved, err := ResolveLeaseIdentity(identity)
		return resolved, false, err
	}

	loaded, created, err := LoadOrCreateIdentity(identityPath, identity)
	if err != nil {
		return types.Identity{}, false, err
	}
	resolved, err := ResolveLeaseIdentity(loaded)
	if err != nil {
		return types.Identity{}, false, err
	}
	return resolved, created, nil
}

func NormalizeIdentityKey(raw string) string {
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
	return normalizeUniqueStrings(inputs, NormalizeIdentityKey)
}

func NormalizeIdentityKeyBPS(inputs map[string]int64) map[string]int64 {
	if len(inputs) == 0 {
		return nil
	}

	out := make(map[string]int64, len(inputs))
	for input, bps := range inputs {
		key := NormalizeIdentityKey(input)
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

func ResolveLeaseIdentity(identity types.Identity) (types.Identity, error) {
	resolved := identity.Copy()

	name, err := NormalizeDNSLabel(resolved.Name)
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
	return resolved, nil
}

var exposeNameOpeners = []string{
	"arcade", "bouncy", "bravo", "bubble", "candy", "cosmic", "dapper", "electric",
	"fancy", "fizzy", "flashy", "fuzzy", "gentle", "glitter", "golden", "happy",
	"hyper", "jazzy", "jolly", "lively", "lucky", "magic", "mellow", "minty",
	"misty", "moonlit", "mystic", "neon", "nova", "peppy", "pixel", "playful",
	"poppy", "rapid", "rocket", "rowdy", "snappy", "snazzy", "sparkly", "spicy",
	"sprightly", "starry", "sunny", "swift", "tangy", "tidy", "toasty", "turbo",
	"velvet", "vivid", "wavy", "whimsy", "wild", "wonky", "zany", "zesty",
}

var exposeNameCenters = []string{
	"alpaca", "badger", "banjo", "beacon", "biscuit", "capybara", "comet", "cricket",
	"dragon", "falcon", "feather", "fjord", "fox", "gadget", "gecko", "gizmo",
	"harbor", "heron", "iguana", "jelly", "koala", "lemur", "mango", "narwhal",
	"nebula", "noodle", "octopus", "otter", "panda", "pepper", "phoenix", "pickle",
	"puffin", "quokka", "radar", "ranger", "rocket", "scooter", "seahorse", "skylark",
	"sprocket", "starling", "sunbeam", "taco", "thimble", "tiger", "toucan", "triton",
	"walrus", "widget", "willow", "wombat", "yeti", "zeppelin", "zigzag", "zinnia",
}

var exposeNameClosers = []string{
	"arcade", "beacon", "boogie", "bounce", "burst", "cascade", "chorus", "dash",
	"disco", "drift", "echo", "fiesta", "flare", "flash", "flight", "flip",
	"glow", "groove", "jam", "jive", "launch", "loop", "march", "orbit",
	"parade", "party", "pulse", "quest", "rally", "riot", "ripple", "rodeo",
	"roll", "rush", "serenade", "shuffle", "signal", "sketch", "spark", "sprint",
	"starlight", "stride", "sway", "swoop", "twirl", "uplift", "vibe", "voyage",
	"whirl", "wink", "zap", "zenith", "zip", "zoom", "zest", "zone",
}

const (
	defaultExposeTargetPort = "3000"
	defaultExposeTargetHost = "127.0.0.1"
)

// DefaultExposeName generates a deterministic 3-word DNS label from a target
// address and seed using FNV-1a hashing. The algorithm matches the frontend
// implementation in frontend/src/lib/exposeName.ts:buildDefaultExposeName.
func DefaultExposeName(target, rawSeed string) (string, error) {
	seed := strings.TrimSpace(rawSeed)
	if cut, ok := strings.CutPrefix(seed, "cli_"); ok {
		seed = cut
	}
	if seed == "" {
		seed = "portal"
	}

	input := []byte(seed + "|" + normalizeExposeTarget(target))
	first := fnv1a32(input, 0x811c9dc5)
	second := fnv1a32(input, 0x9e3779b9)
	third := fnv1a32(input, 0x85ebca6b)

	label := strings.Join([]string{
		exposeNameOpeners[int(first&0xff)%len(exposeNameOpeners)],
		exposeNameCenters[int(second&0xff)%len(exposeNameCenters)],
		exposeNameClosers[int(third&0xff)%len(exposeNameClosers)],
	}, "-")

	return NormalizeDNSLabel(label)
}

// normalizeExposeTarget normalizes a target address for deterministic name
// generation. Must match frontend/src/lib/exposeName.ts:normalizeExposeTarget.
func normalizeExposeTarget(raw string) string {
	trimmed := strings.TrimSpace(raw)
	candidate := trimmed
	if candidate == "" {
		candidate = defaultExposeTargetPort
	}

	if isAllDigits(candidate) {
		return defaultExposeTargetHost + ":" + candidate
	}

	if strings.Contains(candidate, "://") {
		u, err := url.Parse(candidate)
		if err != nil {
			return candidate
		}
		if (u.Scheme == "http" || u.Scheme == "https") &&
			u.Host != "" &&
			(u.Path == "" || u.Path == "/") &&
			u.RawQuery == "" &&
			u.Fragment == "" {
			return u.Host
		}
		return candidate
	}

	u, err := url.Parse("tcp://" + candidate)
	if err != nil || u.Hostname() == "" {
		return candidate
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func resolveExposeName(name, target, identityPath, identityJSON string) (string, error) {
	if name = strings.TrimSpace(name); name != "" {
		return name, nil
	}
	if identityJSON = strings.TrimSpace(identityJSON); identityJSON != "" {
		identity, err := ParseIdentityJSON(identityJSON)
		if err != nil {
			return "", err
		}
		if name := strings.TrimSpace(identity.Name); name != "" {
			return name, nil
		}
	}
	if identityPath = strings.TrimSpace(identityPath); identityPath != "" {
		identity, err := LoadIdentity(identityPath)
		switch {
		case err == nil:
			if name := strings.TrimSpace(identity.Name); name != "" {
				return name, nil
			}
		case !errors.Is(err, os.ErrNotExist):
			return "", err
		}
	}

	return DefaultExposeName(target, RandomID("cli_"))
}

func fnv1a32(data []byte, seed uint32) uint32 {
	h := seed
	for _, b := range data {
		h ^= uint32(b)
		h *= 0x01000193
	}
	return h
}
