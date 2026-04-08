package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
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

func NormalizeStoredIdentity(identity types.Identity) (types.Identity, error) {
	normalized := identity.Copy()
	normalized.Name = strings.TrimSpace(normalized.Name)
	normalized.Address = strings.TrimSpace(normalized.Address)
	normalized.PublicKey = strings.TrimSpace(normalized.PublicKey)
	normalized.PrivateKey = strings.TrimSpace(normalized.PrivateKey)

	if normalized.PrivateKey != "" {
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
		return normalized, nil
	}

	if normalized.PublicKey != "" {
		address, err := AddressFromCompressedPublicKeyHex(normalized.PublicKey)
		if err != nil {
			return types.Identity{}, err
		}
		normalized.PublicKey = strings.ToLower(TrimHexPrefix(normalized.PublicKey))
		if normalized.Address == "" {
			normalized.Address = address
			return normalized, nil
		}
		if !strings.EqualFold(normalized.Address, address) {
			return types.Identity{}, errors.New("identity address does not match public key")
		}
		normalized.Address = address
		return normalized, nil
	}

	if normalized.Address != "" {
		address, err := NormalizeEVMAddress(normalized.Address)
		if err != nil {
			return types.Identity{}, err
		}
		normalized.Address = address
	}
	return normalized, nil
}

type storedIdentity struct {
	Name       string `json:"name,omitempty"`
	Address    string `json:"address,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
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

func LoadIdentity(path string) (types.Identity, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return types.Identity{}, errors.New("identity path is required")
	}
	var payload storedIdentity
	raw, err := os.ReadFile(path)
	if err != nil {
		return types.Identity{}, fmt.Errorf("read identity file: %w", err)
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return types.Identity{}, fmt.Errorf("read identity file: %w", err)
	}
	return NormalizeStoredIdentity(types.Identity{
		Name:       payload.Name,
		Address:    payload.Address,
		PublicKey:  payload.PublicKey,
		PrivateKey: payload.PrivateKey,
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

// LoadOrCreateIdentity loads an existing identity from path, or creates and
// saves a new one if the file does not exist. The returned bool is true only
// when a new identity was generated; callers can use it to emit a one-time
// creation log without misleading operators on subsequent starts.
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

func ResolveListenerIdentity(identity types.Identity, target, identityPath, identityJSON string) (types.Identity, error) {
	identityPath = strings.TrimSpace(identityPath)
	identityJSON = strings.TrimSpace(identityJSON)
	resolvedName, err := resolveExposeName(identity.Name, target, identityPath, identityJSON)
	if err != nil {
		return types.Identity{}, err
	}
	identity.Name = resolvedName
	if identityJSON != "" {
		provided, err := ParseIdentityJSON(identityJSON)
		if err != nil {
			return types.Identity{}, err
		}
		provided.Name = identity.Name
		if identityPath != "" {
			if err := SaveIdentity(identityPath, provided); err != nil {
				return types.Identity{}, fmt.Errorf("persist identity: %w", err)
			}
			provided, err = LoadIdentity(identityPath)
			if err != nil {
				return types.Identity{}, fmt.Errorf("load identity: %w", err)
			}
		}
		resolved, err := ResolveLeaseIdentity(provided)
		return resolved, err
	}
	if identityPath == "" {
		resolved, err := ResolveLeaseIdentity(identity)
		return resolved, err
	}

	loaded, _, err := LoadOrCreateIdentity(identityPath, identity)
	if err != nil {
		return types.Identity{}, err
	}
	resolved, err := ResolveLeaseIdentity(loaded)
	if err != nil {
		return types.Identity{}, err
	}
	return resolved, nil
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
