package identity

import (
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
)

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

// NormalizeIdentityKeys returns the deduplicated, canonical form of
// "name\x1faddress" identity keys, dropping malformed entries.
func NormalizeIdentityKeys(inputs []string) []string {
	return normalizeUniqueStrings(inputs, normalizeIdentityKey)
}

// NormalizeIdentityKeyBPS returns the canonical form of per-identity-key
// bandwidth limits, dropping malformed entries.
func NormalizeIdentityKeyBPS(inputs map[string]int64) map[string]int64 {
	if len(inputs) == 0 {
		return nil
	}
	out := make(map[string]int64, len(inputs))
	for key, bps := range inputs {
		normalized := normalizeIdentityKey(key)
		if normalized == "" || bps <= 0 {
			continue
		}
		if _, ok := out[normalized]; ok {
			continue
		}
		out[normalized] = bps
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
