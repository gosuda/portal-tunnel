package utils

import (
	"encoding/base32"
	"errors"
	"strings"
)

// NormalizeIVNPDestination accepts only a canonical destination hash, never a
// hostname requiring an application-owned resolver or an intermediate route.
func NormalizeIVNPDestination(destination string) (string, error) {
	destination = strings.ToLower(strings.TrimSpace(destination))
	label, ok := strings.CutSuffix(destination, ".b32.i2p")
	if !ok || len(label) != 52 {
		return "", errors.New("ivnp destination must be a 32-byte b32.i2p hash")
	}
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	raw, err := encoding.DecodeString(strings.ToUpper(label))
	if err != nil || len(raw) != 32 || strings.ToLower(encoding.EncodeToString(raw)) != label {
		return "", errors.New("invalid ivnp destination hash")
	}
	return destination, nil
}
