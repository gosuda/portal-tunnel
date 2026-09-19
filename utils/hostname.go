package utils

import (
	"crypto/sha256"
	"encoding/base64"
)

// HostnameHash returns the validation hash of a lease's public fallback
// hostname. The relay stores it instead of the plaintext hostname for
// hash-routed leases and matches plaintext lookups against it.
func HostnameHash(hostname string) string {
	hostname = NormalizeHostname(hostname)
	if hostname == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("portal hostname hash v1\x00" + hostname))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
