package utils

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func LeaseHostname(name, rootHost string) (string, error) {
	label, err := NormalizeDNSLabel(name)
	if err != nil {
		return "", err
	}
	rootHost = NormalizeHostname(rootHost)
	if rootHost == "" {
		return "", errRootHostIsRequired
	}
	if ip := net.ParseIP(rootHost); ip != nil && ip.IsLoopback() {
		rootHost = "localhost"
	}
	return label + "." + rootHost, nil
}

// NormalizeServiceName normalizes a service name to a DNS label that cannot
// be mistaken for a canonical label, so a friendly hostname never collides
// with an identity-bound one.
func NormalizeServiceName(raw string) (string, error) {
	label, err := NormalizeDNSLabel(raw)
	if err != nil {
		return "", err
	}
	if hasCanonicalShape(label) {
		return "", errNameMustNotLookLikeCanonical
	}
	return label, nil
}

// ExtractCanonicalHostnameAddress extracts the 40-character hexadecimal EVM
// address embedded in the first DNS label of a canonical Portal lease hostname
// (<address>.<root>, <name>-<address>.<root>, or <hash>--<address>.<root>) and
// returns it with a lowercase 0x prefix.
func ExtractCanonicalHostnameAddress(hostname string) (string, error) {
	label, rest, ok := strings.Cut(NormalizeHostWithoutPort(hostname), ".")
	if !ok || label == "" || rest == "" || !hasCanonicalShape(label) {
		return "", errHostnameDoesNotContainCanonicalLease
	}
	address := label[len(label)-40:]
	return "0x" + strings.ToLower(address), nil
}

func hasCanonicalShape(label string) bool {
	if isHexAddress(label) {
		return true
	}
	prefix, address, ok := strings.Cut(label[max(len(label)-41, 0):], "-")
	return ok && prefix == "" && isHexAddress(address)
}

func isHexAddress(s string) bool {
	if len(s) != 40 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func canonicalNameHash(label string) string {
	h := sha256.New()
	h.Write([]byte(types.CanonicalLeaseNameHashDomain))
	h.Write([]byte{0, byte(len(label))})
	h.Write([]byte(label))
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h.Sum(nil))
	return strings.ToLower(encoded[:types.CanonicalLeaseNameHashLength])
}

// CanonicalLeaseHostname returns the identity-bound hostname for a lease.
// The full 20-byte EVM address is encoded as lowercase hexadecimal so the
// hostname cannot move between authenticated identities. When name is empty,
// it returns an address-only canonical hostname. See
// types.CanonicalLeaseNameMaxLength for how a name enters the label.
func CanonicalLeaseHostname(name, address, rootHost string) (string, error) {
	name = strings.TrimSpace(name)
	address = strings.ToLower(TrimHexPrefix(strings.TrimSpace(address)))
	if len(address) != 40 {
		return "", errAddressMustContain40HexadecimalCharacters
	}
	if _, err := hex.DecodeString(address); err != nil {
		return "", fmt.Errorf("%w: %w", errAddressMustContain40HexadecimalCharacters, err)
	}
	if name == "" {
		return LeaseHostname(address, rootHost)
	}
	label, err := NormalizeServiceName(name)
	if err != nil {
		return "", err
	}
	if len(label) <= types.CanonicalLeaseNameMaxLength {
		return LeaseHostname(label+"-"+address, rootHost)
	}
	return LeaseHostname(canonicalNameHash(label)+"--"+address, rootHost)
}
