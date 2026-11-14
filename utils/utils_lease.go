package utils

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// LocalTLSLeaseHostname binds an exact service label and wallet under the relay
// root. The reserved default label represents an unnamed service.
func LocalTLSLeaseHostname(name, address, rootHost string) (string, error) {
	label := types.UnnamedServiceLabel
	if strings.TrimSpace(name) != "" {
		var err error
		label, err = types.NormalizeServiceName(name)
		if err != nil {
			return "", err
		}
		if label == types.UnnamedServiceLabel {
			return "", fmt.Errorf("service name %q is reserved for unnamed services", label)
		}
	}
	addressHost, err := CanonicalLeaseHostname("", address, rootHost)
	if err != nil {
		return "", err
	}
	hostname := label + "." + addressHost
	if len(hostname) > 253 {
		return "", fmt.Errorf("local TLS hostname exceeds DNS length limit")
	}
	return hostname, nil
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
		return types.LeaseHostname(address, rootHost)
	}
	label, err := types.NormalizeServiceName(name)
	if err != nil {
		return "", err
	}
	if len(label) <= types.CanonicalLeaseNameMaxLength {
		return types.LeaseHostname(label+"-"+address, rootHost)
	}
	return types.LeaseHostname(canonicalNameHash(label)+"--"+address, rootHost)
}
