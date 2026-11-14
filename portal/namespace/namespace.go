// Package namespace owns Portal service names and public hostname syntax.
package namespace

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errRootHostIsRequired                        = errors.New("root host is required")
	errNameMustNotLookLikeCanonical              = errors.New("name must not look like a canonical hostname (40 hexadecimal characters, alone or after a hyphen)")
	errHostnameDoesNotContainCanonicalLease      = errors.New("hostname does not contain a canonical lease address")
	errAddressMustContain40HexadecimalCharacters = errors.New("address must contain 40 hexadecimal characters")
)

// AliasHostname composes a single DNS label under the relay root.
func AliasHostname(name, rootHost string) (string, error) {
	label, err := utils.NormalizeDNSLabel(name)
	if err != nil {
		return "", err
	}
	rootHost = utils.NormalizeHostname(rootHost)
	if rootHost == "" {
		return "", errRootHostIsRequired
	}
	if ip := net.ParseIP(rootHost); ip != nil && ip.IsLoopback() {
		rootHost = "localhost"
	}
	return label + "." + rootHost, nil
}

// MatchesAlias checks an optional alias against its service name and legacy
// canonical origin. An empty hostname means the alias was not granted.
func MatchesAlias(hostname, name, legacyHostname string) bool {
	if hostname == "" {
		return true
	}
	label, err := utils.NormalizeDNSLabel(name)
	if err != nil || label == "" {
		return false
	}
	_, root, ok := strings.Cut(legacyHostname, ".")
	return ok && hostname == label+"."+root
}

// AddressParent returns the address.<root> DNS parent of a Local TLS hostname.
// Callers must first validate the hostname with IsLocalTLSHostname or use a
// canonical hostname derived for a negotiated Local TLS lease.
func AddressParent(hostname string) string {
	_, parent, _ := strings.Cut(hostname, ".")
	return parent
}

// IsAddressHostname recognizes the address-only legacy hostname at this root.
func IsAddressHostname(hostname, rootHost string) bool {
	label, _, found := strings.Cut(hostname, ".")
	if !found {
		return false
	}
	parent, err := LegacyHostname("", label, rootHost)
	return err == nil && parent == hostname
}

// NormalizeServiceName normalizes a service name to a DNS label that cannot
// be mistaken for a canonical label, so a friendly hostname never collides
// with an identity-bound one.
func NormalizeServiceName(raw string) (string, error) {
	label, err := utils.NormalizeDNSLabel(raw)
	if err != nil {
		return "", err
	}
	if hasCanonicalShape(label) {
		return "", errNameMustNotLookLikeCanonical
	}
	return label, nil
}

// CanonicalAddress extracts the 40-character hexadecimal EVM
// address from the second label of a service.address.root hostname, or the
// first label of a legacy canonical hostname, with a lowercase 0x prefix.
// Routing must additionally validate depth relative to its configured root.
func CanonicalAddress(hostname string) (string, error) {
	label, rest, ok := strings.Cut(utils.NormalizeHostWithoutPort(hostname), ".")
	if !ok || label == "" || rest == "" {
		return "", errHostnameDoesNotContainCanonicalLease
	}
	// Service labels cannot have the legacy canonical shape. Check it first so
	// a relay root beginning with a hexadecimal label cannot replace the owner.
	if hasCanonicalShape(label) {
		return "0x" + strings.ToLower(label[len(label)-40:]), nil
	}
	if address, root, found := strings.Cut(rest, "."); found && root != "" && isHexAddress(address) {
		if normalized, err := NormalizeServiceName(label); err == nil && normalized == label {
			return "0x" + strings.ToLower(address), nil
		}
	}
	return "", errHostnameDoesNotContainCanonicalLease
}

// LocalTLSHostname binds an exact service label and wallet under the relay
// root. The reserved default label represents an unnamed service.
func LocalTLSHostname(name, address, rootHost string) (string, error) {
	label := types.UnnamedServiceLabel
	if strings.TrimSpace(name) != "" {
		var err error
		label, err = NormalizeServiceName(name)
		if err != nil {
			return "", err
		}
		if label == types.UnnamedServiceLabel {
			return "", fmt.Errorf("service name %q is reserved for unnamed services", label)
		}
	}
	addressHost, err := LegacyHostname("", address, rootHost)
	if err != nil {
		return "", err
	}
	hostname := label + "." + addressHost
	if len(hostname) > 253 {
		return "", fmt.Errorf("local TLS hostname exceeds DNS length limit")
	}
	return hostname, nil
}

// IsLocalTLSHostname recognizes the exact two-label namespace relative to the
// configured root, never by an absolute DNS depth.
func IsLocalTLSHostname(hostname, rootHost string) bool {
	root := utils.NormalizeHostWithoutPort(rootHost)
	if ip := net.ParseIP(root); ip != nil && ip.IsLoopback() {
		root = "localhost"
	}
	relative, ok := strings.CutSuffix(utils.NormalizeHostWithoutPort(hostname), "."+root)
	if !ok || root == "" {
		return false
	}
	labels := strings.Split(relative, ".")
	if len(labels) != 2 || !isHexAddress(labels[1]) {
		return false
	}
	label, err := NormalizeServiceName(labels[0])
	return err == nil && label == labels[0]
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

// LegacyHostname returns the identity-bound hostname for a lease.
// The full 20-byte EVM address is encoded as lowercase hexadecimal so the
// hostname cannot move between authenticated identities. When name is empty,
// it returns an address-only canonical hostname. See
// types.CanonicalLeaseNameMaxLength for how a name enters the label.
func LegacyHostname(name, address, rootHost string) (string, error) {
	name = strings.TrimSpace(name)
	address = strings.ToLower(utils.TrimHexPrefix(strings.TrimSpace(address)))
	if len(address) != 40 {
		return "", errAddressMustContain40HexadecimalCharacters
	}
	if _, err := hex.DecodeString(address); err != nil {
		return "", fmt.Errorf("%w: %w", errAddressMustContain40HexadecimalCharacters, err)
	}
	if name == "" {
		return AliasHostname(address, rootHost)
	}
	label, err := NormalizeServiceName(name)
	if err != nil {
		return "", err
	}
	if len(label) <= types.CanonicalLeaseNameMaxLength {
		return AliasHostname(label+"-"+address, rootHost)
	}
	return AliasHostname(canonicalNameHash(label)+"--"+address, rootHost)
}
