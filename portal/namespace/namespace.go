// Package namespace owns Portal service names and public hostname syntax.
package namespace

import (
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
	label, err := types.NormalizeDNSLabel(name)
	if err != nil {
		return "", err
	}
	rootHost = types.NormalizeHostname(rootHost)
	if rootHost == "" {
		return "", errRootHostIsRequired
	}
	if ip := net.ParseIP(rootHost); ip != nil && ip.IsLoopback() {
		rootHost = "localhost"
	}
	return label + "." + rootHost, nil
}

// MatchesAlias checks an optional alias against its service name and relay root. An empty hostname means the alias was not granted.
func MatchesAlias(hostname, name, rootHost string) bool {
	if hostname == "" {
		return true
	}
	expected, err := AliasHostname(name, rootHost)
	return err == nil && hostname == expected
}

// NormalizeServiceName normalizes a service name to a DNS label that cannot
// be mistaken for a canonical label, so a friendly hostname never collides
// with an identity-bound one.
func NormalizeServiceName(raw string) (string, error) {
	label, err := types.NormalizeDNSLabel(raw)
	if err != nil {
		return "", err
	}
	if hasCanonicalShape(label) {
		return "", errNameMustNotLookLikeCanonical
	}
	return label, nil
}

// CanonicalAddress extracts the 40-character hexadecimal EVM
// address from the second label of a service.address.root hostname, with a lowercase 0x prefix.
// Routing must additionally validate depth relative to its configured root.
func CanonicalAddress(hostname string) (string, error) {
	label, rest, ok := strings.Cut(types.NormalizeHostWithoutPort(hostname), ".")
	if !ok || label == "" || rest == "" {
		return "", errHostnameDoesNotContainCanonicalLease
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
	address = strings.ToLower(utils.TrimHexPrefix(strings.TrimSpace(address)))
	if !isHexAddress(address) {
		return "", errAddressMustContain40HexadecimalCharacters
	}
	addressHost, err := AliasHostname(address, rootHost)
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
	root := types.NormalizeHostWithoutPort(rootHost)
	if ip := net.ParseIP(root); ip != nil && ip.IsLoopback() {
		root = "localhost"
	}
	relative, ok := strings.CutSuffix(types.NormalizeHostWithoutPort(hostname), "."+root)
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
