// Package namespace owns Portal service names and public hostname syntax.
package namespace

import (
	"crypto/rand"
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
	errNameMustNotLookLikeUnnamedAlias           = errors.New("name must not look like an automatic alias (a hyphen and 16 base32 characters at the end)")
	errInvalidUnnamedAlias                       = errors.New("unnamed alias must be a service name ending in a 16-character base32 suffix")
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

// MatchesAlias checks an optional alias against its service name and relay
// root. An empty hostname means the alias was not granted. An unnamed service
// accepts any automatic alias under the root, because replicas share the alias
// that the first live replica chose.
func MatchesAlias(hostname, name, rootHost string) bool {
	if hostname == "" {
		return true
	}
	if strings.TrimSpace(name) == "" {
		label, _, _ := strings.Cut(hostname, ".")
		expected, err := UnnamedAliasHostname(label, rootHost)
		return err == nil && hostname == expected
	}
	expected, err := AliasHostname(name, rootHost)
	return err == nil && hostname == expected
}

// unnamedAliasSuffixBytes is the CSPRNG entropy of an automatic alias: 80
// bits, so a live alias cannot be guessed and claimed in advance.
const unnamedAliasSuffixBytes = 10

const unnamedAliasAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

var (
	unnamedAliasSuffixEncoding = base32.NewEncoding(unnamedAliasAlphabet).WithPadding(base32.NoPadding)
	unnamedAliasSuffixLength   = unnamedAliasSuffixEncoding.EncodedLen(unnamedAliasSuffixBytes)

	unnamedAliasAdjectives = [32]string{
		"bouncy", "bravo", "candy", "cosmic", "dapper", "fancy", "fizzy", "fuzzy",
		"gentle", "golden", "happy", "hyper", "jazzy", "jolly", "lucky", "magic",
		"mellow", "minty", "misty", "neon", "nova", "peppy", "pixel", "rapid",
		"snappy", "sunny", "swift", "tidy", "turbo", "vivid", "wavy", "zesty",
	}
	unnamedAliasNouns = [32]string{
		"alpaca", "badger", "banjo", "beacon", "comet", "cricket", "dragon", "falcon",
		"fox", "gecko", "harbor", "heron", "koala", "lemur", "mango", "narwhal",
		"nebula", "otter", "panda", "pepper", "phoenix", "puffin", "quokka", "radar",
		"rocket", "taco", "tiger", "toucan", "walrus", "willow", "wombat", "yeti",
	}
)

// NewUnnamedAlias returns a fresh automatic alias label for an unnamed HTTP
// service, such as sunny-otter-k7m2q6rt3vx5z4ab. The words are for reading;
// the 80-bit CSPRNG suffix makes the label unique. It holds no identity data.
func NewUnnamedAlias() string {
	var b [2 + unnamedAliasSuffixBytes]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never returns an error.
	return unnamedAliasAdjectives[b[0]%32] + "-" + unnamedAliasNouns[b[1]%32] + "-" + unnamedAliasSuffixEncoding.EncodeToString(b[2:])
}

// UnnamedAliasHostname validates an automatic alias label and composes its
// hostname. NormalizeServiceName rejects this shape, so no chosen name can
// claim an automatic alias.
func UnnamedAliasHostname(label, rootHost string) (string, error) {
	if normalized, err := utils.NormalizeDNSLabel(label); err != nil || normalized != label || hasCanonicalShape(label) || !hasUnnamedAliasShape(label) {
		return "", errInvalidUnnamedAlias
	}
	return AliasHostname(label, rootHost)
}

// hasUnnamedAliasShape reports a label that ends in -<16 base32 characters>.
func hasUnnamedAliasShape(label string) bool {
	i := strings.LastIndexByte(label, '-')
	return i > 0 && len(label)-i-1 == unnamedAliasSuffixLength && strings.Trim(label[i+1:], unnamedAliasAlphabet) == ""
}

// NormalizeServiceName normalizes a service name to a DNS label that cannot
// be mistaken for a canonical label or an automatic alias, so a friendly
// hostname never collides with an identity-bound or automatic one.
func NormalizeServiceName(raw string) (string, error) {
	label, err := utils.NormalizeDNSLabel(raw)
	if err != nil {
		return "", err
	}
	if hasCanonicalShape(label) {
		return "", errNameMustNotLookLikeCanonical
	}
	if hasUnnamedAliasShape(label) {
		return "", errNameMustNotLookLikeUnnamedAlias
	}
	return label, nil
}

// CanonicalAddress extracts the 40-character hexadecimal EVM
// address from the second label of a service.address.root hostname, with a lowercase 0x prefix.
// Routing must additionally validate depth relative to its configured root.
func CanonicalAddress(hostname string) (string, error) {
	label, rest, ok := strings.Cut(utils.NormalizeHostWithoutPort(hostname), ".")
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
