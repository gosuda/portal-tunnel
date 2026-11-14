package utils

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

var (
	errAddressMustContain40HexadecimalCharacters = errors.New("address must contain 40 hexadecimal characters")
	errTargetAddressIsRequired                   = errors.New("target address is required")
	errTargetURLHostIsEmpty                      = errors.New("target url host is empty")
	errTargetURLPathNotSupported                 = errors.New("target url path is not supported")
	errTargetURLQueryNotSupported                = errors.New("target url query is not supported")
	errTargetURLFragmentNotSupported             = errors.New("target url fragment is not supported")
)

func SplitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return CompactStrings(strings.Split(raw, ","))
}

// CompactStrings returns values without surrounding spaces and without the
// empty ones, in a new slice; nil when none is left.
func CompactStrings(values []string) []string {
	var out []string
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func TrimHexPrefix(raw string) string {
	if len(raw) < 2 || raw[0] != '0' {
		return raw
	}
	if raw[1] == 'x' || raw[1] == 'X' {
		return raw[2:]
	}
	return raw
}

func NormalizeChildHostnames(inputs []string, baseDomain string) []string {
	if len(inputs) == 0 {
		return nil
	}

	baseDomain = types.NormalizeBaseDomain(baseDomain)
	return normalizeUniqueStrings(inputs, func(input string) string {
		hostname := types.NormalizeHostname(input)
		if hostname == "" || hostname == baseDomain || !types.HostnameMatchesBaseDomain(hostname, baseDomain) {
			return ""
		}
		return hostname
	})
}

func NormalizeURLPath(raw string) string {
	clean := path.Clean(strings.TrimSpace(raw))
	if clean == "." || clean == "" {
		return "/"
	}
	if !strings.HasPrefix(clean, "/") {
		clean = "/" + clean
	}
	// Prevent scheme-relative or otherwise ambiguous paths like "//example" or "/\example".
	if len(clean) > 1 && (clean[1] == '/' || clean[1] == '\\') {
		clean = "/"
	}
	if clean != "/" {
		clean = strings.TrimSuffix(clean, "/")
	}
	return clean
}

func NormalizeRelayURLs(inputs ...string) ([]string, error) {
	out := make([]string, 0, len(inputs))

	for _, input := range inputs {
		for _, part := range SplitCSV(input) {
			normalized, err := types.NormalizeRelayURL(part)
			if err != nil {
				return nil, err
			}
			out = append(out, normalized)
		}
	}

	return normalizeUniqueStrings(out, strings.TrimSpace), nil
}

func NormalizeTargetAddr(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errTargetAddressIsRequired
	}
	if strings.Contains(raw, "://") {
		host, err := splitNormalizeTargetAddrHost(raw)
		if err != nil {
			return "", err
		}
		raw = host
	}
	return formatNormalizeTargetAddrEndpoint(raw)
}

func splitNormalizeTargetAddrHost(raw string) (string, error) {
	targetURL, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse target url: %w", err)
	}
	if !strings.EqualFold(targetURL.Scheme, "http") && !strings.EqualFold(targetURL.Scheme, "https") {
		return "", fmt.Errorf("unsupported target url scheme %q", targetURL.Scheme)
	}
	if targetURL.Host == "" {
		return "", errTargetURLHostIsEmpty
	}
	if targetURL.Path != "" && targetURL.Path != "/" {
		return "", errTargetURLPathNotSupported
	}
	if targetURL.RawQuery != "" {
		return "", errTargetURLQueryNotSupported
	}
	if targetURL.Fragment != "" {
		return "", errTargetURLFragmentNotSupported
	}
	return targetURL.Host, nil
}

func formatNormalizeTargetAddrEndpoint(raw string) (string, error) {
	if _, _, err := net.SplitHostPort(raw); err == nil {
		return raw, nil
	}
	if strings.Count(raw, ":") == 0 && !strings.ContainsAny(raw, "[]") {
		return net.JoinHostPort(raw, "80"), nil
	}
	host := raw
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(host, "80"), nil
	}
	return "", fmt.Errorf("invalid target address %q", raw)
}

// IsLoopbackHost reports whether hostname is a loopback address: "localhost",
// "::1", or a valid IP address that reports true from IsLoopback().
func IsLoopbackHost(hostname string) bool {
	if hostname == "localhost" || hostname == "::1" {
		return true
	}
	if addr, err := netip.ParseAddr(hostname); err == nil && addr.IsLoopback() {
		return true
	}
	return false
}

func EnsurePort(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	return net.JoinHostPort(host, "443")
}

func SleepOrDone(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func RandomID(prefix string) string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return prefix + hex.EncodeToString(buf)
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

func IntOrDefault(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}
