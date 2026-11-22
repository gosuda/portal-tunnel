package utils

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

var (
	errNameIsRequired                    = errors.New("name is required")
	errNameIsInvalid                     = errors.New("name is invalid")
	errNameMustSingleDNSLabel            = errors.New("name must be a single dns label")
	errNameMust63CharactersOrFewer       = errors.New("name must be 63 characters or fewer")
	errNameMustNotStartOrEnd             = errors.New("name must not start or end with hyphen")
	errNameMustContainOnlyLettersNumbers = errors.New("name must contain only letters, numbers, or hyphen")
	errRelayURLIsEmpty                   = errors.New("relay url is empty")
	errRelayURLIsInvalid                 = errors.New("relay url is invalid")
	errRelayURLHostIsEmpty               = errors.New("relay url host is empty")
	errRelayURLMustNotIncludeCredentials = errors.New("relay url must not include credentials")
	errRelayURLHasInvalidPort            = errors.New("relay url has an invalid port")
	errRelayURLPortMustBetween1          = errors.New("relay url port must be between 1 and 65535")
	errRelayURLMustUseHTTPS              = errors.New("relay url must use https")
)

func NormalizeDNSLabel(raw string) (string, error) {
	label := sanitizeDNSLabelInput(raw)
	if label == "" {
		return "", errNameIsRequired
	}

	if !isPlainDNSLabel(label) {
		ascii, err := idna.Lookup.ToASCII(label)
		if err != nil {
			return "", fmt.Errorf("%w: %w", errNameIsInvalid, err)
		}
		label = NormalizeHostname(ascii)
	}
	if strings.Contains(label, ".") {
		return "", errNameMustSingleDNSLabel
	}
	if len(label) > 63 {
		return "", errNameMust63CharactersOrFewer
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return "", errNameMustNotStartOrEnd
	}
	for _, r := range label {
		validRune := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-'
		if validRune {
			continue
		}
		return "", errNameMustContainOnlyLettersNumbers
	}
	return label, nil
}

func sanitizeDNSLabelInput(raw string) string {
	input := strings.TrimSpace(strings.ToLower(raw))
	if input == "" {
		return ""
	}

	var b strings.Builder
	b.Grow(len(input))
	previousHyphen := false

	for _, r := range input {
		if r == '-' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			previousHyphen = false
			continue
		}
		if previousHyphen {
			continue
		}
		b.WriteByte('-')
		previousHyphen = true
	}

	return strings.Trim(b.String(), "-")
}

func isPlainDNSLabel(label string) bool {
	for _, r := range label {
		validRune := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-'
		if validRune {
			continue
		}
		return false
	}
	return true
}

func NormalizeRelayURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errRelayURLIsEmpty
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + strings.TrimPrefix(trimmed, "//")
	}
	parsed, err := parseNormalizeRelayURLCandidate(trimmed)
	if err != nil {
		return "", err
	}
	if err := enforceNormalizeRelayURLScheme(parsed); err != nil {
		return "", err
	}
	return canonicalRelayURL(parsed), nil
}

// NormalizeRelayURLs normalizes a list of relay URLs or comma-separated URL
// strings, dropping duplicates and preserving first-seen order.
func NormalizeRelayURLs(inputs ...string) ([]string, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	var out []string
	seen := make(map[string]struct{})
	for _, input := range inputs {
		for _, part := range strings.Split(input, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			normalized, err := NormalizeRelayURL(part)
			if err != nil {
				return nil, err
			}
			if _, ok := seen[normalized]; !ok {
				seen[normalized] = struct{}{}
				out = append(out, normalized)
			}
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func parseNormalizeRelayURLCandidate(trimmed string) (*url.URL, error) {
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errRelayURLIsInvalid, err)
	}
	if parsed.Host == "" && parsed.Path != "" && !strings.Contains(parsed.Path, "/") {
		reparsed, err := url.Parse("https://" + strings.TrimSpace(parsed.Path))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errRelayURLIsInvalid, err)
		}
		return reparsed, nil
	}
	return parsed, nil
}

func enforceNormalizeRelayURLScheme(parsed *url.URL) error {
	if parsed.Host == "" {
		return errRelayURLHostIsEmpty
	}
	if parsed.User != nil {
		return errRelayURLMustNotIncludeCredentials
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return errRelayURLHasInvalidPort
	}
	if err := checkRelayPort(parsed); err != nil {
		return err
	}
	if strings.EqualFold(parsed.Scheme, "http") && IsLocalRelayHost(parsed.Hostname()) {
		parsed.Scheme = "https"
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return errRelayURLMustUseHTTPS
	}
	return nil
}

func checkRelayPort(parsed *url.URL) error {
	port := parsed.Port()
	if port == "" {
		return nil
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("%w: %w", errRelayURLPortMustBetween1, err)
	}
	if n < 1 || n > 65535 {
		return errRelayURLPortMustBetween1
	}
	return nil
}

func canonicalRelayURL(parsed *url.URL) string {
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if strings.HasSuffix(strings.ToLower(parsed.Path), "/relay") {
		parsed.Path = strings.TrimSuffix(parsed.Path, "/relay")
	}
	return parsed.String()
}

func PortalRootHost(portalURL string) string {
	u, err := url.Parse(strings.TrimSpace(portalURL))
	if err != nil || u.Host == "" {
		return ""
	}
	return NormalizeHostname(u.Hostname())
}

func NormalizeHostname(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

// NormalizeHostWithoutPort normalizes a hostname and drops its port, if any.
func NormalizeHostWithoutPort(hostname string) string {
	hostname = strings.TrimSpace(hostname)
	if host, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = host
	}
	return NormalizeHostname(hostname)
}

func NormalizeBaseDomain(domain string) string {
	return strings.TrimPrefix(NormalizeHostname(domain), "*.")
}

func DomainCandidates(domain string) []string {
	normalized := NormalizeHostname(domain)
	parts := strings.Split(normalized, ".")
	if len(parts) < 2 {
		return nil
	}

	candidates := make([]string, 0, len(parts)-1)
	for i := range len(parts) - 1 {
		candidates = append(candidates, strings.Join(parts[i:], "."))
	}
	return candidates
}

func HostnameMatchesBaseDomain(hostname, baseDomain string) bool {
	hostname = NormalizeHostname(hostname)
	baseDomain = NormalizeBaseDomain(baseDomain)
	if hostname == "" || baseDomain == "" {
		return false
	}
	return hostname == baseDomain || strings.HasSuffix(hostname, "."+baseDomain)
}

func HostnameMatchesPattern(pattern, hostname string) bool {
	pattern = NormalizeHostname(pattern)
	hostname = NormalizeHostname(hostname)
	if pattern == "" || hostname == "" {
		return false
	}
	if pattern == hostname {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := strings.TrimPrefix(pattern, "*.")
	if !strings.Contains(suffix, ".") {
		return false
	}
	_, rest, ok := strings.Cut(hostname, ".")
	return ok && rest == suffix
}

// IsLocalRelayHost identifies the existing local-development TLS trust exception.
func IsLocalRelayHost(host string) bool {
	host = NormalizeHostname(host)
	switch host {
	case "", "localhost":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return strings.HasSuffix(host, ".localhost")
}

// IsLocalOnlyRelayHost rejects locally scoped destinations for public relay
// discovery and overlay gateways. It must not widen local TLS trust.
// Other non-public IP literals and resolved addresses still require IsPublicIP.
func IsLocalOnlyRelayHost(host string) bool {
	host = NormalizeHostname(host)
	return IsLocalRelayHost(host) || strings.Contains(host, "%") || strings.HasSuffix(host, ".local")
}
