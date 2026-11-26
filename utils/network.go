package utils

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/net/idna"
)

var (
	publicIPEndpoints = []string{
		"https://api64.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}
	publicIPv4Endpoints = []string{
		"https://api4.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://4.ident.me",
		"https://checkip.amazonaws.com",
	}
	publicIPv6Endpoints = []string{
		"https://api6.ipify.org",
		"https://ipv6.icanhazip.com",
		"https://6.ident.me",
	}
)

// SourcePrefix groups admission budgets by IPv4 address or IPv6 /64. It does
// not replace the original source used for authentication or diagnostics.
func SourcePrefix(source netip.Addr) netip.Prefix {
	if !source.IsValid() {
		return netip.Prefix{}
	}
	source = source.Unmap().WithZone("")
	bits := source.BitLen()
	if source.Is6() {
		bits = 64
	}
	return netip.PrefixFrom(source, bits).Masked()
}

var errInvalidPublicIPResponse = errors.New("invalid public ip response")

// ResolvePublicIP determines the caller's public IP address using well-known
// external services. It returns an empty string on failure.
func ResolvePublicIP(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if ip, err := resolvePublicIP(ctx, 1500*time.Millisecond, 0, publicIPEndpoints...); err == nil {
		return ip
	}
	ips, _ := resolvePublicIPFamilies(ctx, 1500*time.Millisecond, 0)
	if len(ips) == 0 {
		return ""
	}
	return ips[0]
}

// ResolvePublicIPs discovers IPv4 and IPv6 independently, returning available
// addresses in that order. After one succeeds, it waits at most one more request
// window for the other family, rather than all of that family's fallbacks.
func ResolvePublicIPs(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return resolvePublicIPFamilies(ctx, 3*time.Second, 3*time.Second)
}

type publicIPFamilyResult struct {
	index   int
	address string
	err     error
}

func resolvePublicIPFamilies(ctx context.Context, attemptTimeout, familyWait time.Duration) ([]string, error) {
	ctx, cancel := context.WithCancel(ctx)
	results := make(chan publicIPFamilyResult, 2)
	var workers sync.WaitGroup
	for i, endpoints := range [][]string{publicIPv4Endpoints, publicIPv6Endpoints} {
		workers.Go(func() {
			family := 4 + 2*i
			address, err := resolvePublicIP(ctx, attemptTimeout, family, endpoints...)
			if err != nil {
				err = fmt.Errorf("resolve public ipv%d: %w", family, err)
			}
			results <- publicIPFamilyResult{index: i, address: address, err: err}
		})
	}
	defer func() {
		cancel()
		workers.Wait()
	}()

	addresses, errs, err := collectFamilyResults(ctx, results, familyWait)
	if err != nil {
		return nil, err
	}
	return finalizeFamilyResults(ctx, addresses, errs)
}

func collectFamilyResults(ctx context.Context, results chan publicIPFamilyResult, familyWait time.Duration) ([2]string, [2]error, error) {
	var addresses [2]string
	var errs [2]error
	var remainingFamily <-chan time.Time
collect:
	for range 2 {
		select {
		case result := <-results:
			addresses[result.index], errs[result.index] = result.address, result.err
			done := result.address != "" && familyWait == 0
			if result.address != "" && remainingFamily == nil && familyWait != 0 {
				timer := time.NewTimer(familyWait)
				defer timer.Stop()
				remainingFamily = timer.C
			}
			if done {
				break collect
			}
		case <-remainingFamily:
			break collect
		case <-ctx.Done():
			return addresses, errs, ctx.Err()
		}
	}
	return addresses, errs, nil
}

func finalizeFamilyResults(ctx context.Context, addresses [2]string, errs [2]error) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var ips []string
	for _, address := range addresses {
		if address != "" {
			ips = append(ips, address)
		}
	}
	if len(ips) == 0 {
		return nil, errors.Join(errs[:]...)
	}
	return ips, nil
}

func resolvePublicIP(ctx context.Context, attemptTimeout time.Duration, family int, endpoints ...string) (string, error) {
	var lastErr error
	for _, endpoint := range endpoints {
		if err := ctx.Err(); err != nil {
			lastErr = err
			break
		}
		candidate, err := fetchResolvePublicIPEndpoint(ctx, endpoint, family, attemptTimeout)
		if err != nil {
			lastErr = err
			continue
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return candidate, nil
	}
	if lastErr == nil {
		lastErr = errors.New("resolve public ip failed")
	}
	return "", lastErr
}

func fetchResolvePublicIPEndpoint(ctx context.Context, endpoint string, family int, attemptTimeout time.Duration) (string, error) {
	client := DefaultHTTPClient
	headers := http.Header{"User-Agent": []string{"portal-tunnel"}}
	requestCtx, cancelRequest := context.WithTimeout(ctx, attemptTimeout)
	resp, err := httpDo(requestCtx, client, http.MethodGet, endpoint, nil, headers)
	if err != nil {
		cancelRequest()
		return "", err
	}
	limitedBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 256))
	_ = resp.Body.Close()
	cancelRequest()
	if err := checkEndpointTransport(resp, readErr); err != nil {
		return "", err
	}
	candidate := SanitizeReportedIP(string(limitedBody))
	if err := matchPublicIPFamily(candidate, family); err != nil {
		return "", err
	}
	return candidate, nil
}

func matchPublicIPFamily(candidate string, family int) error {
	if candidate == "" {
		return errInvalidPublicIPResponse
	}
	addressFamily := 4
	if strings.Contains(candidate, ":") {
		addressFamily = 6
	}
	if family != 0 && family != addressFamily {
		return fmt.Errorf("public ip is not ipv%d", family)
	}
	return nil

}

func checkEndpointTransport(resp *http.Response, readErr error) error {
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch public ip: unexpected status %s", resp.Status)
	}
	if readErr != nil {
		return readErr
	}
	return nil
}

func SanitizeReportedIP(raw string) string {
	ip, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || ip.Zone() != "" {
		return ""
	}
	return ip.Unmap().String()
}

var nonPublicIPv4 = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var nonPublicIPv6 = [...]netip.Prefix{
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3ffe::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

var globalIPv6 = netip.MustParsePrefix("2000::/3")

// IsPublicIP excludes locally reachable and special-use destinations,
// including IPv4-mapped IPv6 addresses, for untrusted dial destinations.
func IsPublicIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	if ip.Is4() {
		return !blockedIsPublicIPV4Address(ip)
	}
	if !globalIPv6.Contains(ip) {
		return false
	}
	return !blockedIsPublicIPV6Address(ip)
}

func blockedIsPublicIPV4Address(ip netip.Addr) bool {
	for _, prefix := range nonPublicIPv4 {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func blockedIsPublicIPV6Address(ip netip.Addr) bool {
	for _, prefix := range nonPublicIPv6 {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func NormalizeLoopbackTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if port, ok := strings.CutPrefix(raw, ":"); ok {
		if _, err := strconv.Atoi(port); err == nil {
			raw = net.JoinHostPort("127.0.0.1", port)
		}
	} else if _, err := strconv.Atoi(raw); err == nil {
		raw = net.JoinHostPort("127.0.0.1", raw)
	}
	return NormalizeTargetAddr(raw)
}

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
	if port := parsed.Port(); port != "" && !validPort(port) {
		return errRelayURLPortMustBetween1
	}
	return nil
}

// validPort reports whether port is a decimal port number from 1 to 65535.
func validPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
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
