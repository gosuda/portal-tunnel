package utils

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/idna"
)

func SplitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func TrimHexPrefix(raw string) string {
	if len(raw) >= 2 && raw[0] == '0' && (raw[1] == 'x' || raw[1] == 'X') {
		return raw[2:]
	}
	return raw
}

func ParseCIDRs(raw string) ([]*net.IPNet, error) {
	parts := SplitCSV(raw)
	if len(parts) == 0 {
		return nil, nil
	}

	cidrs := make([]*net.IPNet, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		_, network, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid cidr %q: %w", part, err)
		}
		key := network.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		cidrs = append(cidrs, network)
	}
	return cidrs, nil
}

func NormalizeDNSLabel(raw string) (string, error) {
	label := sanitizeDNSLabelInput(raw)
	if label == "" {
		return "", errors.New("name is required")
	}

	if !isPlainDNSLabel(label) {
		ascii, err := idna.Lookup.ToASCII(label)
		if err != nil {
			return "", errors.New("name is invalid")
		}
		label = NormalizeHostname(ascii)
	}
	if strings.Contains(label, ".") {
		return "", errors.New("name must be a single dns label")
	}
	if len(label) > 63 {
		return "", errors.New("name must be 63 characters or fewer")
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return "", errors.New("name must not start or end with hyphen")
	}
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return "", errors.New("name must contain only letters, numbers, or hyphen")
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
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return true
}

func NormalizeRelayURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("relay url is empty")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + strings.TrimPrefix(trimmed, "//")
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("parse relay url %q: %w", raw, err)
	}
	if parsed.Host == "" && parsed.Path != "" && !strings.Contains(parsed.Path, "/") {
		parsed, err = url.Parse("https://" + strings.TrimSpace(parsed.Path))
		if err != nil {
			return "", fmt.Errorf("parse relay url %q: %w", raw, err)
		}
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("relay url host is empty: %q", raw)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return "", fmt.Errorf("relay url must use https: %q", raw)
	}

	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if strings.HasSuffix(strings.ToLower(parsed.Path), "/relay") {
		parsed.Path = strings.TrimSuffix(parsed.Path, "/relay")
	}
	return parsed.String(), nil
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

func NormalizeChildHostnames(inputs []string, baseDomain string) []string {
	if len(inputs) == 0 {
		return nil
	}

	baseDomain = NormalizeBaseDomain(baseDomain)
	return normalizeUniqueStrings(inputs, func(input string) string {
		hostname := NormalizeHostname(input)
		if hostname == "" || hostname == baseDomain || !HostnameMatchesBaseDomain(hostname, baseDomain) {
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
			normalized, err := NormalizeRelayURL(part)
			if err != nil {
				return nil, err
			}
			out = append(out, normalized)
		}
	}

	return normalizeUniqueStrings(out, strings.TrimSpace), nil
}

func FilterRelayURLs(inputs, excluded []string) []string {
	if len(inputs) == 0 {
		return nil
	}
	if len(excluded) == 0 {
		return append([]string(nil), inputs...)
	}

	skip := make(map[string]struct{}, len(excluded))
	for _, input := range excluded {
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}
		skip[input] = struct{}{}
	}

	filtered := make([]string, 0, len(inputs))
	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}
		if _, ok := skip[input]; ok {
			continue
		}
		filtered = append(filtered, input)
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func RemoveRelayURL(inputs []string, target string) []string {
	if len(inputs) == 0 {
		return nil
	}

	target = strings.TrimSpace(target)
	if target == "" {
		return append([]string(nil), inputs...)
	}

	filtered := make([]string, 0, len(inputs))
	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" || input == target {
			continue
		}
		filtered = append(filtered, input)
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func MergeRelayURLs(current, excluded, inputs []string) ([]string, error) {
	merged, err := NormalizeRelayURLs(append(append([]string(nil), current...), inputs...)...)
	if err != nil {
		return nil, err
	}
	if len(excluded) == 0 {
		return merged, nil
	}

	excluded, err = NormalizeRelayURLs(excluded...)
	if err != nil {
		return nil, err
	}

	return FilterRelayURLs(merged, excluded), nil
}

func ExcludeLocalRelayURLs(inputs ...string) ([]string, error) {
	normalized, err := NormalizeRelayURLs(inputs...)
	if err != nil {
		return nil, err
	}
	if len(normalized) == 0 {
		return nil, nil
	}

	filtered := normalized[:0]
	for _, input := range normalized {
		parsed, err := url.Parse(input)
		if err != nil {
			return nil, fmt.Errorf("parse relay url %q: %w", input, err)
		}
		if IsLocalRelayHost(parsed.Hostname()) {
			continue
		}
		filtered = append(filtered, input)
	}
	if len(filtered) == 0 {
		return nil, nil
	}
	return filtered, nil
}

func LeaseHostname(name, rootHost string) (string, error) {
	label, err := NormalizeDNSLabel(name)
	if err != nil {
		return "", err
	}
	rootHost = NormalizeHostname(rootHost)
	if rootHost == "" {
		return "", errors.New("root host is required")
	}
	return label + "." + rootHost, nil
}

func DecodeBase64URLString(encoded string) (string, error) {
	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err == nil {
		return string(decoded), nil
	}

	decoded, err = base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func NormalizeTargetAddr(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("target address is required")
	}

	if strings.Contains(raw, "://") {
		targetURL, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("parse target url: %w", err)
		}
		if !strings.EqualFold(targetURL.Scheme, "http") && !strings.EqualFold(targetURL.Scheme, "https") {
			return "", fmt.Errorf("unsupported target url scheme %q", targetURL.Scheme)
		}
		if targetURL.Host == "" {
			return "", errors.New("target url host is empty")
		}
		if targetURL.Path != "" && targetURL.Path != "/" {
			return "", errors.New("target url path is not supported")
		}
		if targetURL.RawQuery != "" {
			return "", errors.New("target url query is not supported")
		}
		if targetURL.Fragment != "" {
			return "", errors.New("target url fragment is not supported")
		}
		raw = targetURL.Host
	}

	if _, _, err := net.SplitHostPort(raw); err == nil {
		return raw, nil
	}
	if strings.Count(raw, ":") == 0 {
		return net.JoinHostPort(raw, "80"), nil
	}
	if ip := net.ParseIP(raw); ip != nil {
		return net.JoinHostPort(raw, "80"), nil
	}
	return "", fmt.Errorf("invalid target address %q", raw)
}

func HostPortOrLoopback(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func EnsurePort(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, "443")
}

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

func AddrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func ValidateIPv4(raw string) error {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid ipv4 address: %q", raw)
	}
	return nil
}

func RandomHex(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func CertPoolFromPEM(rootCAPEM []byte) (*x509.CertPool, error) {
	if len(rootCAPEM) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootCAPEM) {
		return nil, errors.New("failed to parse relay root ca")
	}
	return pool, nil
}

func ParseCertificatePEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no pem block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func ParsePrivateKeyPEM(keyPEM []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("invalid private key pem")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch typed := key.(type) {
		case *ecdsa.PrivateKey:
			return typed, nil
		case *rsa.PrivateKey:
			return typed, nil
		}
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key type")
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

func NormalizeIPPrefixes(inputs []string) []string {
	return normalizeUniqueStrings(inputs, func(input string) string {
		input = strings.TrimSpace(input)
		if input == "" {
			return ""
		}
		prefix, err := netip.ParsePrefix(input)
		if err != nil {
			return ""
		}
		return prefix.String()
	})
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

func MarshalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

func UnmarshalJSON(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func PutUint32(b []byte, v uint32) {
	binary.BigEndian.PutUint32(b, v)
}

func Uint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}
