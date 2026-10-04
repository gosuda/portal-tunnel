package policy

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Ingress resolves the client source for relay admission and diagnostics.
// Forwarded headers are trusted only when the direct peer is inside an
// explicitly configured trusted proxy CIDR.
type Ingress struct {
	trustProxyHeaders bool
	trustedProxyCIDRs []netip.Prefix
}

func NewIngress(trustProxyHeaders bool, rawTrustedProxyCIDRs string) (*Ingress, error) {
	trustedProxyCIDRs, err := parseTrustedProxyPrefixes(rawTrustedProxyCIDRs)
	if err != nil {
		return nil, fmt.Errorf("parse trusted proxy cidrs: %w", err)
	}
	return &Ingress{trustProxyHeaders: trustProxyHeaders, trustedProxyCIDRs: trustedProxyCIDRs}, nil
}

func (i *Ingress) SourceAddr(req *http.Request) netip.Addr {
	if req == nil {
		return netip.Addr{}
	}
	if i != nil && i.trustProxyHeaders && isTrustedProxyRemoteAddr(req.RemoteAddr, i.trustedProxyCIDRs) {
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			if before, _, ok := strings.Cut(xff, ","); ok {
				if ip := parseSourceAddr(before); ip.IsValid() {
					return ip
				}
			} else if ip := parseSourceAddr(xff); ip.IsValid() {
				return ip
			}
		}
		if xri := req.Header.Get("X-Real-IP"); xri != "" {
			if ip := parseSourceAddr(xri); ip.IsValid() {
				return ip
			}
		}
	}

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return parseSourceAddr(req.RemoteAddr)
	}
	return parseSourceAddr(host)
}

// ClientIP is the serialized compatibility form of SourceAddr.
func (i *Ingress) ClientIP(req *http.Request) string {
	addr := i.SourceAddr(req)
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

func isTrustedProxyRemoteAddr(remoteAddr string, trustedProxyCIDRs []netip.Prefix) bool {
	remoteIP := parseRemoteAddrIP(remoteAddr)
	if !remoteIP.IsValid() {
		return false
	}

	for _, network := range trustedProxyCIDRs {
		if network.Contains(remoteIP) {
			return true
		}
	}
	return false
}

func parseRemoteAddrIP(remoteAddr string) netip.Addr {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err == nil {
		return parseSourceAddr(host)
	}
	return parseSourceAddr(remoteAddr)
}

func parseSourceAddr(raw string) netip.Addr {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func parseTrustedProxyPrefixes(raw string) ([]netip.Prefix, error) {
	parts := utils.SplitCSV(raw)
	prefixes := make([]netip.Prefix, 0, len(parts))
	seen := make(map[netip.Prefix]struct{}, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("invalid cidr %q: %w", part, err)
		}
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefix = prefix.Masked()
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}
