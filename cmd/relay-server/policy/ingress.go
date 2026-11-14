package policy

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Ingress resolves the client source for relay admission and diagnostics, and
// decides which sources may run tunnels. Forwarded headers are trusted only
// when the direct peer is inside an explicitly configured trusted proxy CIDR.
type Ingress struct {
	trustProxyHeaders bool
	trustedProxyCIDRs []netip.Prefix
	tunnelSourceCIDRs []netip.Prefix
}

// NewIngress reads both lists as comma-separated CIDRs. A blank tunnel source
// setting lets every source run tunnels; a non-blank one must name at least one
// network, so a mistyped value cannot open the relay.
func NewIngress(trustProxyHeaders bool, rawTrustedProxyCIDRs, rawTunnelSourceCIDRs string) (*Ingress, error) {
	trustedProxyCIDRs, err := parseCIDRs(rawTrustedProxyCIDRs)
	if err != nil {
		return nil, fmt.Errorf("parse trusted proxy cidrs: %w", err)
	}
	tunnelSourceCIDRs, err := parseCIDRs(rawTunnelSourceCIDRs)
	if err != nil {
		return nil, fmt.Errorf("parse tunnel source cidrs: %w", err)
	}
	if len(tunnelSourceCIDRs) == 0 && strings.TrimSpace(rawTunnelSourceCIDRs) != "" {
		return nil, fmt.Errorf("parse tunnel source cidrs: %q names no network", rawTunnelSourceCIDRs)
	}
	return &Ingress{trustProxyHeaders: trustProxyHeaders, trustedProxyCIDRs: trustedProxyCIDRs, tunnelSourceCIDRs: tunnelSourceCIDRs}, nil
}

func (i *Ingress) allowsTunnelFrom(source netip.Addr) bool {
	if i == nil || len(i.tunnelSourceCIDRs) == 0 {
		return true
	}
	return slices.ContainsFunc(i.tunnelSourceCIDRs, func(network netip.Prefix) bool {
		return network.Contains(source.WithZone(""))
	})
}

func (i *Ingress) forwardedHeaderAddr(req *http.Request) (netip.Addr, bool) {
	if i == nil || !i.trustProxyHeaders || !isTrustedProxyRemoteAddr(req.RemoteAddr, i.trustedProxyCIDRs) {
		return netip.Addr{}, false
	}
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		before, _, _ := strings.Cut(xff, ",")
		if ip := parseSourceAddr(before); ip.IsValid() {
			return ip, true
		}
	}
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		if ip := parseSourceAddr(xri); ip.IsValid() {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

func (i *Ingress) SourceAddr(req *http.Request) netip.Addr {
	if req == nil {
		return netip.Addr{}
	}
	if ip, ok := i.forwardedHeaderAddr(req); ok {
		return ip
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
	raw = strings.TrimSpace(raw)
	if addr, err := netip.ParseAddr(raw); err == nil {
		return addr.Unmap()
	}
	if addrPort, err := netip.ParseAddrPort(raw); err == nil {
		return addrPort.Addr().Unmap()
	}
	return netip.Addr{}
}

func parseCIDRs(raw string) ([]netip.Prefix, error) {
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
