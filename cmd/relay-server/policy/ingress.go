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
// explicitly configured trusted proxy CIDR. The resolved value flows to lower
// layers as a plain string; portal code never inspects proxy headers itself.
type Ingress struct {
	trustProxyHeaders bool
	trustedProxyCIDRs []netip.Prefix
}

func NewIngress(trustProxyHeaders bool, rawTrustedProxyCIDRs string) (*Ingress, error) {
	trustedProxyCIDRs, err := utils.ParseCIDRs(rawTrustedProxyCIDRs)
	if err != nil {
		return nil, fmt.Errorf("parse trusted proxy cidrs: %w", err)
	}
	return &Ingress{trustProxyHeaders: trustProxyHeaders, trustedProxyCIDRs: trustedProxyCIDRs}, nil
}

func (i *Ingress) ClientIP(req *http.Request) string {
	if req == nil {
		return ""
	}
	if i != nil && i.trustProxyHeaders && isTrustedProxyRemoteAddr(req.RemoteAddr, i.trustedProxyCIDRs) {
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			if before, _, ok := strings.Cut(xff, ","); ok {
				if ip := normalizeClientIPCandidate(before); ip != "" {
					return ip
				}
			} else if ip := normalizeClientIPCandidate(xff); ip != "" {
				return ip
			}
		}
		if xri := req.Header.Get("X-Real-IP"); xri != "" {
			if ip := normalizeClientIPCandidate(xri); ip != "" {
				return ip
			}
		}
	}

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(req.RemoteAddr)
	}
	if normalized := normalizeClientIPCandidate(host); normalized != "" {
		return normalized
	}
	return strings.TrimSpace(host)
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
	return utils.NormalizeSourceAddr(remoteAddr)
}

func normalizeClientIPCandidate(raw string) string {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return ""
	}
	if addr := utils.NormalizeSourceAddr(candidate); addr.IsValid() {
		return addr.String()
	}
	return ""
}
