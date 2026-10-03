package policy

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Ingress resolves the client source for relay admission and diagnostics.
// Forwarded headers are trusted only when the direct peer is inside an
// explicitly configured trusted proxy CIDR. The resolved value flows to lower
// layers as a plain string; portal code never inspects proxy headers itself.
type Ingress struct {
	trustProxyHeaders bool
	trustedProxyCIDRs []*net.IPNet
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

func isTrustedProxyRemoteAddr(remoteAddr string, trustedProxyCIDRs []*net.IPNet) bool {
	remoteIP := parseRemoteAddrIP(remoteAddr)
	if remoteIP == nil {
		return false
	}

	for _, network := range trustedProxyCIDRs {
		if network != nil && network.Contains(remoteIP) {
			return true
		}
	}
	return false
}

func parseRemoteAddrIP(remoteAddr string) net.IP {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return nil
	}
	host := remoteAddr
	if parsedHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = parsedHost
	}
	return net.ParseIP(strings.TrimSpace(host))
}

func normalizeClientIPCandidate(raw string) string {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return ""
	}
	if ip := net.ParseIP(candidate); ip != nil {
		return ip.String()
	}
	host, _, err := net.SplitHostPort(candidate)
	if err != nil {
		return ""
	}
	host = strings.TrimSpace(host)
	if host == "" || net.ParseIP(host) == nil {
		return ""
	}
	return net.ParseIP(host).String()
}
