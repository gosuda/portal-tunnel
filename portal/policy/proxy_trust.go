package policy

import (
	"net"
	"net/http"
	"strings"
)

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

func (r *Runtime) ExtractClientIP(req *http.Request) string {
	if r == nil {
		return ""
	}
	if req == nil {
		return ""
	}

	cfg := runtimeConfig{}
	if r.config != nil {
		cfg = r.config.Load()
	}
	if cfg.trustProxyHeaders && isTrustedProxyRemoteAddr(req.RemoteAddr, cfg.trustedProxyCIDRs) {
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
		return candidate
	}
	host, _, err := net.SplitHostPort(candidate)
	if err != nil {
		return ""
	}
	host = strings.TrimSpace(host)
	if host == "" || net.ParseIP(host) == nil {
		return ""
	}
	return host
}
