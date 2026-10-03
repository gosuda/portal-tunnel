package policy

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
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

// NewAdmissionLimiter builds the weighted pre-auth budget the relay applies
// to anonymous protocol requests.
func NewAdmissionLimiter(preAuth types.PreAuthConfig) *utils.SourceLimiter {
	return utils.NewSourceLimiter(preAuth.SourcePerMinute, preAuth.SourceBurst, preAuth.GlobalPerMinute, preAuth.GlobalBurst)
}

func DefaultPreAuthConfig() types.PreAuthConfig {
	// 600 units/minute permits about 100 complete registrations/minute;
	// the 200-unit burst permits about 33 simultaneous startups. Operators
	// should tune this aggregate work budget to their relay capacity.
	return types.PreAuthConfig{SourcePerMinute: 10, SourceBurst: 20, GlobalPerMinute: 600, GlobalBurst: 200, ChallengeCost: 1, AnnounceCost: 2, RegisterCost: 5}
}

func NormalizePreAuthConfig(c *types.PreAuthConfig) error {
	defaults := DefaultPreAuthConfig()
	for _, field := range []struct {
		value    *int
		fallback int
	}{
		{&c.SourcePerMinute, defaults.SourcePerMinute}, {&c.SourceBurst, defaults.SourceBurst},
		{&c.GlobalPerMinute, defaults.GlobalPerMinute}, {&c.GlobalBurst, defaults.GlobalBurst},
		{&c.ChallengeCost, defaults.ChallengeCost}, {&c.AnnounceCost, defaults.AnnounceCost}, {&c.RegisterCost, defaults.RegisterCost},
	} {
		if *field.value < 0 {
			return fmt.Errorf("pre-auth limits and weights must be positive")
		}
		if *field.value == 0 {
			*field.value = field.fallback
		}
	}
	if weight := max(c.ChallengeCost, c.AnnounceCost, c.RegisterCost); weight > c.SourceBurst || weight > c.GlobalBurst {
		return fmt.Errorf("pre-auth burst budgets must cover every endpoint weight")
	}
	return nil
}

// WriteRetryAfter answers a rejected admission with the limiter's retry
// guidance; no source history is exposed.
func WriteRetryAfter(w http.ResponseWriter, retry time.Duration, message string) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retry.Seconds())))))
	utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, message)
}
