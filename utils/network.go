package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

var (
	publicIPv4Endpoints = []string{
		"https://api4.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://v4.ident.me",
		"https://checkip.amazonaws.com",
	}
	publicIPv6Endpoints = []string{
		"https://api64.ipify.org",
		"https://ipv6.icanhazip.com",
		"https://v6.ident.me",
	}
)

type PublicIPs struct {
	IPv4 string
	IPv6 string
}

func (ips PublicIPs) Any() bool {
	return strings.TrimSpace(ips.IPv4) != "" || strings.TrimSpace(ips.IPv6) != ""
}

func (ips PublicIPs) PreferredIP() string {
	if ipv4 := strings.TrimSpace(ips.IPv4); ipv4 != "" {
		return ipv4
	}
	return strings.TrimSpace(ips.IPv6)
}

func NormalizePublicIPs(publicIPs PublicIPs) (PublicIPs, error) {
	normalized := PublicIPs{
		IPv4: SanitizeReportedIPv4(publicIPs.IPv4),
		IPv6: SanitizeReportedIPv6(publicIPs.IPv6),
	}
	if trimmed := strings.TrimSpace(publicIPs.IPv4); trimmed != "" && normalized.IPv4 == "" {
		return PublicIPs{}, fmt.Errorf("invalid ipv4 address: %q", publicIPs.IPv4)
	}
	if trimmed := strings.TrimSpace(publicIPs.IPv6); trimmed != "" && normalized.IPv6 == "" {
		return PublicIPs{}, fmt.Errorf("invalid ipv6 address: %q", publicIPs.IPv6)
	}
	if !normalized.Any() {
		return PublicIPs{}, errors.New("at least one public ip address is required")
	}
	return normalized, nil
}

type ipFamily int

const (
	ipFamilyAny ipFamily = iota
	ipFamilyV4
	ipFamilyV6
)

// ResolvePublicIP attempts to determine the caller's public IP address
// using well-known external services. Returns empty string on failure.
// Best-effort with a short timeout to avoid blocking registration.
func ResolvePublicIP(ctx context.Context) string {
	ips, err := resolvePublicIPs(ctx, 5*time.Second, 1500*time.Millisecond)
	if err != nil {
		return ""
	}
	return ips.PreferredIP()
}

func ResolvePublicIPs(ctx context.Context) (PublicIPs, error) {
	return resolvePublicIPs(ctx, 15*time.Second, 3*time.Second)
}

func ResolvePublicIPv4(ctx context.Context) (string, error) {
	return resolvePublicIP(ctx, 15*time.Second, 3*time.Second, ipFamilyV4, publicIPv4Endpoints...)
}

func ResolvePublicIPv6(ctx context.Context) (string, error) {
	return resolvePublicIP(ctx, 15*time.Second, 3*time.Second, ipFamilyV6, publicIPv6Endpoints...)
}

func resolvePublicIPs(ctx context.Context, totalTimeout, attemptTimeout time.Duration) (PublicIPs, error) {
	type result struct {
		family ipFamily
		ip     string
		err    error
	}

	results := make(chan result, 2)
	go func() {
		ip, err := resolvePublicIP(ctx, totalTimeout, attemptTimeout, ipFamilyV4, publicIPv4Endpoints...)
		results <- result{family: ipFamilyV4, ip: ip, err: err}
	}()
	go func() {
		ip, err := resolvePublicIP(ctx, totalTimeout, attemptTimeout, ipFamilyV6, publicIPv6Endpoints...)
		results <- result{family: ipFamilyV6, ip: ip, err: err}
	}()

	var ips PublicIPs
	var combinedErr error
	for range 2 {
		result := <-results
		switch result.family {
		case ipFamilyV4:
			ips.IPv4 = result.ip
		case ipFamilyV6:
			ips.IPv6 = result.ip
		}
		if result.err != nil {
			combinedErr = errors.Join(combinedErr, result.err)
		}
	}
	if ips.Any() {
		return ips, nil
	}
	if combinedErr == nil {
		combinedErr = errors.New("resolve public ip failed")
	}
	return PublicIPs{}, combinedErr
}

func resolvePublicIP(ctx context.Context, totalTimeout, attemptTimeout time.Duration, family ipFamily, endpoints ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, totalTimeout)
	defer cancel()

	client := &http.Client{}
	headers := http.Header{"User-Agent": []string{"portal-tunnel"}}
	var lastErr error

	for _, endpoint := range endpoints {
		if err := ctx.Err(); err != nil {
			lastErr = err
			break
		}

		requestTimeout := attemptTimeout
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				lastErr = context.DeadlineExceeded
				break
			}
			if requestTimeout <= 0 || requestTimeout > remaining {
				requestTimeout = remaining
			}
		}

		requestCtx, cancelRequest := context.WithTimeout(ctx, requestTimeout)
		resp, err := httpDo(requestCtx, client, http.MethodGet, endpoint, nil, headers)
		cancelRequest()
		if err != nil {
			lastErr = err
			continue
		}

		limitedBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = errors.New(resp.Status)
			continue
		}
		if readErr != nil {
			lastErr = readErr
			continue
		}

		candidate := SanitizeReportedIP(string(limitedBody))
		if candidate == "" {
			lastErr = errors.New("invalid public ip response")
			continue
		}
		switch family {
		case ipFamilyV4:
			candidate = SanitizeReportedIPv4(candidate)
			if candidate == "" {
				lastErr = errors.New("public ip is not ipv4")
				continue
			}
		case ipFamilyV6:
			candidate = SanitizeReportedIPv6(candidate)
			if candidate == "" {
				lastErr = errors.New("public ip is not ipv6")
				continue
			}
		}
		return candidate, nil
	}

	if lastErr == nil {
		lastErr = errors.New("resolve public ip failed")
	}
	return "", lastErr
}

func SanitizeReportedIP(raw string) string {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return ""
	}
	if net.ParseIP(candidate) == nil {
		return ""
	}
	return candidate
}

func SanitizeReportedIPv4(raw string) string {
	candidate := SanitizeReportedIP(raw)
	if candidate == "" {
		return ""
	}
	if err := ValidateIPv4(candidate); err != nil {
		return ""
	}
	return candidate
}

func SanitizeReportedIPv6(raw string) string {
	candidate := SanitizeReportedIP(raw)
	if candidate == "" {
		return ""
	}
	if err := ValidateIPv6(candidate); err != nil {
		return ""
	}
	return candidate
}

func SanitizeReportedPublicIPs(reportedIP, reportedIPv4, reportedIPv6 string) PublicIPs {
	ips := PublicIPs{
		IPv4: SanitizeReportedIPv4(reportedIPv4),
		IPv6: SanitizeReportedIPv6(reportedIPv6),
	}

	legacy := SanitizeReportedIP(reportedIP)
	if legacy == "" {
		return ips
	}
	if ips.IPv4 == "" {
		ips.IPv4 = SanitizeReportedIPv4(legacy)
	}
	if ips.IPv6 == "" {
		ips.IPv6 = SanitizeReportedIPv6(legacy)
	}
	return ips
}

func ResolveHostIPFamilies(ctx context.Context, host string) (supportsIPv4, supportsIPv6 bool, err error) {
	host = NormalizeHostname(host)
	if host == "" {
		return false, false, errors.New("host is required")
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4() != nil, ip.To4() == nil, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return false, false, err
	}
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			supportsIPv4 = true
			continue
		}
		if ip.To16() != nil {
			supportsIPv6 = true
		}
	}
	if !supportsIPv4 && !supportsIPv6 {
		return false, false, errors.New("host did not resolve to any ip address")
	}
	return supportsIPv4, supportsIPv6, nil
}

// FetchRelayVersion calls GET /sdk/domain on a relay and returns its release version.
// Returns an empty string on any error (timeout, unreachable, bad response).
func FetchRelayVersion(ctx context.Context, relayURL string) string {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := httpDo(ctx, client, http.MethodGet, relayURL+types.PathSDKDomain, nil, nil)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var envelope types.APIEnvelope[types.DomainResponse]
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil || !envelope.OK {
		return ""
	}
	return envelope.Data.ReleaseVersion
}

func ResolvePortalRelayURLs(ctx context.Context, explicit []string, includeDefaults bool) ([]string, error) {
	explicit, err := NormalizeRelayURLs(explicit...)
	if err != nil {
		return nil, err
	}
	if !includeDefaults {
		return explicit, nil
	}

	client := &http.Client{Timeout: 5 * time.Second}
	var registry struct {
		Relays []string `json:"relays"`
	}
	resp, err := httpDo(ctx, client, http.MethodGet, types.PortalRelayRegistryURL, nil, nil)
	if err != nil {
		return explicit, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return explicit, nil
	}
	if err := json.NewDecoder(resp.Body).Decode(&registry); err != nil {
		return explicit, nil
	}

	defaults, err := NormalizeRelayURLs(registry.Relays...)
	if err != nil {
		return explicit, nil
	}
	if len(defaults) == 0 {
		return explicit, nil
	}
	return MergeRelayURLs(defaults, nil, explicit)
}
