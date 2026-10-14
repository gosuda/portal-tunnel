package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
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

// ResolvePublicIP attempts to determine the caller's public IP address
// using well-known external services. Returns empty string on failure.
// Best-effort with a short timeout to avoid blocking registration.
func ResolvePublicIP(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if ip, err := resolvePublicIP(ctx, 1500*time.Millisecond, 0, publicIPEndpoints...); err == nil {
		return ip
	}
	// Neither address family should spend the other's remaining fallback budget.
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

// resolvePublicIPFamilies shares concurrent discovery and cancellation between
// first-address registration and best-effort dual-stack DNS discovery.
func resolvePublicIPFamilies(ctx context.Context, attemptTimeout, familyWait time.Duration) ([]string, error) {
	ctx, cancel := context.WithCancel(ctx)
	type result struct {
		index   int
		address string
		err     error
	}
	results := make(chan result, 2)
	var workers sync.WaitGroup
	for i, endpoints := range [][]string{publicIPv4Endpoints, publicIPv6Endpoints} {
		workers.Go(func() {
			family := 4 + 2*i
			address, err := resolvePublicIP(ctx, attemptTimeout, family, endpoints...)
			if err != nil {
				err = fmt.Errorf("resolve public ipv%d: %w", family, err)
			}
			results <- result{index: i, address: address, err: err}
		})
	}
	defer func() {
		cancel()
		workers.Wait()
	}()

	var addresses [2]string
	var errs [2]error
	var remainingFamily <-chan time.Time
collect:
	for range 2 {
		select {
		case result := <-results:
			addresses[result.index], errs[result.index] = result.address, result.err
			if result.address != "" {
				if familyWait == 0 {
					break collect
				}
				if remainingFamily == nil {
					timer := time.NewTimer(familyWait)
					defer timer.Stop()
					remainingFamily = timer.C
				}
			}
		case <-remainingFamily:
			break collect
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
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
	client := DefaultHTTPClient
	headers := http.Header{"User-Agent": []string{"portal-tunnel"}}
	var lastErr error

	for _, endpoint := range endpoints {
		if err := ctx.Err(); err != nil {
			lastErr = err
			break
		}

		requestCtx, cancelRequest := context.WithTimeout(ctx, attemptTimeout)
		resp, err := httpDo(requestCtx, client, http.MethodGet, endpoint, nil, headers)
		if err != nil {
			cancelRequest()
			lastErr = err
			continue
		}

		limitedBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		cancelRequest()
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
		addressFamily := 4
		if strings.Contains(candidate, ":") {
			addressFamily = 6
		}
		if family != 0 && family != addressFamily {
			lastErr = fmt.Errorf("public ip is not ipv%d", family)
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

func SanitizeReportedIP(raw string) string {
	ip, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || ip.Zone() != "" {
		return ""
	}
	return ip.Unmap().String()
}

// FetchRelayVersion calls GET /sdk/domain on a relay and returns its release version.
// Returns an empty string on any error (timeout, unreachable, bad response).
func FetchRelayVersion(ctx context.Context, relayURL string) string {
	client := NewHTTPClient(WithHTTPTimeout(3 * time.Second))
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

// The non-public exceptions to Go's IsGlobalUnicast and IsPrivate checks
// include shared, benchmark, documentation, and transition address space.
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
		for _, prefix := range nonPublicIPv4 {
			if prefix.Contains(ip) {
				return false
			}
		}
		return true
	}
	if !globalIPv6.Contains(ip) {
		return false
	}
	for _, prefix := range nonPublicIPv6 {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
