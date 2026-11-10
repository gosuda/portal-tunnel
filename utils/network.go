package utils

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
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
			storeCollectFamilyResultsOutcome(&addresses, &errs, result)
			done, nextFamily, timer := advanceCollectFamilyResultsWait(result.address, familyWait, remainingFamily)
			if timer != nil {
				defer timer.Stop()
				remainingFamily = nextFamily
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

func storeCollectFamilyResultsOutcome(addresses *[2]string, errs *[2]error, result publicIPFamilyResult) {
	addresses[result.index], errs[result.index] = result.address, result.err
}

func advanceCollectFamilyResultsWait(address string, familyWait time.Duration, remainingFamily <-chan time.Time) (bool, <-chan time.Time, *time.Timer) {
	if address == "" {
		return false, remainingFamily, nil
	}
	if familyWait == 0 {
		return true, remainingFamily, nil
	}
	if remainingFamily != nil {
		return false, remainingFamily, nil
	}
	timer := time.NewTimer(familyWait)
	return false, timer.C, timer
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
			return net.JoinHostPort("127.0.0.1", port), nil
		}
	}
	if _, err := strconv.Atoi(raw); err == nil {
		return net.JoinHostPort("127.0.0.1", raw), nil
	}
	return NormalizeTargetAddr(raw)
}
