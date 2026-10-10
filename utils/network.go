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
	endpoints := append(append([]string{}, publicIPEndpoints...), publicIPv6Endpoints...)
	endpoints = append(endpoints, publicIPv4Endpoints...)
	ip, err := resolvePublicIP(ctx, 5*time.Second, 1500*time.Millisecond, 0, endpoints...)
	if err != nil {
		return ""
	}
	return ip
}

// ResolvePublicIPs discovers IPv4 and IPv6 independently, returning available
// addresses in that order. A failure in one family does not hide the other.
func ResolvePublicIPs(ctx context.Context) ([]string, error) {
	var addresses [2]string
	var errs [2]error
	var workers sync.WaitGroup
	for i, endpoints := range [][]string{publicIPv4Endpoints, publicIPv6Endpoints} {
		workers.Go(func() {
			family := 4 + 2*i
			addresses[i], errs[i] = resolvePublicIP(ctx, 15*time.Second, 3*time.Second, family, endpoints...)
			if errs[i] != nil {
				errs[i] = fmt.Errorf("resolve public ipv%d: %w", family, errs[i])
			}
		})
	}
	workers.Wait()
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

func resolvePublicIP(ctx context.Context, totalTimeout, attemptTimeout time.Duration, family int, endpoints ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, totalTimeout)
	defer cancel()

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
