package utils

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

var (
	publicIPEndpoints = []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://checkip.amazonaws.com",
	}
	publicIPv4Endpoints = []string{
		"https://api4.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://v4.ident.me",
		"https://checkip.amazonaws.com",
	}
)

// ResolvePublicIP attempts to determine the caller's public IP address
// using well-known external services. Returns empty string on failure.
// Best-effort with a short timeout to avoid blocking registration.
func ResolvePublicIP(ctx context.Context) string {
	endpoints := append(append([]string{}, publicIPEndpoints...), publicIPv4Endpoints...)
	ip, err := resolvePublicIP(ctx, 5*time.Second, 1500*time.Millisecond, false, endpoints...)
	if err != nil {
		return ""
	}
	return ip
}

func ResolvePublicIPv4(ctx context.Context) (string, error) {
	endpoints := append(append([]string{}, publicIPv4Endpoints...), publicIPEndpoints...)
	return resolvePublicIP(ctx, 15*time.Second, 3*time.Second, true, endpoints...)
}

func resolvePublicIP(ctx context.Context, totalTimeout, attemptTimeout time.Duration, requireIPv4 bool, endpoints ...string) (string, error) {
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
		if requireIPv4 {
			parsed := net.ParseIP(candidate)
			if parsed == nil || parsed.To4() == nil {
				lastErr = errors.New("public ip is not ipv4")
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

func ResolvePortalRelayURLs(ctx context.Context, explicit []string, includeDefaults bool) ([]string, error) {
	explicit, err := NormalizeRelayURLs(explicit...)
	if err != nil {
		return nil, err
	}
	if !includeDefaults {
		return explicit, nil
	}

	client := NewHTTPClient(WithHTTPTimeout(3 * time.Second))
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
