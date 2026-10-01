//go:build js

package utils

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// FetchEndpointCertificateChain asks the relay for its public chain because a
// browser does not expose the peer certificates from its TLS handshake.
func FetchEndpointCertificateChain(ctx context.Context, endpoint, _ string) ([]byte, error) {
	raw := strings.TrimSpace(endpoint)
	if raw == "" {
		return nil, errors.New("endpoint is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint url: %w", err)
	}
	parsed.Path = types.PathSDKCertificateChain
	parsed.RawQuery = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch certificate chain: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch certificate chain: unexpected status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
