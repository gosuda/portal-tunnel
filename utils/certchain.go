package utils

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// FetchEndpointCertificateChain returns the certificate chain presented by endpoint.
// Browsers ask the relay for the public chain because their TLS stack does not expose
// peer certificates; native runtimes read it directly from the TLS handshake.
func FetchEndpointCertificateChain(ctx context.Context, endpoint, serverName string) ([]byte, error) {
	if runtime.GOOS != "js" {
		return fetchEndpointCertificateChainOverTLS(ctx, endpoint, serverName)
	}

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
