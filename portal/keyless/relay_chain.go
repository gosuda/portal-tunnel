package keyless

import (
	"context"
	"fmt"
	"net/url"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

func resolveRelayEndpoint(relayURL string) (string, string, error) {
	normalizedRelayURL, err := utils.NormalizeRelayURL(relayURL)
	if err != nil {
		return "", "", err
	}
	parsed, err := url.Parse(normalizedRelayURL)
	if err != nil {
		return "", "", fmt.Errorf("parse relay url: %w", err)
	}
	serverName := parsed.Hostname()
	if serverName == "" {
		return "", "", errRelayHostnameIsRequired
	}
	return normalizedRelayURL, serverName, nil
}

func relayChain(ctx context.Context, endpoint, serverName string) ([]byte, error) {
	chainPEM, err := utils.FetchEndpointCertificateChain(ctx, endpoint, serverName)
	if err != nil {
		return nil, fmt.Errorf("fetch signer certificate chain: %w", err)
	}
	if len(chainPEM) == 0 {
		return nil, errKeylessCertificateChainIsRequired
	}
	return chainPEM, nil
}

func verifyCertificateHostname(certPEM []byte, hostname string) error {
	leaf, err := utils.ParseCertificatePEM(certPEM)
	if err != nil {
		return err
	}
	return leaf.VerifyHostname(hostname)
}
