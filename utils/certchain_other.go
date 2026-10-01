//go:build !js

package utils

import "context"

// FetchEndpointCertificateChain returns the certificate chain presented by endpoint.
func FetchEndpointCertificateChain(ctx context.Context, endpoint, serverName string) ([]byte, error) {
	return fetchEndpointCertificateChainOverTLS(ctx, endpoint, serverName)
}
