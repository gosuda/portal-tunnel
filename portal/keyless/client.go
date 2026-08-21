package keyless

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	keylesstls "github.com/gosuda/keyless_tls/keyless"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const materialsRequestTimeout = 15 * time.Second

func BuildClientTLSConfig(relayURL, hostname string, echKeys []tls.EncryptedClientHelloKey, headers func() http.Header) (*tls.Config, ioCloser, error) {
	normalizedRelayURL, err := utils.NormalizeRelayURL(relayURL)
	if err != nil {
		return nil, nil, err
	}

	parsed, err := url.Parse(normalizedRelayURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse relay url: %w", err)
	}
	serverName := parsed.Hostname()
	if serverName == "" {
		return nil, nil, errors.New("relay hostname is required")
	}

	certPEM, rootCAPEM, keyID, err := ResolveMaterials(context.Background(), normalizedRelayURL, serverName)
	if err != nil {
		return nil, nil, fmt.Errorf("prepare keyless materials: %w", err)
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return nil, nil, errors.New("keyless hostname is required")
	}
	if verifyErr := VerifyCertificateHostname(certPEM, hostname); verifyErr != nil {
		return nil, nil, fmt.Errorf("keyless certificate does not cover %s: %w", hostname, verifyErr)
	}

	remoteSigner, err := keylesstls.NewRemoteSigner(keylesstls.RemoteSignerConfig{
		Endpoint:   normalizedRelayURL,
		ServerName: serverName,
		KeyID:      keyID,
		RootCAPEM:  rootCAPEM,
		Headers:    headers,
	}, certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("create keyless remote signer: %w", err)
	}

	tlsConfig, err := keylesstls.NewServerTLSConfig(keylesstls.ServerTLSConfig{
		CertPEM:                  certPEM,
		Signer:                   remoteSigner,
		NextProtos:               []string{"http/1.1"},
		MinVersion:               MinTLSVersion(len(echKeys) > 0),
		EncryptedClientHelloKeys: echKeys,
	})
	if err != nil {
		_ = remoteSigner.Close()
		return nil, nil, fmt.Errorf("create keyless tls config: %w", err)
	}
	return tlsConfig, remoteSigner, nil
}

type ioCloser interface {
	Close() error
}

func ResolveMaterials(ctx context.Context, endpoint, serverName string) ([]byte, []byte, string, error) {
	chainPEM, err := utils.FetchEndpointCertificateChain(ctx, endpoint, serverName)
	if err != nil {
		return nil, nil, "", fmt.Errorf("fetch signer api certificate chain: %w", err)
	}
	if len(chainPEM) == 0 {
		return nil, nil, "", errors.New("keyless api certificate chain is required")
	}

	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, nil, "", fmt.Errorf("parse signer endpoint: %w", err)
	}
	requestCtx, cancel := context.WithTimeout(ctx, materialsRequestTimeout)
	defer cancel()
	_, client, transport, err := utils.NewHTTPTLSClient(requestCtx, parsed, materialsRequestTimeout)
	if err != nil {
		return nil, nil, "", fmt.Errorf("create signer materials client: %w", err)
	}
	defer transport.CloseIdleConnections()

	var materials types.KeylessMaterials
	if err := utils.HTTPDoAPIPath(requestCtx, client, parsed, http.MethodGet, types.PathV1KeylessMaterials, nil, nil, &materials); err != nil {
		return nil, nil, "", fmt.Errorf("fetch tenant keyless materials: %w", err)
	}
	materials.KeyID = strings.TrimSpace(materials.KeyID)
	if materials.KeyID == "" {
		return nil, nil, "", errors.New("tenant keyless key id is required")
	}
	if len(materials.CertificateChain) == 0 {
		return nil, nil, "", errors.New("tenant keyless certificate chain is required")
	}
	return bytes.Clone(materials.CertificateChain), bytes.Clone(chainPEM), materials.KeyID, nil
}

func VerifyCertificateHostname(certPEM []byte, hostname string) error {
	leaf, err := utils.ParseCertificatePEM(certPEM)
	if err != nil {
		return err
	}
	return leaf.VerifyHostname(hostname)
}
