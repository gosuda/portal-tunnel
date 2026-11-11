package utils

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

var (
	errRelayURLIsRequired              = errors.New("relay url is required")
	errRelayHostnameIsRequired         = errors.New("relay hostname is required")
	errFailedParseRelayRootCA          = errors.New("failed to parse relay root ca")
	errEndpointIsRequired              = errors.New("endpoint is required")
	errRelayEndpointMustUseHTTPS       = errors.New("relay endpoint must use https")
	errEndpointHostnameIsEmpty         = errors.New("endpoint hostname is empty")
	errNoPeerCertificatesRelayEndpoint = errors.New("no peer certificates from relay endpoint")
	errNoPEMBlockFound                 = errors.New("no pem block found")
)

func NewHTTPTLSClient(ctx context.Context, relayURL *url.URL, timeout time.Duration) (*tls.Config, *http.Client, *http.Transport, error) {
	if relayURL == nil {
		return nil, nil, nil, errRelayURLIsRequired
	}

	serverName := relayURL.Hostname()
	if serverName == "" {
		return nil, nil, nil, errRelayHostnameIsRequired
	}

	var rootCAs *x509.CertPool
	if IsLocalRelayHost(serverName) {
		rootCAPEM, err := FetchEndpointCertificateChain(ctx, relayURL.String(), serverName)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("bootstrap localhost relay trust: %w", err)
		}
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(rootCAPEM) {
			return nil, nil, nil, errFailedParseRelayRootCA
		}
	}

	rawTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		RootCAs:    rootCAs,
		NextProtos: []string{"http/1.1"},
	}
	httpClient := NewHTTPClient(
		WithHTTPTLSConfig(rawTLSConfig),
		WithoutHTTP2(),
		WithHTTPTimeout(timeout),
	)
	return rawTLSConfig, httpClient, httpClient.Transport.(*http.Transport), nil
}

// FetchEndpointCertificateChain dials endpoint and returns its PEM-encoded peer chain.
func FetchEndpointCertificateChain(ctx context.Context, endpoint, serverName string) ([]byte, error) {
	u, err := parseEndpointURL(endpoint)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS == "js" {
		return fetchChainOverHTTPS(ctx, u)
	}

	host := u.Hostname()
	if host == "" {
		return nil, errEndpointHostnameIsEmpty
	}
	port := cmp.Or(u.Port(), "443")
	serverName = cmp.Or(serverName, host)
	tlsConn, err := dialEndpointTLS(ctx, host, port, serverName)
	if err != nil {
		return nil, err
	}
	defer tlsConn.Close()

	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return nil, errNoPeerCertificatesRelayEndpoint
	}

	var chainPEM []byte
	for _, cert := range peerCerts {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}
	return chainPEM, nil
}

func parseEndpointURL(endpoint string) (*url.URL, error) {
	raw := strings.TrimSpace(endpoint)
	if raw == "" {
		return nil, errEndpointIsRequired
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint url: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, errRelayEndpointMustUseHTTPS
	}
	return u, nil
}

func fetchChainOverHTTPS(ctx context.Context, u *url.URL) ([]byte, error) {
	u.Path = types.PathSDKCertificateChain
	u.RawPath = ""
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
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

func dialEndpointTLS(ctx context.Context, host, port, serverName string) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("dial relay endpoint: %w", err)
	}
	tlsConn := tls.Client(rawConn, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: IsLocalRelayHost(host),
		NextProtos:         []string{"http/1.1"},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("tls handshake with relay endpoint: %w", err)
	}
	return tlsConn, nil
}

func ParseCertificatePEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errNoPEMBlockFound
	}
	return x509.ParseCertificate(block.Bytes)
}
