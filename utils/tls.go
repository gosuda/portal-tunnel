package utils

import (
	"bufio"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
	rawConn, err := dialEndpointTCP(ctx, host, port)
	if err != nil {
		return nil, err
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

// dialEndpointTCP honors the same HTTP(S)_PROXY and NO_PROXY rules as the REST
// client: endpoints routed through a proxy by the environment are reached over
// an HTTP CONNECT tunnel, all others through a direct TCP connection.
func dialEndpointTCP(ctx context.Context, host, port string) (net.Conn, error) {
	address := net.JoinHostPort(host, port)
	proxyURL, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: address}})
	if err != nil {
		return nil, fmt.Errorf("resolve proxy for relay endpoint: %w", err)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if proxyURL == nil {
		rawConn, dialErr := dialer.DialContext(ctx, "tcp", address)
		if dialErr != nil {
			return nil, fmt.Errorf("dial relay endpoint: %w", dialErr)
		}
		return rawConn, nil
	}
	return dialConnectTunnel(ctx, dialer, proxyURL, address)
}

// dialConnectTunnel opens address through an HTTP proxy and returns the raw
// tunneled connection.
func dialConnectTunnel(ctx context.Context, dialer *net.Dialer, proxyURL *url.URL, address string) (net.Conn, error) {
	scheme := strings.ToLower(proxyURL.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("relay endpoint proxy scheme %q is not supported", proxyURL.Scheme)
	}
	proxyConn, err := dialer.DialContext(ctx, "tcp", proxyDialAddress(proxyURL))
	if err != nil {
		return nil, fmt.Errorf("dial relay endpoint proxy: %w", err)
	}
	connectDeadline := time.Now().Add(5 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(connectDeadline) {
		connectDeadline = ctxDeadline
	}
	_ = proxyConn.SetDeadline(connectDeadline)
	if scheme == "https" {
		proxyTLSConn := tls.Client(proxyConn, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: proxyURL.Hostname()})
		if err := proxyTLSConn.HandshakeContext(ctx); err != nil {
			_ = proxyConn.Close()
			return nil, fmt.Errorf("tls handshake with relay endpoint proxy: %w", err)
		}
		proxyConn = proxyTLSConn
	}
	connectRequest := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: make(http.Header),
	}
	if user := proxyURL.User; user != nil {
		password, _ := user.Password()
		credentials := base64.StdEncoding.EncodeToString([]byte(user.Username() + ":" + password))
		connectRequest.Header.Set("Proxy-Authorization", "Basic "+credentials)
	}
	if err := connectRequest.Write(proxyConn); err != nil {
		_ = proxyConn.Close()
		return nil, fmt.Errorf("connect relay endpoint through proxy: %w", err)
	}
	// The buffered reader is safe to discard once the response is read: the
	// endpoint's TLS server does not speak until the client sends its handshake.
	reader := bufio.NewReader(&io.LimitedReader{R: proxyConn, N: maxProxyResponseHeaderBytes})
	response, err := http.ReadResponse(reader, connectRequest)
	if err != nil {
		_ = proxyConn.Close()
		return nil, fmt.Errorf("read relay endpoint proxy response: %w", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_ = proxyConn.Close()
		return nil, fmt.Errorf("connect relay endpoint through proxy: %s", response.Status)
	}
	_ = proxyConn.SetDeadline(time.Time{})
	return proxyConn, nil
}

const maxProxyResponseHeaderBytes = 1 << 20

func proxyDialAddress(proxyURL *url.URL) string {
	if proxyURL.Port() != "" {
		return proxyURL.Host
	}
	if strings.EqualFold(proxyURL.Scheme, "https") {
		return net.JoinHostPort(proxyURL.Hostname(), "443")
	}
	return net.JoinHostPort(proxyURL.Hostname(), "80")
}

func ParseCertificatePEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errNoPEMBlockFound
	}
	return x509.ParseCertificate(block.Bytes)
}
