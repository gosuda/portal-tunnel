package utils

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func NewHTTPTLSClient(ctx context.Context, relayURL *url.URL, timeout time.Duration) (*tls.Config, *http.Client, error) {
	if relayURL == nil {
		return nil, nil, errors.New("relay url is required")
	}

	serverName := relayURL.Hostname()
	if serverName == "" {
		return nil, nil, errors.New("relay hostname is required")
	}

	var rootCAs *x509.CertPool
	if IsLocalRelayHost(serverName) {
		rootCAPEM, err := FetchEndpointCertificateChain(ctx, relayURL.String(), serverName)
		if err != nil {
			return nil, nil, fmt.Errorf("bootstrap localhost relay trust: %w", err)
		}
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(rootCAPEM) {
			return nil, nil, errors.New("failed to parse relay root ca")
		}
	}

	rawTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		RootCAs:    rootCAs,
		NextProtos: []string{"http/1.1"},
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   rawTLSConfig.Clone(),
			ForceAttemptHTTP2: false,
		},
		Timeout: timeout,
	}
	return rawTLSConfig, httpClient, nil
}

func FetchEndpointCertificateChain(ctx context.Context, endpoint, serverName string) ([]byte, error) {
	raw := strings.TrimSpace(endpoint)
	if raw == "" {
		return nil, errors.New("endpoint is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint url: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, errors.New("relay endpoint must use https")
	}

	host := u.Hostname()
	if host == "" {
		return nil, errors.New("endpoint hostname is empty")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if serverName == "" {
		serverName = host
	}

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
	defer tlsConn.Close()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake with relay endpoint: %w", err)
	}

	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return nil, errors.New("no peer certificates from relay endpoint")
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

func ParseCertificatePEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no pem block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func ParsePrivateKeyPEM(keyPEM []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("invalid private key pem")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch typed := key.(type) {
		case *ecdsa.PrivateKey:
			return typed, nil
		case *rsa.PrivateKey:
			return typed, nil
		}
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key type")
}
