package keyless

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	keylesstls "github.com/gosuda/keyless_tls/keyless"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

// DialContextFunc allows callers to override how keyless materials are fetched.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

func BuildClientTLSConfig(relayURL string, domains []string, dial DialContextFunc) (*tls.Config, ioCloser, error) {
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

	certPEM, rootCAPEM, err := ResolveMaterials(context.Background(), normalizedRelayURL, serverName, dial)
	if err != nil {
		return nil, nil, fmt.Errorf("prepare keyless materials: %w", err)
	}
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		verifyErr := VerifyCertificateHostname(certPEM, domain)
		if verifyErr != nil {
			return nil, nil, fmt.Errorf("keyless certificate does not cover %s: %w", domain, verifyErr)
		}
	}

	remoteSigner, err := keylesstls.NewRemoteSigner(keylesstls.RemoteSignerConfig{
		Endpoint:   normalizedRelayURL,
		ServerName: serverName,
		KeyID:      RelayKeyID,
		RootCAPEM:  rootCAPEM,
	}, certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("create keyless remote signer: %w", err)
	}

	tlsConfig, err := keylesstls.NewServerTLSConfig(keylesstls.ServerTLSConfig{
		CertPEM:    certPEM,
		Signer:     remoteSigner,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
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

func ResolveMaterials(ctx context.Context, endpoint, serverName string, dial DialContextFunc) ([]byte, []byte, error) {
	chainPEM, err := FetchEndpointCertificateChain(ctx, endpoint, serverName, dial)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch signer certificate chain: %w", err)
	}
	if len(chainPEM) == 0 {
		return nil, nil, errors.New("keyless certificate chain is required")
	}
	return append([]byte(nil), chainPEM...), append([]byte(nil), chainPEM...), nil
}

func VerifyCertificateHostname(certPEM []byte, hostname string) error {
	leaf, err := utils.ParseCertificatePEM(certPEM)
	if err != nil {
		return err
	}
	return leaf.VerifyHostname(hostname)
}

func FetchEndpointCertificateChain(ctx context.Context, endpoint, serverName string, dial DialContextFunc) ([]byte, error) {
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
		return nil, errors.New("keyless endpoint must use https")
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

	var rawConn net.Conn
	if dial != nil {
		rawConn, err = dial(ctx, "tcp", net.JoinHostPort(host, port))
	} else {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		rawConn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}
	if err != nil {
		return nil, fmt.Errorf("dial signer endpoint: %w", err)
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: utils.IsLocalRelayHost(host),
		NextProtos:         []string{"http/1.1"},
	})
	defer tlsConn.Close()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake with signer endpoint: %w", err)
	}

	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return nil, errors.New("no peer certificates from signer endpoint")
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
