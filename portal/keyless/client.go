// Package keyless owns Portal's tenant TLS feature boundary: tenant TLS
// termination via the keyless_tls t13server (transcript-bound TLS 1.3 whose
// CertificateVerify signatures are produced remotely by the relay's /v1/sign
// endpoint) plus the material resolution that pins the relay certificate
// chain. The SDK and the relay own when and why these operations happen
// (lease sessions, reverse sessions, TLS listeners); this package owns the
// tenant TLS protocol itself. Relay key possession is proven per handshake:
// every termination presents transcript-bound signatures from the key that
// matches the pinned certificate, so no configuration-time signer self-test
// is needed.
package keyless

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	keylesstls "github.com/gosuda/keyless_tls/keyless"
	"github.com/gosuda/keyless_tls/keyless/t13server"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// ClientConfig contains the lease-scoped inputs for a tenant TLS client.
type ClientConfig struct {
	RelayURL    string
	Hostname    string
	AccessToken string
}

// Client terminates tenant TLS on raw reverse-session connections. The
// presented certificate chain is pinned from the relay's HTTPS endpoint, and
// the CertificateVerify signatures for every handshake are requested from the
// relay's transcript-bound /v1/sign endpoint. Access tokens can be updated
// without rebuilding the client.
type Client struct {
	mu            sync.RWMutex
	accessToken   string
	server        *t13server.Server
	signer        io.Closer
	relayCertPool *x509.CertPool
	closeOnce     sync.Once
	closeErr      error
}

// NewClient creates one lease-scoped tenant TLS client. It resolves and pins
// the relay certificate chain, verifies the chain covers the lease hostname,
// and wires the remote transcript signer to the relay's /v1/sign endpoint.
func NewClient(config ClientConfig) (*Client, error) {
	normalizedRelayURL, err := utils.NormalizeRelayURL(config.RelayURL)
	if err != nil {
		return nil, err
	}

	parsed, err := url.Parse(normalizedRelayURL)
	if err != nil {
		return nil, fmt.Errorf("parse relay url: %w", err)
	}
	serverName := parsed.Hostname()
	if serverName == "" {
		return nil, errors.New("relay hostname is required")
	}

	certPEM, rootCAPEM, err := resolveMaterials(context.Background(), normalizedRelayURL, serverName)
	if err != nil {
		return nil, fmt.Errorf("prepare keyless materials: %w", err)
	}
	hostname := strings.TrimSpace(config.Hostname)
	if hostname == "" {
		return nil, errors.New("keyless hostname is required")
	}
	if verifyErr := verifyCertificateHostname(certPEM, hostname); verifyErr != nil {
		return nil, fmt.Errorf("keyless certificate does not cover %s: %w", hostname, verifyErr)
	}
	client := &Client{accessToken: strings.TrimSpace(config.AccessToken)}
	relayCertPool := x509.NewCertPool()
	if !relayCertPool.AppendCertsFromPEM(certPEM) {
		return nil, errors.New("keyless pinned relay certificate chain is unparsable")
	}
	client.relayCertPool = relayCertPool

	remoteSigner, err := keylesstls.NewRemoteSigner(keylesstls.RemoteSignerConfig{
		Endpoint:   normalizedRelayURL,
		ServerName: serverName,
		KeyID:      relayKeyID,
		RootCAPEM:  rootCAPEM,
		Headers:    client.headers,
	})
	if err != nil {
		return nil, fmt.Errorf("create keyless remote signer: %w", err)
	}

	server, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		NextProtos:       []string{"http/1.1"},
		KeyID:            relayKeyID,
		TranscriptSigner: remoteSigner,
	})
	if err != nil {
		_ = remoteSigner.Close()
		return nil, fmt.Errorf("create keyless tls server: %w", err)
	}
	client.server = server
	client.signer = remoteSigner
	return client, nil
}

func (c *Client) headers() http.Header {
	headers := http.Header{}
	c.mu.RLock()
	token := c.accessToken
	c.mu.RUnlock()
	if token != "" {
		headers.Set(types.HeaderAccessToken, token)
	}
	return headers
}

// SetAccessToken updates the credential used by subsequent signer requests.
func (c *Client) SetAccessToken(token string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.accessToken = strings.TrimSpace(token)
	c.mu.Unlock()
}

// TerminateConn terminates tenant TLS on raw, presenting the pinned relay
// chain and proving possession of its key through a transcript-bound
// signature from the relay. binding is the relay-minted per-connection value
// forwarded with every /v1/sign request for the handshake. The returned
// net.Conn is ready for application traffic.
func (c *Client) TerminateConn(ctx context.Context, raw net.Conn, binding []byte) (net.Conn, error) {
	if c == nil || c.server == nil {
		return nil, errors.New("keyless client is unavailable")
	}
	conn := c.server.NewConn(raw, binding)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tenant tls handshake: %w", err)
	}
	return conn, nil
}

// ExportsKeyingMaterial reports whether terminated tenant connections can
// export TLS keying material for the SDK's MITM responder probe. The
// t13server terminator exposes the RFC 8446 Section 7.5 exporter on every
// post-handshake conn, so the capability holds
// whenever the tenant TLS server exists.
func (c *Client) ExportsKeyingMaterial() bool {
	return c != nil && c.server != nil
}

// RelayCertPool returns the pinned relay certificate chain as a verification
// pool. Callers that dial the relay themselves, such as the MITM self-probe,
// verify against this pool instead of disabling certificate verification.
func (c *Client) RelayCertPool() *x509.CertPool {
	if c == nil {
		return nil
	}
	return c.relayCertPool
}

// Close releases the remote signer backing the TLS server. It is safe
// to call more than once: the signer is closed exactly once and every call
// returns the result of that first close attempt.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		if c.signer != nil {
			c.closeErr = c.signer.Close()
		}
	})
	return c.closeErr
}

func resolveMaterials(ctx context.Context, endpoint, serverName string) ([]byte, []byte, error) {
	chainPEM, err := utils.FetchEndpointCertificateChain(ctx, endpoint, serverName)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch signer certificate chain: %w", err)
	}
	if len(chainPEM) == 0 {
		return nil, nil, errors.New("keyless certificate chain is required")
	}
	return bytes.Clone(chainPEM), bytes.Clone(chainPEM), nil
}

func verifyCertificateHostname(certPEM []byte, hostname string) error {
	leaf, err := utils.ParseCertificatePEM(certPEM)
	if err != nil {
		return err
	}
	return leaf.VerifyHostname(hostname)
}
