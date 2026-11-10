// Package keyless owns Portal's tenant TLS feature boundary: terminating tenant TLS with transcript-bound relay signatures and resolving the pinned relay certificate chain.
package keyless

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	keylesstls "github.com/gosuda/keyless_tls/keyless"
	"github.com/gosuda/keyless_tls/keyless/t13server"

	"github.com/gosuda/portal-tunnel/v2/types"
)

var (
	errRelayHostnameIsRequired                      = errors.New("relay hostname is required")
	errKeylessHostnameIsRequired                    = errors.New("keyless hostname is required")
	errKeylessPinnedRelayCertificateChainUnparsable = errors.New("keyless pinned relay certificate chain is unparsable")
	errKeylessClientIsUnavailable                   = errors.New("keyless client is unavailable")
	errKeylessCertificateChainIsRequired            = errors.New("keyless certificate chain is required")
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
// without rebuilding the client, and RefreshChain pins a renewed relay
// certificate without one.
type Client struct {
	mu          sync.RWMutex
	accessToken string
	pin         *pinnedChain
	closed      bool
	closeOnce   sync.Once
	closeErr    error

	relayURL   string
	serverName string
	hostname   string

	refreshMu sync.Mutex
}

type pinnedChain struct {
	chainPEM []byte
	server   *t13server.Server
	pool     *x509.CertPool
	signer   io.Closer
}

// NewClient creates one lease-scoped tenant TLS client. It resolves and pins
// the relay certificate chain, verifies the chain covers the lease hostname,
// and wires the remote transcript signer to the relay's /v1/sign endpoint.
// ctx controls initialization; subsequent operations use their own contexts.
func NewClient(ctx context.Context, config ClientConfig) (*Client, error) {
	normalizedRelayURL, serverName, err := resolveRelayEndpoint(config.RelayURL)
	if err != nil {
		return nil, err
	}
	return buildTenantClient(ctx, config, normalizedRelayURL, serverName)
}

func buildTenantClient(ctx context.Context, config ClientConfig, normalizedRelayURL, serverName string) (*Client, error) {
	chainPEM, err := relayChain(ctx, normalizedRelayURL, serverName)
	if err != nil {
		return nil, fmt.Errorf("prepare keyless materials: %w", err)
	}
	hostname := strings.TrimSpace(config.Hostname)
	if hostname == "" {
		return nil, errKeylessHostnameIsRequired
	}
	client := &Client{
		accessToken: strings.TrimSpace(config.AccessToken),
		relayURL:    normalizedRelayURL,
		serverName:  serverName,
		hostname:    hostname,
	}
	if err := attachPinForNewClient(client, chainPEM); err != nil {
		return nil, err
	}
	return client, nil
}

func attachPinForNewClient(client *Client, chainPEM []byte) error {
	pin, err := client.newPin(chainPEM)
	if err != nil {
		return err
	}
	client.pin = pin
	return nil
}

func (c *Client) newPin(chainPEM []byte) (*pinnedChain, error) {
	if err := verifyCertificateHostname(chainPEM, c.hostname); err != nil {
		return nil, fmt.Errorf("keyless certificate does not cover %s: %w", c.hostname, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(chainPEM) {
		return nil, errKeylessPinnedRelayCertificateChainUnparsable
	}
	remoteSigner, err := keylesstls.NewRemoteSigner(keylesstls.RemoteSignerConfig{
		Endpoint:   c.relayURL,
		ServerName: c.serverName,
		KeyID:      types.KeylessRelayKeyID,
		RootCAPEM:  chainPEM,
		Headers:    c.headers,
	})
	if err != nil {
		return nil, fmt.Errorf("create keyless remote signer: %w", err)
	}
	server, err := t13server.NewServer(t13server.Config{
		CertPEM:          chainPEM,
		NextProtos:       []string{"http/1.1"},
		KeyID:            types.KeylessRelayKeyID,
		TranscriptSigner: remoteSigner,
	})
	if err != nil {
		_ = remoteSigner.Close()
		return nil, fmt.Errorf("create keyless tls server: %w", err)
	}
	return &pinnedChain{chainPEM: chainPEM, server: server, pool: pool, signer: remoteSigner}, nil
}

func (c *Client) pinned() *pinnedChain {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pin
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

// RefreshChain pins the certificate chain the relay serves now when it is not
// the pinned one, and reports whether it changed. A renewal gives the relay a
// new certificate and key, while a client keeps presenting the chain it pinned
// until this runs. The relay signs for the replaced certificate until it
// expires, so every client has to come here before then; connections already
// terminated are not affected.
func (c *Client) RefreshChain(ctx context.Context) (bool, error) {
	return c.refreshChain(ctx, nil)
}

func (c *Client) refreshChain(ctx context.Context, stale *pinnedChain) (bool, error) {
	if c.pinned() == nil {
		return false, errKeylessClientIsUnavailable
	}
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	if stale != nil && c.pinned() != stale {
		return false, nil
	}
	chainPEM, err := relayChain(ctx, c.relayURL, c.serverName)
	if err != nil {
		return false, err
	}
	current := c.pinned()
	if bytes.Equal(chainPEM, current.chainPEM) {
		return false, nil
	}
	next, err := c.newPin(chainPEM)
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = next.signer.Close()
		return false, nil
	}
	c.pin = next
	c.mu.Unlock()
	_ = current.signer.Close()
	return true, nil
}

func pinIsStale(err error) bool {
	if strings.Contains(err.Error(), types.KeylessUnknownCertificateMessage) {
		return true
	}
	_, verification := errors.AsType[*tls.CertificateVerificationError](err)
	return verification
}

// TerminateConn terminates tenant TLS on raw, presenting the pinned relay
// chain and proving possession of its key through a transcript-bound
// signature from the relay. binding is the relay-minted per-connection value
// forwarded with every /v1/sign request for the handshake. The returned
// net.Conn is ready for application traffic.
func (c *Client) TerminateConn(ctx context.Context, raw net.Conn, binding []byte) (net.Conn, error) {
	pin := c.pinned()
	if pin == nil {
		return nil, errKeylessClientIsUnavailable
	}
	conn := pin.server.NewConn(raw, binding)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		if pinIsStale(err) {
			if _, refreshErr := c.refreshChain(ctx, pin); refreshErr != nil {
				err = errors.Join(err, fmt.Errorf("refresh relay certificate chain: %w", refreshErr))
			}
		}
		return nil, fmt.Errorf("tenant tls handshake: %w", err)
	}
	return conn, nil
}

// RelayCertPool returns the pinned relay certificate chain as a verification
// pool. Callers that dial the relay themselves, such as the MITM self-probe,
// verify against this pool instead of disabling certificate verification.
func (c *Client) RelayCertPool() *x509.CertPool {
	pin := c.pinned()
	if pin == nil {
		return nil
	}
	return pin.pool
}

// Close releases the remote signer of the pinned chain. The pinned chain stays
// readable, but RefreshChain pins nothing new after Close, so no signer is left
// unreleased. It is safe to call more than once: the signer is closed exactly
// once and every call returns the result of that first close attempt.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		pin := c.pin
		c.mu.Unlock()
		if pin != nil && pin.signer != nil {
			c.closeErr = pin.signer.Close()
		}
	})
	return c.closeErr
}
