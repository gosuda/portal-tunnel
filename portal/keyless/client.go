// Package keyless owns relay-backed tenant TLS for friendly and legacy hostnames.
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
	"net/url"
	"strings"
	"sync"
	"time"

	keylesstls "github.com/gosuda/keyless_tls/keyless"
	"github.com/gosuda/keyless_tls/keyless/t13server"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errTenantCertificateNotValid                    = errors.New("tenant certificate is not currently valid")
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

// Client owns one tenant TLS engine and atomically replaces certificate/signer material.
type Client struct {
	mu          sync.RWMutex
	accessToken string
	pin         *pinnedChain
	closed      bool
	closeOnce   sync.Once
	closeErr    error

	relay    *relaySource
	hostname string

	refreshMu sync.Mutex
}

type pinnedChain struct {
	chainPEM []byte
	server   *t13server.Server
	pool     *x509.CertPool
	signer   io.Closer
	leaf     *x509.Certificate
}

// NewClient pins the relay chain for friendly and legacy tenant TLS.
func NewClient(ctx context.Context, config ClientConfig) (*Client, error) {
	normalizedRelayURL, serverName, err := resolveRelayEndpoint(config.RelayURL)
	if err != nil {
		return nil, err
	}
	return buildTenantClient(ctx, config, normalizedRelayURL, serverName)
}

func buildTenantClient(ctx context.Context, config ClientConfig, normalizedRelayURL, serverName string) (*Client, error) {
	var err error
	hostname := strings.TrimSpace(config.Hostname)
	if hostname == "" {
		return nil, errKeylessHostnameIsRequired
	}
	client := &Client{
		accessToken: strings.TrimSpace(config.AccessToken),
		hostname:    hostname,
	}

	client.relay = &relaySource{relayURL: normalizedRelayURL, serverName: serverName, hostname: hostname, headers: client.headers}
	if client.pin, err = client.loadPin(ctx); err != nil {
		return nil, err
	}
	return client, nil
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

// RefreshChain reloads the relay chain. Invalid replacements
// leave the previous generation intact; existing connections are not restarted.
func (c *Client) RefreshChain(ctx context.Context) (bool, error) {
	return c.refreshChain(ctx, nil)
}

func (c *Client) refreshChain(ctx context.Context, stale *pinnedChain) (bool, error) {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	current := c.pinned()
	if current == nil {
		return false, errKeylessClientIsUnavailable
	}
	if stale != nil && current != stale {
		return false, nil
	}
	next, err := c.loadPin(ctx)
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	if c.closed || bytes.Equal(next.chainPEM, current.chainPEM) {
		c.mu.Unlock()
		_ = next.signer.Close()
		return false, nil
	}
	c.pin = next
	c.mu.Unlock()
	if current.signer != nil {
		_ = current.signer.Close()
	}
	return true, nil
}

func pinIsStale(err error) bool {
	if errors.Is(err, errTenantCertificateNotValid) {
		return true
	}
	if strings.Contains(err.Error(), types.KeylessUnknownCertificateMessage) {
		return true
	}
	_, verification := errors.AsType[*tls.CertificateVerificationError](err)
	return verification
}

// TerminateConn captures the relay certificate and forwards the connection binding.
func (c *Client) TerminateConn(ctx context.Context, raw net.Conn, binding []byte) (net.Conn, error) {
	pin := c.pinned()
	if pin == nil {
		return nil, errKeylessClientIsUnavailable
	}
	var err error
	if pin.leaf != nil && (time.Now().Before(pin.leaf.NotBefore) || !time.Now().Before(pin.leaf.NotAfter)) {
		_ = raw.Close()

		err = errTenantCertificateNotValid
	} else {
		conn := pin.server.NewConn(raw, binding)
		err = conn.HandshakeContext(ctx)
		if err == nil {
			return conn, nil
		}
		_ = conn.Close()
	}
	// Expiry fails closed, but still refreshes the stale generation so the
	// next connection can use renewed relay material.
	if pinIsStale(err) {
		if _, refreshErr := c.refreshChain(ctx, pin); refreshErr != nil {
			err = errors.Join(err, fmt.Errorf("refresh tenant certificate chain: %w", refreshErr))
		}
	}
	return nil, fmt.Errorf("tenant tls handshake: %w", err)
}

// TenantCertPool returns the current tenant trust snapshot. Use TenantTLSConfig
// for probes that can overlap rotation. This is not relay control API trust.
func (c *Client) TenantCertPool() *x509.CertPool {
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

// loadPin keeps provisioning separate from the shared tenant handshake engine.
func (c *Client) loadPin(ctx context.Context) (*pinnedChain, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.relay.acquire(ctx)
}

// TenantTLSConfig verifies probes using the current relay tenant chain.
func (c *Client) TenantTLSConfig() *tls.Config {
	return &tls.Config{ServerName: c.hostname, MinVersion: tls.VersionTLS13, RootCAs: c.TenantCertPool()}
}

// relaySource acquires bootstrap material and binds its remote signer to the lease.
type relaySource struct {
	relayURL   string
	serverName string
	hostname   string
	headers    func() http.Header
}

func (c *relaySource) acquire(ctx context.Context) (*pinnedChain, error) {
	chain, err := relayChain(ctx, c.relayURL, c.serverName)
	if err != nil {
		return nil, err
	}
	return c.newPin(chain)
}

func (c *relaySource) newPin(chainPEM []byte) (*pinnedChain, error) {
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
	leaf, _ := utils.ParseCertificatePEM(chainPEM)
	return &pinnedChain{chainPEM: chainPEM, server: server, pool: pool, signer: remoteSigner, leaf: leaf}, nil
}

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
