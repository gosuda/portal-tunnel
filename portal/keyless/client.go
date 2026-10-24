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
	"sync/atomic"

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
// without rebuilding the client, and RefreshChain pins a renewed relay
// certificate without one.
type Client struct {
	mu          sync.RWMutex
	accessToken string
	pin         *pinnedChain
	closed      bool // guarded by mu, so that no pin is installed after Close
	closeOnce   sync.Once
	closeErr    error

	// Fixed when the client is created; RefreshChain reuses them to pin another
	// chain.
	relayURL   string
	serverName string
	hostname   string

	// refreshMu serializes the checks of the relay chain, and checks counts the
	// ones that completed.
	refreshMu sync.Mutex
	checks    atomic.Uint64
}

// pinnedChain is one relay certificate chain with what is derived from it. The
// signer reaches the relay's /v1/sign endpoint verified against this same
// chain. RefreshChain replaces the whole value, so the chain a handshake
// presents, the pool the MITM probe verifies it against and the chain the
// signer trusts always belong together.
type pinnedChain struct {
	chainPEM []byte
	server   *t13server.Server
	pool     *x509.CertPool
	signer   io.Closer
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

	chainPEM, err := relayChain(context.Background(), normalizedRelayURL, serverName)
	if err != nil {
		return nil, fmt.Errorf("prepare keyless materials: %w", err)
	}
	hostname := strings.TrimSpace(config.Hostname)
	if hostname == "" {
		return nil, errors.New("keyless hostname is required")
	}
	client := &Client{
		accessToken: strings.TrimSpace(config.AccessToken),
		relayURL:    normalizedRelayURL,
		serverName:  serverName,
		hostname:    hostname,
	}

	if client.pin, err = client.newPin(chainPEM); err != nil {
		return nil, err
	}
	return client, nil
}

// newPin pins chainPEM: it checks the chain covers the lease hostname and
// builds the TLS server that presents it with the signer that proves possession
// of its key.
func (c *Client) newPin(chainPEM []byte) (*pinnedChain, error) {
	if err := verifyCertificateHostname(chainPEM, c.hostname); err != nil {
		return nil, fmt.Errorf("keyless certificate does not cover %s: %w", c.hostname, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(chainPEM) {
		return nil, errors.New("keyless pinned relay certificate chain is unparsable")
	}
	remoteSigner, err := keylesstls.NewRemoteSigner(keylesstls.RemoteSignerConfig{
		Endpoint:   c.relayURL,
		ServerName: c.serverName,
		KeyID:      relayKeyID,
		RootCAPEM:  chainPEM,
		Headers:    c.headers,
	})
	if err != nil {
		return nil, fmt.Errorf("create keyless remote signer: %w", err)
	}
	server, err := t13server.NewServer(t13server.Config{
		CertPEM:          chainPEM,
		NextProtos:       []string{"http/1.1"},
		KeyID:            relayKeyID,
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

// refreshChain is RefreshChain, except that it does nothing when checkedBefore
// is set and a check has completed since the checks counter had that value: the
// handshakes of a burst that fail on the same stale pin share the one check.
func (c *Client) refreshChain(ctx context.Context, checkedBefore *uint64) (bool, error) {
	if c.pinned() == nil {
		return false, errors.New("keyless client is unavailable")
	}
	// Serialized so that a slower fetch cannot pin a chain the relay already
	// replaced.
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	if checkedBefore != nil && c.checks.Load() != *checkedBefore {
		return false, nil
	}
	defer c.checks.Add(1)
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
		// Close already released the pin it saw; a new one would never be.
		c.mu.Unlock()
		_ = next.signer.Close()
		return false, nil
	}
	c.pin = next
	c.mu.Unlock()
	// Handshakes still using the replaced signer finish on their connections.
	_ = current.signer.Close()
	return true, nil
}

// pinIsStale reports whether a failed handshake means the relay no longer
// accepts the chain this client pinned: it holds no key for the chain it
// presents, or its API certificate does not verify against the pinned chain
// any more, as when a renewal comes from another issuer. Both are cured by
// pinning the chain the relay serves now.
func pinIsStale(err error) bool {
	if strings.Contains(err.Error(), unknownCertificateMessage) {
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
	// Read before the pin: a check that completes after this point also
	// completes after the pin was read, so it is never mistaken for one that
	// already looked at a newer pin.
	checks := c.checks.Load()
	pin := c.pinned()
	if pin == nil {
		return nil, errors.New("keyless client is unavailable")
	}
	conn := pin.server.NewConn(raw, binding)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		// This handshake is lost; the ones after it present the chain the relay
		// serves now.
		if pinIsStale(err) {
			if _, refreshErr := c.refreshChain(ctx, &checks); refreshErr != nil {
				err = errors.Join(err, fmt.Errorf("refresh relay certificate chain: %w", refreshErr))
			}
		}
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
	return c.pinned() != nil
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

// Close releases the remote signer backing the TLS server, and no chain is
// pinned after it. It is safe to call more than once: the signer is closed
// exactly once and every call returns the result of that first close attempt.
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

// relayChain returns the certificate chain the relay presents on endpoint.
func relayChain(ctx context.Context, endpoint, serverName string) ([]byte, error) {
	chainPEM, err := utils.FetchEndpointCertificateChain(ctx, endpoint, serverName)
	if err != nil {
		return nil, fmt.Errorf("fetch signer certificate chain: %w", err)
	}
	if len(chainPEM) == 0 {
		return nil, errors.New("keyless certificate chain is required")
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
