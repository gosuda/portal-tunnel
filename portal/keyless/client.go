// Package keyless owns tenant TLS with relay-backed or in-process transcript signing.
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
	"time"

	"github.com/gosuda/keyless_tls/keyless/t13server"

	"github.com/gosuda/portal-tunnel/v2/types"
)

var (
	errTenantCertificatePairRequired                = errors.New("tenant certificate and key files must be supplied together")
	errTenantKeyCannotSign                          = errors.New("tenant private key cannot sign")
	errTenantPeerCertificateMissing                 = errors.New("tenant peer certificate is missing")
	errTenantCertificateNotValid                    = errors.New("tenant certificate is not currently valid")
	errRelayHostnameIsRequired                      = errors.New("relay hostname is required")
	errKeylessHostnameIsRequired                    = errors.New("keyless hostname is required")
	errKeylessPinnedRelayCertificateChainUnparsable = errors.New("keyless pinned relay certificate chain is unparsable")
	errKeylessClientIsUnavailable                   = errors.New("keyless client is unavailable")
	errKeylessCertificateChainIsRequired            = errors.New("keyless certificate chain is required")
)

// ClientConfig contains the lease-scoped inputs for a tenant TLS client.
type ClientConfig struct {
	RelayURL            string
	Hostname            string
	AlternativeHostname string
	AccessToken         string
	CertificateDir      string
	RequireLocal        bool
	// InstalledCertificates receives best-effort installed local public leaf DER.
	// Delivery never blocks TLS activation; the receiver owns its lifecycle.
	InstalledCertificates chan<- []byte
	// CertFile and KeyFile select local-only signing; both must be supplied.
	CertFile string
	KeyFile  string
}

// Client owns one tenant TLS engine and atomically replaces certificate/signer material.
type Client struct {
	mu          sync.RWMutex
	accessToken string
	pin         *pinnedChain
	retired     []*pinnedChain
	closed      bool
	closeOnce   sync.Once
	closeErr    error

	relay     *relaySource
	files     *fileSource
	automatic *automaticSource
	hostname  string

	refreshMu             sync.Mutex
	ready                 chan struct{}
	installedCertificates chan<- []byte
}

type pinnedChain struct {
	chainPEM []byte
	server   *t13server.Server
	pool     *x509.CertPool
	signer   io.Closer
	leaf     *x509.Certificate
	local    bool
}

// NewClient loads local material when configured, otherwise pins the relay chain.
// Local file errors fail closed; they never select relay-backed signing.
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
		accessToken:           strings.TrimSpace(config.AccessToken),
		installedCertificates: config.InstalledCertificates,
		hostname:              hostname,
	}

	client.relay = &relaySource{relayURL: normalizedRelayURL, serverName: serverName, hostname: hostname, headers: client.headers}
	if (config.CertFile == "") != (config.KeyFile == "") {
		return nil, errTenantCertificatePairRequired
	}
	if config.CertFile != "" {
		client.files = &fileSource{config.CertFile, config.KeyFile, hostname, strings.TrimSpace(config.AlternativeHostname)}
	}
	if config.RequireLocal && config.CertificateDir == "" && config.CertFile == "" {
		return nil, errAutomaticCertificateDirectoryRequired
	}
	if config.CertificateDir != "" {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if config.CertFile != "" {
			return nil, errAutomaticAndManualCertificateConflict
		}
		client.automatic = &automaticSource{relaySource: client.relay, certificateDir: config.CertificateDir}
		if strings.TrimSpace(config.AlternativeHostname) != "" {
			return nil, errAutomaticCanonicalHostnameOnly
		}
		if client.pin, err = client.automatic.initial(ctx, config.RequireLocal); err != nil {
			return nil, err
		}
		client.ready = make(chan struct{})
		if client.pin != nil {
			close(client.ready)
		}
		client.publishInstalled(client.pin)
		client.automatic.start(client)
		return client, nil
	}
	if client.pin, err = client.loadPin(ctx); err != nil {
		return nil, err
	}
	client.publishInstalled(client.pin)
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

// RefreshChain reloads configured files, a persisted automatic bundle, or the relay
// bootstrap chain. It never issues certificates. Invalid replacements
// leave the previous generation intact; existing connections are not restarted.
func (c *Client) RefreshChain(ctx context.Context) (bool, error) {
	return c.refreshChain(ctx, nil)
}

func (c *Client) refreshChain(ctx context.Context, stale *pinnedChain) (bool, error) {
	if c.pinned() == nil && c.automatic == nil {
		return false, errKeylessClientIsUnavailable
	}
	bootstrapRecovery := c.automatic != nil && stale != nil && stale.signer != nil
	// Stale bootstrap recovery must not wait for another reload. Its
	// compare-and-swap below cannot overwrite a concurrently activated local pin.
	if !bootstrapRecovery {
		if c.automatic != nil {
			if !c.refreshMu.TryLock() {
				return false, errAutomaticCertificateBusy
			}
		} else {
			c.refreshMu.Lock()
		}
		defer c.refreshMu.Unlock()
	}
	if stale != nil && c.pinned() != stale {
		return false, nil
	}
	current := c.pinned()
	var next *pinnedChain
	var err error
	if bootstrapRecovery {
		next, err = c.relay.acquire(ctx)
	} else {
		next, err = c.loadPin(ctx)
	}
	var reloadErr error
	if err != nil && !bootstrapRecovery && c.automatic != nil && current != nil && current.signer != nil {
		reloadErr = err
		// Bootstrap is still allowed: preserve normal relay certificate rotation
		// during an issuance outage. Local activation never takes this path.
		next, err = c.relay.acquire(ctx)
	}
	if err != nil {
		return false, errors.Join(reloadErr, err)
	}
	if current != nil && bytes.Equal(next.chainPEM, current.chainPEM) {
		if next.signer != nil {
			_ = next.signer.Close()
		}
		return false, reloadErr
	}
	c.mu.Lock()
	staleRecovery := bootstrapRecovery && c.pin != stale
	downgrade := c.pin != nil && c.pin.local && !next.local
	if c.closed || staleRecovery || downgrade {
		c.mu.Unlock()
		if next.signer != nil {
			_ = next.signer.Close()
		}
		return false, nil
	}
	current = c.pin
	// Retain exact public leaves, never a retired relay's CA trust. A probe
	// already in flight may still observe that leaf after local activation.
	// The handshake owns its server and key for as long as it needs them.
	live := c.retired[:0]
	for _, old := range c.retired {
		if old.leaf != nil && time.Now().Before(old.leaf.NotAfter) {
			live = append(live, old)
		}
	}
	c.retired = live
	if current != nil {
		c.retired = append(c.retired, &pinnedChain{leaf: current.leaf, local: current.local})
	} else if c.ready != nil {
		close(c.ready)
	}
	c.pin = next
	c.publishInstalled(next)
	c.mu.Unlock()
	// RemoteSigner.Close only closes idle HTTP connections; it neither cancels
	// an in-flight signature nor prevents one on an already captured server.
	if current != nil && current.signer != nil {
		_ = current.signer.Close()
	}
	return true, reloadErr
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

// TerminateConn uses one captured certificate/signer generation. Local signing
// stays in process; relay-backed signing forwards the per-connection binding.
func (c *Client) TerminateConn(ctx context.Context, raw net.Conn, binding []byte) (net.Conn, error) {
	pin := c.pinned()
	if pin == nil {
		return nil, errKeylessClientIsUnavailable
	}
	var err error
	if pin.leaf != nil && (time.Now().Before(pin.leaf.NotBefore) || !time.Now().Before(pin.leaf.NotAfter)) {
		_ = raw.Close()
		if pin.local && c.automatic != nil {
			// Automatic renewal owns its backoff; incoming connections must
			// neither trigger issuance attempts nor restore relay signing.
			return nil, errTenantCertificateNotValid
		}
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
	// next connection can use renewed relay material or replacement local files.
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
// Shutdown cancels and joins the local renewal HTTP worker. It does not wait
// for the remote ACME order: its serialization and DNS cleanup belong to the relay.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.automatic != nil && c.automatic.cancel != nil {
			c.automatic.cancel()
		}
		pin := c.pin
		c.mu.Unlock()
		if c.automatic != nil && c.automatic.done != nil {
			<-c.automatic.done
		}
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
	if c.automatic != nil {
		bundle, err := c.automatic.readBundle()
		if err != nil {
			return nil, err
		}
		if bundle.CertificatePEM == "" {
			return nil, errAutomaticCertificateMissing
		}
		return newLocalPin([]byte(bundle.CertificatePEM), []byte(bundle.KeyPEM), c.hostname, "")
	}
	if c.files != nil {
		return c.files.acquire()
	}
	return c.relay.acquire(ctx)
}

// TenantTLSConfig verifies self-probes against installed tenant materials,
// including a previous generation still used by an in-flight handshake.
// Retired generations trust only their exact leaf until expiry, including a
// relay bootstrap leaf during local activation, never its issuing CA.
// It must not be used for the relay control API.
func (c *Client) TenantTLSConfig() *tls.Config {
	return &tls.Config{
		ServerName: c.hostname,
		MinVersion: tls.VersionTLS13,
		// Replace the static-root verification with full verification against
		// the installed generations at handshake time; verification is not skipped.
		InsecureSkipVerify: true, //nolint:gosec // VerifyConnection performs x509 verification below.
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errTenantPeerCertificateMissing
			}
			c.mu.RLock()
			pins := append([]*pinnedChain{c.pin}, c.retired...)
			c.mu.RUnlock()
			intermediates := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			var verificationErr error
			for i, pin := range pins {
				if pin == nil {
					continue
				}
				roots := pin.pool
				if i > 0 {
					if pin.leaf == nil || !state.PeerCertificates[0].Equal(pin.leaf) {
						continue
					}
					roots = x509.NewCertPool()
					roots.AddCert(pin.leaf)
				}
				_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
					DNSName: c.hostname, Roots: roots, Intermediates: intermediates,
				})
				if err == nil {
					return nil
				}
				verificationErr = err
			}
			if verificationErr == nil {
				return errKeylessClientIsUnavailable
			}
			return verificationErr
		},
	}
}

// publishInstalled runs only while initializing or holding the activation lock.
func (c *Client) publishInstalled(pin *pinnedChain) {
	if c.installedCertificates == nil || pin == nil || !pin.local || pin.leaf == nil {
		return
	}
	select {
	case c.installedCertificates <- append([]byte(nil), pin.leaf.Raw...):
	default:
	}
}
