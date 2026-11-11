// Package localtls owns exact-hostname, tunnel-terminated TLS and certificate renewal.
package localtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errTenantCertificatePairRequired = errors.New("tenant certificate and key files must be supplied together")
	errTenantPeerCertificateMissing  = errors.New("tenant peer certificate is missing")
	errTenantCertificateNotValid     = errors.New("tenant certificate is not currently valid")
	errLocalHostnameIsRequired       = errors.New("local TLS hostname is required")
	errLocalClientIsUnavailable      = errors.New("local TLS certificate is unavailable")
)

// ClientConfig contains the lease-scoped inputs for a tenant TLS client.
type ClientConfig struct {
	RelayURL       string
	Hostname       string
	AccessToken    string
	CertificateDir string
	NextProtos     []string
	// InstalledCertificates receives best-effort installed local public leaf DER.
	// Delivery never blocks TLS activation; the receiver owns its lifecycle.
	InstalledCertificates chan<- []byte
	// CertFile and KeyFile select local-only signing; both must be supplied.
	CertFile string
	KeyFile  string
}

// Client owns one tenant TLS engine and atomically replaces certificate material.
type Client struct {
	mu          sync.RWMutex
	accessToken string
	pin         *pinnedChain
	retired     []*pinnedChain
	closed      bool
	closeOnce   sync.Once

	files      *fileSource
	automatic  *automaticSource
	hostname   string
	nextProtos []string

	refreshMu             sync.Mutex
	ready                 chan struct{}
	installedCertificates chan<- []byte
}

type pinnedChain struct {
	chainPEM    []byte
	certificate tls.Certificate
	pool        *x509.CertPool
	leaf        *x509.Certificate
}

// NewClient loads manual or persisted material and starts automatic renewal when
// configured. Missing automatic material stays unavailable until issuance succeeds.
func NewClient(ctx context.Context, config ClientConfig) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	normalizedRelayURL, err := utils.NormalizeRelayURL(config.RelayURL)
	if err != nil {
		return nil, err
	}
	hostname := strings.TrimSpace(config.Hostname)
	if hostname == "" {
		return nil, errLocalHostnameIsRequired
	}
	client := &Client{
		accessToken:           strings.TrimSpace(config.AccessToken),
		installedCertificates: config.InstalledCertificates,
		hostname:              hostname,
		nextProtos:            append([]string(nil), config.NextProtos...),
	}

	if len(client.nextProtos) == 0 {
		client.nextProtos = []string{"http/1.1"}
	}
	if (config.CertFile == "") != (config.KeyFile == "") {
		return nil, errTenantCertificatePairRequired
	}
	if config.CertFile != "" {
		client.files = &fileSource{config.CertFile, config.KeyFile, hostname}
	}
	if config.CertificateDir == "" && config.CertFile == "" {
		return nil, errAutomaticCertificateDirectoryRequired
	}
	if config.CertificateDir != "" {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if config.CertFile != "" {
			return nil, errAutomaticAndManualCertificateConflict
		}
		client.automatic = &automaticSource{relayURL: normalizedRelayURL, hostname: hostname, headers: client.headers, certificateDir: config.CertificateDir}
		if client.pin, err = client.automatic.initial(ctx); err != nil {
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

// SetAccessToken updates the credential used by subsequent issuance requests.
func (c *Client) SetAccessToken(token string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.accessToken = strings.TrimSpace(token)
	c.mu.Unlock()
}

// RefreshChain reloads configured files or a persisted automatic bundle.
// It never issues certificates. Invalid replacements
// leave the previous generation intact; existing connections are not restarted.
func (c *Client) RefreshChain(ctx context.Context) (bool, error) {
	return c.refreshChain(ctx, nil)
}

func (c *Client) refreshChain(ctx context.Context, stale *pinnedChain) (bool, error) {
	if !c.refreshMu.TryLock() {
		return false, errAutomaticCertificateBusy
	}
	defer c.refreshMu.Unlock()
	if stale != nil && c.pinned() != stale {
		return false, nil
	}
	next, err := c.loadPin(ctx)
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || (c.pin != nil && bytes.Equal(next.chainPEM, c.pin.chainPEM)) {
		return false, nil
	}
	live := c.retired[:0]
	for _, old := range c.retired {
		if time.Now().Before(old.leaf.NotAfter) {
			live = append(live, old)
		}
	}
	c.retired = live
	if c.pin != nil {
		c.retired = append(c.retired, &pinnedChain{leaf: c.pin.leaf})
	} else if c.ready != nil {
		close(c.ready)
	}
	c.pin = next
	c.publishInstalled(next)
	return true, nil
}

// TerminateConn captures local material for one ordinary crypto/tls connection.
// The connection retains its certificate and key across later rotations.
func (c *Client) TerminateConn(ctx context.Context, raw net.Conn, _ []byte) (net.Conn, error) {
	pin := c.pinned()
	c.mu.RLock()
	protos := append([]string(nil), c.nextProtos...)
	c.mu.RUnlock()
	if pin == nil {
		_ = raw.Close()
		return nil, errLocalClientIsUnavailable
	}
	if time.Now().Before(pin.leaf.NotBefore) || !time.Now().Before(pin.leaf.NotAfter) {
		_ = raw.Close()
		if c.automatic == nil {
			_, _ = c.refreshChain(ctx, pin)
		}
		return nil, errTenantCertificateNotValid
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pin.certificate}, NextProtos: protos,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if hello.ServerName != c.hostname {
				return nil, fmt.Errorf("local TLS SNI does not match service hostname")
			}
			return nil, nil
		}}
	conn := tls.Server(raw, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tenant tls handshake: %w", err)
	}
	return conn, nil
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

// Close cancels and joins the renewal worker; remote ACME cleanup belongs to the relay.
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
		c.mu.Unlock()
		if c.automatic != nil && c.automatic.done != nil {
			<-c.automatic.done
		}
	})
	return nil
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
		return newLocalPin([]byte(bundle.CertificatePEM), []byte(bundle.KeyPEM), c.hostname)
	}
	if c.files != nil {
		return c.files.acquire()
	}
	return nil, errAutomaticCertificateMissing
}

// TenantTLSConfig verifies self-probes against installed tenant materials,
// including a previous generation still used by an in-flight handshake.
// Prior local generations trust only their exact leaf until expiry.
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
			for _, pin := range pins {
				if pin == nil || pin.leaf == nil || !state.PeerCertificates[0].Equal(pin.leaf) {
					continue
				}
				roots := x509.NewCertPool()
				roots.AddCert(pin.leaf)
				_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
					DNSName: c.hostname, Roots: roots, Intermediates: intermediates,
				})
				if err == nil {
					return nil
				}
				verificationErr = err
			}
			if verificationErr == nil {
				return errLocalClientIsUnavailable
			}
			return verificationErr
		},
	}
}

// publishInstalled runs only while initializing or holding the activation lock.
func (c *Client) publishInstalled(pin *pinnedChain) {
	if c.installedCertificates == nil || pin == nil || pin.leaf == nil {
		return
	}
	select {
	case c.installedCertificates <- append([]byte(nil), pin.leaf.Raw...):
	default:
	}
}

// SetNextProtos selects ALPN for future connections once the HTTP consumer is ready.
func (c *Client) SetNextProtos(protos []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextProtos = append([]string(nil), protos...)
}

// Ready reports whether a new canonical connection can use a current local certificate.
func (c *Client) Ready() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed || c.pin == nil {
		return false
	}
	now := time.Now()
	return !now.Before(c.pin.leaf.NotBefore) && now.Before(c.pin.leaf.NotAfter)
}
