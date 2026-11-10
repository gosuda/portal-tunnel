// Package keyless owns tenant TLS with relay-backed or in-process transcript signing.
package keyless

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	keylesstls "github.com/gosuda/keyless_tls/keyless"
	"github.com/gosuda/keyless_tls/keyless/t13server"
	ksigner "github.com/gosuda/keyless_tls/relay/signer"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
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
	certFile    string
	keyFile     string
	closed      bool
	closeOnce   sync.Once
	closeErr    error

	relayURL            string
	serverName          string
	hostname            string
	alternativeHostname string

	refreshMu      sync.Mutex
	certificateDir string
	workerCancel   context.CancelFunc
	workerDone     chan struct{}
	ready          chan struct{}
}

type pinnedChain struct {
	chainPEM []byte
	server   *t13server.Server
	pool     *x509.CertPool
	signer   io.Closer
	leaf     *x509.Certificate
}

// NewClient loads local material when configured, otherwise pins the relay chain.
// Local file errors fail closed; they never select relay-backed signing.
func NewClient(ctx context.Context, config ClientConfig) (*Client, error) {
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
		return nil, errRelayHostnameIsRequired
	}

	hostname := strings.TrimSpace(config.Hostname)
	if hostname == "" {
		return nil, errKeylessHostnameIsRequired
	}
	client := &Client{
		accessToken:         strings.TrimSpace(config.AccessToken),
		relayURL:            normalizedRelayURL,
		serverName:          serverName,
		hostname:            hostname,
		alternativeHostname: strings.TrimSpace(config.AlternativeHostname),
		certFile:            config.CertFile,
		keyFile:             config.KeyFile,
		certificateDir:      config.CertificateDir,
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if (client.certFile == "") != (client.keyFile == "") {
		return nil, errTenantCertificatePairRequired
	}
	if config.RequireLocal && config.CertificateDir == "" && config.CertFile == "" {
		return nil, errAutomaticCertificateDirectoryRequired
	}
	if config.CertificateDir != "" {
		if config.CertFile != "" {
			return nil, errAutomaticAndManualCertificateConflict
		}
		if err := client.startAutomatic(ctx, config.RequireLocal); err != nil {
			return nil, err
		}
		return client, nil
	}
	if client.pin, err = client.loadPin(ctx); err != nil {
		return nil, err
	}
	return client, nil
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
	leaf, _ := utils.ParseCertificatePEM(chainPEM)
	return &pinnedChain{chainPEM: chainPEM, server: server, pool: pool, signer: remoteSigner, leaf: leaf}, nil
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

// RefreshChain reloads configured local files or the relay chain. Invalid replacements
// leave the previous generation intact; existing connections are not restarted.
func (c *Client) RefreshChain(ctx context.Context) (bool, error) {
	return c.refreshChain(ctx, nil)
}

func (c *Client) refreshChain(ctx context.Context, stale *pinnedChain) (bool, error) {
	if c.pinned() == nil && c.certificateDir == "" {
		return false, errKeylessClientIsUnavailable
	}
	bootstrapRecovery := c.certificateDir != "" && stale != nil && stale.signer != nil
	// Stale bootstrap recovery must not wait for an ACME operation. Its
	// compare-and-swap below cannot overwrite a concurrently activated local pin.
	if !bootstrapRecovery {
		if c.certificateDir != "" {
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
		var chain []byte
		chain, err = relayChain(ctx, c.relayURL, c.serverName)
		if err == nil {
			next, err = c.newPin(chain)
		}
	} else {
		next, err = c.loadPin(ctx)
	}
	var issuanceErr error
	if err != nil && !bootstrapRecovery && c.certificateDir != "" && current != nil && current.signer != nil {
		issuanceErr = err
		// Bootstrap is still allowed: preserve normal relay certificate rotation
		// during an issuance outage. Local activation never takes this path.
		var chain []byte
		chain, err = relayChain(ctx, c.relayURL, c.serverName)
		if err == nil {
			next, err = c.newPin(chain)
		}
	}
	if err != nil {
		return false, errors.Join(issuanceErr, err)
	}
	if current != nil && bytes.Equal(next.chainPEM, current.chainPEM) {
		if next.signer != nil {
			_ = next.signer.Close()
		}
		return false, issuanceErr
	}
	c.mu.Lock()
	if c.closed || (bootstrapRecovery && c.pin != stale) {
		c.mu.Unlock()
		if next.signer != nil {
			_ = next.signer.Close()
		}
		return false, nil
	}
	current = c.pin
	// Retain only public verification material. The handshake owns its server
	// and local key for as long as it needs them.
	live := c.retired[:0]
	for _, old := range c.retired {
		if old.leaf != nil && time.Now().Before(old.leaf.NotAfter) {
			live = append(live, old)
		}
	}
	c.retired = live
	if current != nil {
		c.retired = append(c.retired, &pinnedChain{pool: current.pool, leaf: current.leaf})
	} else if c.ready != nil {
		close(c.ready)
	}
	c.pin = next
	c.mu.Unlock()
	// RemoteSigner.Close only closes idle HTTP connections; it neither cancels
	// an in-flight signature nor prevents one on an already captured server.
	if current != nil && current.signer != nil {
		_ = current.signer.Close()
	}
	return true, issuanceErr
}

func pinIsStale(err error) bool {
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
	if pin.leaf != nil && (time.Now().Before(pin.leaf.NotBefore) || !time.Now().Before(pin.leaf.NotAfter)) {
		_ = raw.Close()
		return nil, errTenantCertificateNotValid
	}
	conn := pin.server.NewConn(raw, binding)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		if pinIsStale(err) {
			if _, refreshErr := c.refreshChain(ctx, pin); refreshErr != nil {
				err = errors.Join(err, fmt.Errorf("refresh tenant certificate chain: %w", refreshErr))
			}
		}
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
		if c.workerCancel != nil {
			c.workerCancel()
		}
		pins := append([]*pinnedChain{c.pin}, c.retired...)
		c.mu.Unlock()
		if c.workerDone != nil {
			<-c.workerDone
		}
		for _, pin := range pins {
			if pin != nil && pin.signer != nil {
				c.closeErr = errors.Join(c.closeErr, pin.signer.Close())
			}
		}
	})
	return c.closeErr
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

// loadPin keeps provisioning separate from the shared tenant handshake engine.
func (c *Client) loadPin(ctx context.Context) (*pinnedChain, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.certificateDir != "" {
		return c.automaticPin(ctx)
	}
	if c.certFile == "" {
		chain, err := relayChain(ctx, c.relayURL, c.serverName)
		if err != nil {
			return nil, err
		}
		return c.newPin(chain)
	}
	certPEM, err := os.ReadFile(c.certFile)
	if err != nil {
		return nil, fmt.Errorf("read tenant certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(c.keyFile)
	if err != nil {
		return nil, fmt.Errorf("read tenant key: %w", err)
	}
	return c.localPin(certPEM, keyPEM)
}

func (c *Client) localPin(certPEM, keyPEM []byte) (*pinnedChain, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load tenant certificate/key: %w", err)
	}
	key, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errTenantKeyCannotSign
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	for i, der := range pair.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		if i == len(pair.Certificate)-1 {
			roots.AddCert(cert)
		} else if i > 0 {
			intermediates.AddCert(cert)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: c.hostname, Roots: roots, Intermediates: intermediates}); err != nil {
		return nil, fmt.Errorf("validate tenant certificate: %w", err)
	}
	if c.alternativeHostname != "" {
		if err := leaf.VerifyHostname(c.alternativeHostname); err != nil {
			return nil, fmt.Errorf("tenant certificate alias: %w", err)
		}
	}
	store := ksigner.NewStaticKeyStore()
	if err := store.Put(types.KeylessRelayKeyID, key); err != nil {
		return nil, err
	}
	service := &ksigner.Service{Store: store}
	server, err := t13server.NewServer(t13server.Config{
		Certificates:     pair.Certificate,
		NextProtos:       []string{"http/1.1"},
		KeyID:            types.KeylessRelayKeyID,
		TranscriptSigner: service,
	})
	if err != nil {
		return nil, fmt.Errorf("create local tenant tls server: %w", err)
	}
	// The exact installed leaf is the probe's trust anchor, not the relay's
	// control-plane certificate or a broader CA capable of issuing other leaves.
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &pinnedChain{chainPEM: certPEM, server: server, pool: pool, leaf: leaf}, nil
}

// TenantTLSConfig verifies self-probes against installed tenant materials,
// including a previous generation still used by an in-flight handshake.
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
				if pin == nil {
					continue
				}
				_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
					DNSName: c.hostname, Roots: pin.pool, Intermediates: intermediates,
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
