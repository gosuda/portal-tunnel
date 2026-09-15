// Package keyless owns Portal's tenant TLS feature boundary: keyless remote
// signing for relay-facing TLS, TLS config construction, and the ECH
// (Encrypted Client Hello) material and routing semantics that keep tenant
// hostnames private on that TLS path. The SDK and the relay own when and why
// these operations happen (lease sessions, DNS publication, TLS listeners);
// this package owns the tenant TLS protocol itself.
package keyless

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	keylesstls "github.com/gosuda/keyless_tls/keyless"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// ClientConfig contains the lease-scoped inputs for a tenant TLS client.
type ClientConfig struct {
	RelayURL    string
	Hostname    string
	ECH         ECHMaterials
	AccessToken string
}

// Client owns the tenant TLS configuration and the remote signer that keeps
// it usable. Access tokens can be updated without rebuilding the TLS client.
type Client struct {
	mu          sync.RWMutex
	accessToken string
	tlsConfig   *tls.Config
	signer      io.Closer
	closeOnce   sync.Once
	closeErr    error
}

// NewClient creates one lease-scoped tenant TLS client.
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

	certPEM, rootCAPEM, err := ResolveMaterials(context.Background(), normalizedRelayURL, serverName)
	if err != nil {
		return nil, fmt.Errorf("prepare keyless materials: %w", err)
	}
	hostname := strings.TrimSpace(config.Hostname)
	if hostname == "" {
		return nil, errors.New("keyless hostname is required")
	}
	if verifyErr := VerifyCertificateHostname(certPEM, hostname); verifyErr != nil {
		return nil, fmt.Errorf("keyless certificate does not cover %s: %w", hostname, verifyErr)
	}
	client := &Client{accessToken: strings.TrimSpace(config.AccessToken)}

	remoteSigner, err := keylesstls.NewRemoteSigner(keylesstls.RemoteSignerConfig{
		Endpoint:   normalizedRelayURL,
		ServerName: serverName,
		KeyID:      RelayKeyID,
		RootCAPEM:  rootCAPEM,
		Headers:    client.headers,
	}, certPEM)
	if err != nil {
		return nil, fmt.Errorf("create keyless remote signer: %w", err)
	}

	if err := verifyRemoteSigner(remoteSigner); err != nil {
		_ = remoteSigner.Close()
		return nil, fmt.Errorf("keyless signer self-test against %s failed: %w", serverName, err)
	}

	tlsConfig, err := keylesstls.NewServerTLSConfig(keylesstls.ServerTLSConfig{
		CertPEM:                  certPEM,
		Signer:                   remoteSigner,
		NextProtos:               []string{"http/1.1"},
		MinVersion:               MinTLSVersion(len(config.ECH.Keys) > 0),
		EncryptedClientHelloKeys: config.ECH.Keys,
	})
	if err != nil {
		_ = remoteSigner.Close()
		return nil, fmt.Errorf("create keyless tls config: %w", err)
	}
	client.tlsConfig = tlsConfig
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

// TLSConfig returns a clone safe for one listener session.
func (c *Client) TLSConfig() *tls.Config {
	if c == nil || c.tlsConfig == nil {
		return nil
	}
	return c.tlsConfig.Clone()
}

// Close releases the remote signer backing the TLS configuration. It is safe
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

func ResolveMaterials(ctx context.Context, endpoint, serverName string) ([]byte, []byte, error) {
	chainPEM, err := utils.FetchEndpointCertificateChain(ctx, endpoint, serverName)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch signer certificate chain: %w", err)
	}
	if len(chainPEM) == 0 {
		return nil, nil, errors.New("keyless certificate chain is required")
	}
	return bytes.Clone(chainPEM), bytes.Clone(chainPEM), nil
}

func VerifyCertificateHostname(certPEM []byte, hostname string) error {
	leaf, err := utils.ParseCertificatePEM(certPEM)
	if err != nil {
		return err
	}
	return leaf.VerifyHostname(hostname)
}

// errSignerKeyMismatch reports the verified fact that the relay's /v1/sign
// endpoint returned a signature that does not verify against the certificate
// pinned from the relay's HTTPS endpoint. In #377 the cause was a terminating
// proxy and the relay signer holding different keypairs, but the check itself
// cannot distinguish that from any other signer/certificate divergence, so
// the error only states the mismatch and points operators at the known cause
// as something to check. Sign-RPC failures are not this error; only a
// returned signature that fails verification is.
var errSignerKeyMismatch = errors.New("keyless signer does not match the pinned relay certificate; check whether a terminating proxy and the relay signer use different keypairs")

// verifyRemoteSigner probes signer with a one-off random challenge and checks
// the returned signature against the signer's advertised public key — for a
// RemoteSigner, the key parsed from the pinned certificate. The #377 failure
// mode — a terminating proxy presenting certificate A while the relay's
// keyless signer holds keypair B — otherwise surfaces only as an opaque TLS
// "bad signature" alert on every tenant handshake. One probe at configuration
// time turns it into an actionable startup error; healthy deployments pay a
// single extra /v1/sign round trip, bounded by the signer's call timeout.
func verifyRemoteSigner(signer crypto.Signer) error {
	pinned := signer.Public()
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("generate self-test challenge: %w", err)
	}
	digest := sha256.Sum256(challenge)

	// The probe fixes the scheme itself: RSA-PSS with hash-length salt — the
	// CertificateVerify scheme TLS 1.3 uses and the salt length the relay
	// signer applies — or ECDSA, both over SHA-256. The /v1/sign protocol
	// cannot sign for any other key type.
	switch key := pinned.(type) {
	case *rsa.PublicKey:
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
		signature, err := signer.Sign(rand.Reader, digest[:], opts)
		if err != nil {
			return fmt.Errorf("sign self-test challenge: %w", err)
		}
		if err := rsa.VerifyPSS(key, crypto.SHA256, digest[:], signature, opts); err != nil {
			return fmt.Errorf("%w: %w", errSignerKeyMismatch, err)
		}
	case *ecdsa.PublicKey:
		signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return fmt.Errorf("sign self-test challenge: %w", err)
		}
		if !ecdsa.VerifyASN1(key, digest[:], signature) {
			return fmt.Errorf("%w: ecdsa signature verification failed", errSignerKeyMismatch)
		}
	default:
		return fmt.Errorf("key type %T not supported by the keyless sign protocol", pinned)
	}
	return nil
}
