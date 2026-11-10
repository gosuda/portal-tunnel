package keyless

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errAutomaticCanonicalHostnameOnly        = errors.New("automatic certificates support only canonical hostnames")
	errAutomaticCertificateDirectoryRequired = errors.New("require-local needs automatic certificate storage or certificate files")
	errAutomaticAndManualCertificateConflict = errors.New("automatic certificate storage cannot be combined with certificate files")
	errAutomaticBundleInvalid                = errors.New("invalid automatic tenant certificate bundle")
	errAutomaticCertificateMissing           = errors.New("automatic tenant certificate is not available yet")
	errAutomaticCertificateBusy              = errors.New("another process is issuing this tenant certificate")
)

// The private key is persisted before contacting the CA, and the completed pair
// replaces the same bundle atomically. Lease credentials never enter this file.
type certificateBundle struct {
	Hostname       string `json:"hostname"`
	KeyPEM         string `json:"key_pem"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
}

func (c *Client) bundlePath() string {
	hash := sha256.Sum256([]byte(c.hostname))
	return filepath.Join(c.certificateDir, hex.EncodeToString(hash[:])+".json")
}

func (c *Client) readBundle() (certificateBundle, error) {
	path := c.bundlePath()
	if err := utils.EnsurePrivateFile(path); err != nil {
		return certificateBundle{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return certificateBundle{}, err
	}
	var bundle certificateBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return bundle, fmt.Errorf("%w: %w", errAutomaticBundleInvalid, err)
	}
	if bundle.Hostname != c.hostname || bundle.KeyPEM == "" {
		return bundle, errAutomaticBundleInvalid
	}
	block, _ := pem.Decode([]byte(bundle.KeyPEM))
	if block == nil {
		return bundle, errAutomaticBundleInvalid
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return bundle, fmt.Errorf("%w: %w", errAutomaticBundleInvalid, err)
	}
	if signer, ok := key.(*ecdsa.PrivateKey); !ok || signer.Curve != elliptic.P256() {
		return bundle, errAutomaticBundleInvalid
	}
	return bundle, nil
}

func (c *Client) saveBundle(bundle certificateBundle) error {
	data, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(c.certificateDir, ".tenant-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if err := utils.EnsurePrivateFile(name); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name, c.bundlePath())
}

func (c *Client) startAutomatic(ctx context.Context, requireLocal bool) error {
	if c.alternativeHostname != "" {
		return errAutomaticCanonicalHostnameOnly
	}
	if err := utils.EnsurePrivateDir(c.certificateDir); err != nil {
		return err
	}
	bundle, err := c.readBundle()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err // Corrupt state never selects the bootstrap path.
	}
	if err == nil && bundle.CertificatePEM != "" {
		c.pin, err = c.localPin([]byte(bundle.CertificatePEM), []byte(bundle.KeyPEM))
		// An expired certificate needs renewal, but other corrupt material
		// requires repair rather than silently downgrading or replacing a key.
		if err != nil {
			var invalid x509.CertificateInvalidError
			if !errors.As(err, &invalid) || invalid.Reason != x509.Expired {
				return err
			}
		}
	}
	c.ready = make(chan struct{})
	if c.pin == nil && !requireLocal && bundle.CertificatePEM == "" {
		chain, err := relayChain(ctx, c.relayURL, c.serverName)
		if err != nil {
			return err
		}
		if c.pin, err = c.newPin(chain); err != nil {
			return err
		}
	}
	if c.pin != nil {
		close(c.ready)
	}
	workerCtx, cancel := context.WithCancel(context.Background())
	c.workerCancel = cancel
	c.workerDone = make(chan struct{})
	go c.maintainCertificate(workerCtx)
	return nil
}

func (c *Client) maintainCertificate(ctx context.Context) {
	defer close(c.workerDone)
	delay := time.Duration(0)
	backoff := time.Minute
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		issueCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		_, err := c.RefreshChain(issueCtx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Warn().Err(err).Str("hostname", c.hostname).Msg("tenant certificate issuance or renewal failed; retaining current TLS material")
			delay = backoff
			backoff = min(2*backoff, time.Hour)
		} else {
			delay, backoff = time.Hour, time.Minute
			if pin := c.pinned(); pin != nil && pin.signer == nil {
				untilRenewal := time.Until(pin.leaf.NotAfter) - pin.leaf.NotAfter.Sub(pin.leaf.NotBefore)/3
				delay = min(delay, max(time.Second, untilRenewal))
			}
		}
	}
}

// automaticPin serializes issuance across processes, reuses the persisted key,
// and never returns relay-backed material. Failure cannot downgrade a live pin.
func (c *Client) automaticPin(ctx context.Context) (*pinnedChain, error) {
	lock, err := lockCertificate(c.bundlePath() + ".lock")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	bundle, err := c.readBundle()
	if errors.Is(err, os.ErrNotExist) {
		key, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if genErr != nil {
			return nil, genErr
		}
		der, marshalErr := x509.MarshalPKCS8PrivateKey(key)
		if marshalErr != nil {
			return nil, marshalErr
		}
		bundle = certificateBundle{Hostname: c.hostname, KeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))}
		if err := c.saveBundle(bundle); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if bundle.CertificatePEM != "" {
		pin, err := c.localPin([]byte(bundle.CertificatePEM), []byte(bundle.KeyPEM))
		if err == nil {
			renewBefore := pin.leaf.NotAfter.Sub(pin.leaf.NotBefore) / 3
			if time.Until(pin.leaf.NotAfter) > renewBefore {
				return pin, nil
			}
		}
	}
	block, _ := pem.Decode([]byte(bundle.KeyPEM))
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{c.hostname}}, key)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(types.TenantCertificateRequest{CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))})
	if err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(c.relayURL)
	if err != nil {
		return nil, err
	}
	tlsConfig, httpClient, transport, err := utils.NewHTTPTLSClient(ctx, endpoint, 2*time.Minute)
	if err != nil {
		return nil, err
	}
	defer transport.CloseIdleConnections()
	// Never forward the lease credential across a redirect.
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	endpoint.Path, endpoint.RawPath, endpoint.RawQuery = types.PathV1TenantCertificate, "", ""
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = c.headers()
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, utils.DecodeAPIRequestError(resp)
	}
	var envelope types.APIEnvelope[types.TenantCertificateResponse]
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128<<10)).Decode(&envelope); err != nil {
		return nil, err
	}
	if !envelope.OK || envelope.Data.CertificatePEM == "" {
		return nil, errAutomaticCertificateMissing
	}
	chain := []byte(envelope.Data.CertificatePEM)
	pair, err := tls.X509KeyPair(chain, []byte(bundle.KeyPEM))
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		intermediates.AddCert(cert)
	}
	// Production uses system trust. Local development uses only the existing
	// local relay CA; the returned bundle cannot introduce another trust root.
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: c.hostname, Roots: tlsConfig.RootCAs, Intermediates: intermediates}); err != nil {
		return nil, fmt.Errorf("verify issued tenant certificate: %w", err)
	}
	pin, err := c.localPin(chain, []byte(bundle.KeyPEM))
	if err != nil {
		return nil, err
	}
	bundle.CertificatePEM = string(chain)
	if err := c.saveBundle(bundle); err != nil {
		return nil, err
	}
	return pin, nil
}

// WaitReady gates traffic until require-local initialization has a usable
// certificate. Lease renewal remains the SDK's responsibility while this waits.
func (c *Client) WaitReady(ctx context.Context) error {
	if c.pinned() != nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ready:
		return nil
	case <-c.workerDone:
		return errKeylessClientIsUnavailable
	}
}
