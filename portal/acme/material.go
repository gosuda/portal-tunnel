package acme

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/rs/zerolog/log"
)

var errRelayCertificateIsNotLoaded = errors.New("relay certificate is not loaded")

// TLSMaterial is the relay certificate chain with its private key, as served.
// A renewal replaces the whole value, so the chain PEM and the parsed
// certificate with its key always belong together.
type TLSMaterial struct {
	CertPEM     []byte
	Certificate tls.Certificate
}

type servedMaterial struct {
	current *TLSMaterial
	retired []*TLSMaterial
}

// TLSMaterial returns the certificate material the relay is serving, or nil
// until EnsureTLSMaterial has loaded it. A renewal replaces it.
func (m *Manager) TLSMaterial() *TLSMaterial {
	if m == nil {
		return nil
	}
	return m.material.Load().current
}

// GetCertificate serves the current material to a TLS listener, so a renewed
// certificate is used from the next handshake on, without a restart.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	material := m.TLSMaterial()
	if material == nil {
		return nil, errRelayCertificateIsNotLoaded
	}
	return &material.Certificate, nil
}

// SigningKey returns the private key of the certificate whose leaf is leafDER:
// the one being served, or one served before a renewal for as long as it has
// not expired. Any other certificate gets nil.
func (m *Manager) SigningKey(leafDER []byte) crypto.Signer {
	if m == nil {
		return nil
	}
	for _, material := range m.material.Load().signable(time.Now()) {
		if material.holds(leafDER) {
			signer, _ := material.Certificate.PrivateKey.(crypto.Signer)
			return signer
		}
	}
	return nil
}

func (s servedMaterial) signable(now time.Time) []*TLSMaterial {
	var signable []*TLSMaterial
	if s.current != nil {
		signable = append(signable, s.current)
	}
	for _, previous := range s.retired {
		if now.Before(previous.Certificate.Leaf.NotAfter) {
			signable = append(signable, previous)
		}
	}
	return signable
}

// TenantTLSConfig is the configuration of a TLS client that reaches a tenant
// presenting a relay certificate under serverName, as the cache fallback does.
// It trusts exactly the certificates SigningKey signs for, each leaf as its own
// root: a tenant may still present a chain that a renewal replaced.
func (m *Manager) TenantTLSConfig(serverName string) *tls.Config {
	roots := x509.NewCertPool()
	if m != nil {
		for _, material := range m.material.Load().signable(time.Now()) {
			roots.AddCert(material.Certificate.Leaf)
		}
	}
	return &tls.Config{ServerName: serverName, RootCAs: roots, MinVersion: tls.VersionTLS12}
}

func (t *TLSMaterial) holds(leafDER []byte) bool {
	return t != nil && bytes.Equal(t.Certificate.Certificate[0], leafDER)
}

func (m *Manager) serve(material *TLSMaterial) {
	replaced := m.TLSMaterial()
	now := time.Now()
	m.material.Update(func(served servedMaterial) servedMaterial {
		next := servedMaterial{current: material}
		for _, previous := range slices.Concat(served.retired, []*TLSMaterial{served.current}) {
			if previous != nil && now.Before(previous.Certificate.Leaf.NotAfter) && !previous.holds(material.Certificate.Certificate[0]) {
				next.retired = append(next.retired, previous)
			}
		}
		return next
	})
	if replaced != nil && !replaced.holds(material.Certificate.Certificate[0]) && !material.TrustedBy(replaced.CertPEM, m.cfg.BaseDomain) {
		log.Warn().
			Str("base_domain", m.cfg.BaseDomain).
			Msg("renewed relay certificate does not chain to the replaced one's issuer: tenants on older SDKs pinned to the previous chain must re-register, which their next lease renewal asks them to; restart the relay to re-pin them all at once")
	}
}

// TrustedBy reports whether a client that pinned the relay chain pinnedPEM
// accepts t as the certificate of serverName, trusting the pinned certificates
// as roots the way the /v1/sign connection of an SDK that cannot re-pin does. A
// renewal by the same intermediate passes; one by another intermediate does not.
func (t *TLSMaterial) TrustedBy(pinnedPEM []byte, serverName string) bool {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pinnedPEM) {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, der := range t.Certificate.Certificate[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return false
		}
		intermediates.AddCert(certificate)
	}
	_, err := t.Certificate.Leaf.Verify(x509.VerifyOptions{DNSName: serverName, Roots: roots, Intermediates: intermediates})
	return err == nil
}

func newTLSMaterial(certPEM, keyPEM []byte) (*TLSMaterial, error) {
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse relay api keypair: %w", err)
	}
	return &TLSMaterial{CertPEM: certPEM, Certificate: certificate}, nil
}

func (m *Manager) loadTLSMaterial(certFile, keyFile string) error {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("read api tls certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("read api tls private key: %w", err)
	}
	material, err := newTLSMaterial(certPEM, keyPEM)
	if err != nil {
		return err
	}
	m.serve(material)
	return nil
}
