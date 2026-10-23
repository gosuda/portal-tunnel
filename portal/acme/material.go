package acme

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
)

// TLSMaterial is the relay certificate chain with its private key, as served.
// A renewal replaces the whole value, so the chain, the key and the parsed
// certificate always belong together.
type TLSMaterial struct {
	CertPEM     []byte
	KeyPEM      []byte
	Certificate tls.Certificate
}

type tlsMaterialStore struct {
	current atomic.Pointer[TLSMaterial]
}

// TLSMaterial returns the certificate material the relay is serving, or nil
// until EnsureTLSMaterial has loaded it. A renewal replaces it.
func (m *Manager) TLSMaterial() *TLSMaterial {
	if m == nil {
		return nil
	}
	return m.material.current.Load()
}

// GetCertificate serves the current material to a TLS listener, so a renewed
// certificate is used from the next handshake on, without a restart.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	material := m.TLSMaterial()
	if material == nil {
		return nil, errors.New("relay certificate is not loaded")
	}
	return &material.Certificate, nil
}

// loadTLSMaterial reads the certificate pair and makes it the served material.
// A pair that cannot be read or parsed leaves the previous material in place.
func (m *Manager) loadTLSMaterial(certFile, keyFile string) (*TLSMaterial, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read api tls certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read api tls private key: %w", err)
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse relay api keypair: %w", err)
	}
	material := &TLSMaterial{CertPEM: certPEM, KeyPEM: keyPEM, Certificate: certificate}
	m.material.current.Store(material)
	return material, nil
}
