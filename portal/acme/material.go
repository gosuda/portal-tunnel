package acme

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"
)

// TLSMaterial is the relay certificate chain with its private key, as served.
// A renewal replaces the whole value, so the chain, the key and the parsed
// certificate always belong together.
type TLSMaterial struct {
	CertPEM     []byte
	KeyPEM      []byte
	Certificate tls.Certificate
}

// servedMaterial is the certificate the relay serves now, and the earlier ones
// that tenants may still present: a tenant pins the chain the relay served when
// its lease client was created and keeps presenting it to visitors after a
// renewal replaced it.
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
		return nil, errors.New("relay certificate is not loaded")
	}
	return &material.Certificate, nil
}

// SigningKey returns the private key of the certificate whose leaf is leafDER:
// the one being served, or one served before a renewal for as long as it has
// not expired. A visitor's browser trusts a certificate until it expires, so a
// tenant still presenting it is signed for exactly that long and no longer
// (see serve for what that means after a revocation). Any other certificate
// gets nil.
func (m *Manager) SigningKey(leafDER []byte) crypto.Signer {
	if m == nil {
		return nil
	}
	served := m.material.Load()
	if served.current.holds(leafDER) {
		signer, _ := served.current.Certificate.PrivateKey.(crypto.Signer)
		return signer
	}
	now := time.Now()
	for _, previous := range served.retired {
		if previous.holds(leafDER) && now.Before(previous.Certificate.Leaf.NotAfter) {
			signer, _ := previous.Certificate.PrivateKey.(crypto.Signer)
			return signer
		}
	}
	return nil
}

func (t *TLSMaterial) holds(leafDER []byte) bool {
	return t != nil && bytes.Equal(t.Certificate.Certificate[0], leafDER)
}

// serve makes material the served certificate. The one it replaces stays
// available to SigningKey; certificates that have expired are dropped.
//
// This is built for scheduled renewal, where the replaced certificate is still
// valid and tenants still present it. It keeps the replaced key signing until
// that certificate expires even when the renewal was meant to retire it, as
// after a revocation or a key compromise. For a compromise, restart the relay:
// the retired material lives in memory only, and the restart also drops every
// lease, so tenants re-pin the chain on disk.
func (m *Manager) serve(material *TLSMaterial) {
	now := time.Now()
	m.material.Update(func(served servedMaterial) servedMaterial {
		next := servedMaterial{current: material}
		for _, previous := range slices.Concat(served.retired, []*TLSMaterial{served.current}) {
			if previous != nil && now.Before(previous.Certificate.Leaf.NotAfter) {
				next.retired = append(next.retired, previous)
			}
		}
		return next
	})
}

func newTLSMaterial(certPEM, keyPEM []byte) (*TLSMaterial, error) {
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse relay api keypair: %w", err)
	}
	return &TLSMaterial{CertPEM: certPEM, KeyPEM: keyPEM, Certificate: certificate}, nil
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
	material, err := newTLSMaterial(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	m.serve(material)
	return material, nil
}
