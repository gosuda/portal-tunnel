package keyless

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/gosuda/keyless_tls/keyless/t13server"
	ksigner "github.com/gosuda/keyless_tls/relay/signer"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// ErrLocalCertificate identifies invalid manual certificate material, including
// a certificate that does not cover a relay's assigned tenant hostname.
// Retrying relay registration cannot repair this local configuration.
var ErrLocalCertificate = errors.New("invalid local tenant certificate")

// ValidateCertificateFiles checks a manual certificate/key pair before relay
// registration. Hostname coverage is checked when the relay assigns its names.
func ValidateCertificateFiles(certFile, keyFile string) error {
	_, err := loadLocalPin(certFile, keyFile, "", "")
	return err
}

func loadLocalPin(certFile, keyFile, hostname, alternativeHostname string) (*pinnedChain, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("%w: read tenant certificate: %w", ErrLocalCertificate, err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("%w: read tenant key: %w", ErrLocalCertificate, err)
	}
	pin, err := newLocalPin(certPEM, keyPEM, hostname, alternativeHostname)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLocalCertificate, err)
	}
	return pin, nil
}

func newLocalPin(certPEM, keyPEM []byte, hostname, alternativeHostname string) (*pinnedChain, error) {
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
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: hostname, Roots: roots, Intermediates: intermediates}); err != nil {
		return nil, fmt.Errorf("validate tenant certificate: %w", err)
	}
	if alternativeHostname != "" {
		if err := leaf.VerifyHostname(alternativeHostname); err != nil {
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
	return &pinnedChain{chainPEM: certPEM, server: server, pool: pool, leaf: leaf, local: true}, nil
}
