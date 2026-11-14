package localtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// ErrLocalCertificate identifies invalid manual configuration at initial
// validation or a certificate that cannot cover the assigned service.
// Runtime file rotation failures are not terminal configuration errors.
var ErrLocalCertificate = errors.New("invalid local tenant certificate")

// ValidateCertificateFiles checks a manual certificate/key pair before relay
// registration. Hostname coverage is checked when the relay assigns its names.
func ValidateCertificateFiles(certFile, keyFile string) error {
	_, err := loadLocalPin(certFile, keyFile, "")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLocalCertificate, err)
	}
	return nil
}

func loadLocalPin(certFile, keyFile, hostname string) (*pinnedChain, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read tenant certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read tenant key: %w", err)
	}
	return newLocalPin(certPEM, keyPEM, hostname)
}

func newLocalPin(certPEM, keyPEM []byte, hostname string) (*pinnedChain, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load tenant certificate/key: %w", err)
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
	exactDNSName := len(leaf.DNSNames) == 1 && leaf.DNSNames[0] == hostname
	hasOtherNames := len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0
	if hostname != "" && (!exactDNSName || hasOtherNames) {
		if err := leaf.VerifyHostname(hostname); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrLocalCertificate, err)
		}
		return nil, fmt.Errorf("%w: certificate must contain only the exact service DNS name", ErrLocalCertificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: hostname, Roots: roots, Intermediates: intermediates}); err != nil {
		return nil, fmt.Errorf("validate tenant certificate: %w", err)
	}
	pair.Leaf = leaf
	// The exact installed leaf is the probe's trust anchor, not the relay's
	// control-plane certificate or a broader CA capable of issuing other leaves.
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &pinnedChain{chainPEM: certPEM, certificate: pair, pool: pool, leaf: leaf}, nil
}
