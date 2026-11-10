package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	ErrTenantOrderLimited       = errors.New("tenant hostname certificate order budget exhausted")
	errTenantCSRInvalid         = errors.New("invalid tenant certificate request")
	errTenantCSRNames           = errors.New("tenant certificate request contains an unauthorized name")
	errTenantCSRKey             = errors.New("unsupported tenant certificate public key")
	ErrTenantIssuerBusy         = errors.New("certificate issuance is already in progress")
	errTenantCertificateMissing = errors.New("issuer returned no tenant certificate")
)

// ParseTenantCSR accepts one exact authorized canonical DNS name, not wildcard,
// IP, email or URI identities. The common name cannot add an order identifier.
func ParseTenantCSR(encoded string, allowed []string) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errTenantCSRInvalid
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errTenantCSRInvalid, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %w", errTenantCSRInvalid, err)
	}
	if len(csr.DNSNames) != 1 || len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 {
		return nil, errTenantCSRNames
	}
	for _, name := range csr.DNSNames {
		if name == "" || strings.Contains(name, "*") || name != utils.NormalizeHostname(name) || !slices.Contains(allowed, name) {
			return nil, errTenantCSRNames
		}
	}
	if csr.Subject.CommonName != "" && !slices.Contains(csr.DNSNames, csr.Subject.CommonName) {
		return nil, errTenantCSRNames
	}
	// Unknown extensions cannot smuggle additional identity or CA constraints.
	seenSAN := false
	for _, extension := range csr.Extensions {
		if seenSAN || !extension.Id.Equal([]int{2, 5, 29, 17}) {
			return nil, errTenantCSRInvalid
		}
		seenSAN = true
		var names []asn1.RawValue
		rest, err := asn1.Unmarshal(extension.Value, &names)
		if err != nil || len(rest) != 0 {
			return nil, errTenantCSRInvalid
		}
		if len(names) != len(csr.DNSNames) {
			return nil, errTenantCSRInvalid
		}
		for _, name := range names {
			if name.Class != asn1.ClassContextSpecific || name.Tag != 2 || name.IsCompound {
				return nil, errTenantCSRNames
			}
			rawName := string(name.Bytes)
			if !slices.Contains(allowed, rawName) || !slices.Contains(csr.DNSNames, rawName) {
				return nil, errTenantCSRNames
			}
		}
	}
	switch key := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() {
			return nil, errTenantCSRKey
		}
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 || key.N.BitLen() > 4096 {
			return nil, errTenantCSRKey
		}
	case ed25519.PublicKey:
	default:
		return nil, errTenantCSRKey
	}
	return csr, nil
}

// ObtainTenantCertificate completes a lease-authorized CSR using the relay's
// existing ACME account and DNS provider. The caller must first authenticate
// lease ownership and validate this CSR with ParseTenantCSR. Only public material
// is returned.
func (m *Manager) ObtainTenantCertificate(ctx context.Context, csr *x509.CertificateRequest) ([]byte, error) {
	if m == nil {
		return nil, errACMEManagerIsNil
	}
	if !m.issuanceMu.TryLock() {
		return nil, ErrTenantIssuerBusy
	}
	defer m.issuanceMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		material := m.TLSMaterial()
		if material == nil {
			return nil, errRelayCertificateIsNotLoaded
		}
		ca := material.Certificate.Leaf
		if ca == nil {
			var err error
			ca, err = x509.ParseCertificate(material.Certificate.Certificate[0])
			if err != nil {
				return nil, err
			}
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, err
		}
		notAfter := time.Now().Add(24 * time.Hour)
		if ca.NotAfter.Before(notAfter) {
			notAfter = ca.NotAfter
		}
		leaf := &x509.Certificate{
			SerialNumber: serial, DNSNames: slices.Clone(csr.DNSNames),
			NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, material.Certificate.PrivateKey)
		if err != nil {
			return nil, err
		}
		return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), material.CertPEM...), nil
	}
	now := time.Now()
	for name, attemptedAt := range m.tenantOrderAttempts {
		if now.Sub(attemptedAt) >= time.Hour {
			delete(m.tenantOrderAttempts, name)
		}
	}
	for _, name := range csr.DNSNames {
		if _, limited := m.tenantOrderAttempts[name]; limited {
			return nil, ErrTenantOrderLimited
		}
	}
	if len(m.tenantOrderAttempts)+len(csr.DNSNames) > 4096 {
		return nil, ErrTenantOrderLimited
	}
	if m.tenantOrderAttempts == nil {
		m.tenantOrderAttempts = make(map[string]time.Time)
	}
	for _, name := range csr.DNSNames {
		m.tenantOrderAttempts[name] = now
	}
	client, err := m.newClient(ctx)
	if err != nil {
		return nil, err
	}
	obtained, err := client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{CSR: csr, Bundle: true})
	if err != nil {
		return nil, fmt.Errorf("obtain tenant certificate: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if obtained == nil || len(obtained.Certificate) == 0 {
		return nil, errTenantCertificateMissing
	}
	return obtained.Certificate, nil
}
