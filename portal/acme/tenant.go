package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	ErrTenantIssuanceDisabled   = errors.New("public tenant issuance requires an existing relay ACME account")
	ErrTenantOrderLimited       = errors.New("tenant certificate order budget exhausted")
	errTenantCSRInvalid         = errors.New("invalid tenant certificate request")
	errTenantCSRNames           = errors.New("tenant certificate request contains an unauthorized name")
	errTenantCSRKey             = errors.New("unsupported tenant certificate public key")
	ErrTenantIssuerBusy         = errors.New("certificate issuance is already in progress")
	errTenantCertificateMissing = errors.New("issuer returned no tenant certificate")
)

// ParseTenantCSR accepts an ECDSA P-256 key and one exact authorized canonical
// DNS name, not wildcard, IP, email or URI identities. The common name cannot add
// an order identifier.
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
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errTenantCSRKey
	}
	return csr, nil
}

// TenantIssuanceConfigured reports whether the relay can offer issuance.
func (m *Manager) TenantIssuanceConfigured() bool {
	if m == nil {
		return false
	}
	if utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return true
	}
	_, err := os.Stat(filepath.Join(m.cfg.KeyDir, accountKeyFileName))
	return err == nil && m.cfg.ValidateTenantIssuanceState() == nil
}

// ObtainTenantCertificate completes a lease-authorized CSR using the relay's
// existing ACME account and DNS provider. The caller must first authenticate
// lease ownership and validate this CSR with ParseTenantCSR. Only public material
// is returned.
func (m *Manager) ObtainTenantCertificate(ctx context.Context, csr *x509.CertificateRequest) ([]byte, error) {
	if m == nil {
		return nil, errACMEManagerIsNil
	}
	// Maintenance also provisions relay certificates, so wait for the DNS
	// owner before acquiring issuanceMu.
	if csr != nil && len(csr.DNSNames) == 1 && !utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		if err := m.waitLeaseDNS(ctx, csr.DNSNames[0]); err != nil {
			return nil, err
		}
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
	// Only relay provisioning may create the account key. Opening the existing
	// key without a create fallback also keeps manual certificate rotation safe.
	user, registrationFile, err := m.newClientLoadUser(defaultACMEEmailPrefix+m.cfg.BaseDomain, false)
	if err != nil {
		return nil, err
	}
	reservation, err := m.reserveTenantOrder(csr.DNSNames[0], time.Now())
	if err != nil {
		return nil, err
	}
	defer reservation.file.Close()
	client, err := m.newClientWithLoadedUser(ctx, user, registrationFile)
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
	if err := reservation.reconcile(obtained.Certificate, csr); err != nil {
		return nil, err
	}
	return obtained.Certificate, nil
}
