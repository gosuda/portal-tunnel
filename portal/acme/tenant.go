package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"golang.org/x/net/publicsuffix"

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

const tenantBudgetWindow = 7 * 24 * time.Hour

var (
	errTenantStateRequired     = errors.New("public tenant issuance requires a shared tenant issuance state directory")
	errTenantJournalCapacity   = errors.New("tenant order journal capacity exceeded")
	errTenantJournalIncomplete = errors.New("incomplete tenant order journal")
	errTenantJournalEntry      = errors.New("invalid tenant order journal entry")
	errTenantJournalResult     = errors.New("invalid tenant order journal result")
	errTenantJournalDuplicate  = errors.New("duplicate tenant order reservation")
	errTenantIssuedMismatch    = errors.New("issuer returned a mismatched tenant certificate")
)

// Reservations are never refunded, including failed, canceled and ambiguous
// orders. Results only establish eligibility for the separate renewal budget.
// All relays sharing a CA quota must use this same lock-coherent durable file.
type tenantOrderEntry struct {
	ID        string    `json:"id"`
	CA        string    `json:"ca"`
	Domain    string    `json:"domain"`
	Host      string    `json:"host"`
	At        time.Time `json:"at"`
	Renewal   bool      `json:"renewal,omitempty"`
	NotBefore time.Time `json:"not_before,omitempty"`
	NotAfter  time.Time `json:"not_after,omitempty"`
}

type tenantOrderReservation struct {
	file  *os.File
	entry tenantOrderEntry
}

// ValidateTenantIssuanceState checks that public issuance can open its durable
// journal. It may create the journal, but never reserves an order or takes the
// issuance lock: another replica issuing a certificate is not a config error.
func (cfg Config) ValidateTenantIssuanceState() error {
	if utils.IsLocalRelayHost(cfg.BaseDomain) {
		return nil
	}
	if cfg.TenantIssuanceStateDir == "" {
		return errTenantStateRequired
	}
	file, err := os.OpenFile(filepath.Join(cfg.TenantIssuanceStateDir, "tenant-orders.jsonl"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open tenant issuance state: %w", err)
	}
	return file.Close()
}

func (m *Manager) reserveTenantOrder(host string, now time.Time) (*tenantOrderReservation, error) {
	if m.cfg.TenantIssuanceStateDir == "" {
		return nil, errTenantStateRequired
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return nil, err
	}

	file, err := utils.TryLockFile(filepath.Join(m.cfg.TenantIssuanceStateDir, "tenant-orders.jsonl"))
	if err != nil {
		if errors.Is(err, utils.ErrFileLocked) {
			return nil, ErrTenantIssuerBusy
		}
		return nil, err
	}
	reservation := &tenantOrderReservation{file: file, entry: tenantOrderEntry{CA: m.cfg.CADirURL, Domain: domain, Host: host, At: now}}
	if err := reservation.admit(); err != nil {
		_ = file.Close()
		return nil, err
	}

	// Establish the journal directory entry before authorizing a CA order.
	// Windows cannot Sync directories; the operator must provision the state
	// directory durably, and file.Sync flushes the journal data and metadata.
	if runtime.GOOS != "windows" {
		dir, err := os.Open(m.cfg.TenantIssuanceStateDir)
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		err = dir.Sync()
		_ = dir.Close()
		if err != nil {
			_ = file.Close()
			return nil, err
		}
	}
	return reservation, nil
}

func (r *tenantOrderReservation) admit() error {

	data, err := io.ReadAll(io.LimitReader(r.file, (16<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 16<<20 {
		return errTenantJournalCapacity
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		return errTenantJournalIncomplete
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	reservations := make(map[string]tenantOrderEntry)
	results := make(map[string]bool)
	var latest tenantOrderEntry
	var newOrders, renewals, caOrders, hostOrders int
	for {
		var entry tenantOrderEntry
		if err := decoder.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("read tenant order journal: %w", err)
		}
		missingIdentity := entry.ID == "" || entry.CA == "" || entry.Domain == "" || entry.Host == ""
		invalidTime := entry.At.IsZero() || entry.At.After(r.entry.At)
		if missingIdentity || invalidTime {
			return errTenantJournalEntry
		}
		if !entry.NotAfter.IsZero() {
			original, ok := reservations[entry.ID]
			sameOrder := original.CA == entry.CA && original.Domain == entry.Domain && original.Host == entry.Host
			sameReservation := original.At.Equal(entry.At) && original.Renewal == entry.Renewal
			validCertificate := entry.NotAfter.After(entry.NotBefore) && !entry.NotBefore.IsZero() && entry.NotAfter.After(entry.At)
			if !ok || results[entry.ID] || !sameOrder || !sameReservation || !validCertificate {
				return errTenantJournalResult
			}
			results[entry.ID] = true
			matchesHost := entry.CA == r.entry.CA && entry.Host == r.entry.Host
			moreRecent := latest.At.IsZero() || entry.At.After(latest.At)
			if matchesHost && moreRecent {
				latest = entry
			}
			continue
		}
		if _, exists := reservations[entry.ID]; exists {
			return errTenantJournalDuplicate
		}
		reservations[entry.ID] = entry
		if entry.CA != r.entry.CA || r.entry.At.Sub(entry.At) >= tenantBudgetWindow {
			continue
		}
		caOrders++
		if entry.Domain != r.entry.Domain {
			continue
		}
		if entry.Renewal {
			renewals++
		} else {
			newOrders++
		}
		if entry.Host == r.entry.Host {
			hostOrders++
		}
		if entry.Host == r.entry.Host && r.entry.At.Sub(entry.At) < time.Hour {
			return ErrTenantOrderLimited
		}
	}

	r.entry.Renewal = r.entry.At.Before(latest.NotAfter) && !r.entry.At.Before(latest.NotBefore.Add(latest.NotAfter.Sub(latest.NotBefore)*2/3))
	categoryFull := newOrders >= 20
	if r.entry.Renewal {
		categoryFull = renewals >= 10
	}
	if hostOrders >= 3 || caOrders >= 40 || categoryFull {
		return ErrTenantOrderLimited
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	r.entry.ID = hex.EncodeToString(id[:])
	return r.append(r.entry)
}

func (r *tenantOrderReservation) append(entry tenantOrderEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := r.file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	if _, err := r.file.Write(append(data, '\n')); err != nil {
		return err
	}
	return r.file.Sync()
}

func (r *tenantOrderReservation) reconcile(chain []byte, csr *x509.CertificateRequest) error {
	block, _ := pem.Decode(chain)
	if block == nil || block.Type != "CERTIFICATE" {
		return errTenantCertificateMissing
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if leaf.IsCA || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != r.entry.Host || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) || !leaf.NotAfter.After(r.entry.At) {
		return errTenantIssuedMismatch
	}
	entry := r.entry
	entry.NotBefore, entry.NotAfter = leaf.NotBefore, leaf.NotAfter
	return r.append(entry)
}
