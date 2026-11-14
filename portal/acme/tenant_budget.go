package acme

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

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
	// The directory is operator-provisioned. Persist the new journal entry
	// before allowing any CA work, including on its first creation.
	if err := syncTenantJournalDirectory(m.cfg.TenantIssuanceStateDir); err != nil {
		_ = file.Close()
		return nil, err
	}
	return reservation, nil
}

func (r *tenantOrderReservation) admit() error {
	// A corrupt or unexpectedly large journal fails closed; never reset it to
	// regain capacity. Reads and append+fsync share the operating-system lock.
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
	// A new key/CSR is never a CA-exempt renewal. Only our successful issuance
	// history reaching two thirds of its lifetime qualifies for reserved capacity.
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
