// Package ctmonitor audits public Certificate Transparency observations against verified PGNS SMT state.
package ctmonitor

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/gosuda/portal-tunnel/v2/pgns"
	"github.com/gosuda/portal-tunnel/v2/types"
)

var (
	// ErrUnauthorizedCertificate marks a CT certificate/precertificate whose SAN or SPKI
	// is not authorized by active verified PGNS leaf state.
	ErrUnauthorizedCertificate = errors.New("ctmonitor: certificate SPKI not authorized by PGNS leaf state")
)

// Monitor compares CT observations for a PGNS zone against witnessed epoch leaf state.
type Monitor struct {
	mu         sync.RWMutex
	zone       string
	witnessSet pgns.WitnessSet
	hasEpoch   bool
	state      pgns.WitnessState
	activeLeaf map[string]pgns.PortalLeafRecord
}

// New creates a deterministic CT monitor bound to zone and ws.
func New(zone string, ws pgns.WitnessSet) (*Monitor, error) {
	normZone, err := pgns.NormalizeZone(zone)
	if err != nil {
		return nil, err
	}
	if err := ws.Validate(); err != nil {
		return nil, err
	}
	return &Monitor{
		zone:       normZone,
		witnessSet: ws,
		activeLeaf: make(map[string]pgns.PortalLeafRecord),
	}, nil
}

// ApplyEpoch verifies a witnessed checkpoint and full batch transition proof, updating
// the active leaf SPKI snapshot synchronously with SMTRoot_e.
func (m *Monitor) ApplyEpoch(rawCheckpoint, rawBatch []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var prevPtr *pgns.WitnessState
	if m.hasEpoch {
		prev := m.state
		prevPtr = &prev
	}
	cp, batch, nextState, err := pgns.VerifyEpochBatch(prevPtr, m.zone, m.witnessSet, rawCheckpoint, rawBatch)
	if err != nil {
		return err
	}
	for _, tx := range batch.TxEntries {
		m.activeLeaf[tx.Leaf.FQDN] = tx.Leaf
	}
	for fqdn, leaf := range m.activeLeaf {
		if cp.Timestamp >= leaf.ExpiresAt {
			delete(m.activeLeaf, fqdn)
		}
	}
	m.hasEpoch = true
	m.state = nextState
	return nil
}

// State returns the latest verified epoch number and SMT root audited by Monitor.
func (m *Monitor) State() (uint64, [32]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.Epoch, m.state.SMTRoot, m.hasEpoch
}

// CheckCertificate validates every SAN in cert targeting this PGNS zone against
// active leaves' (tls_spki_sha256 | next_tls_spki_sha256).
func (m *Monitor) CheckCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("%w: nil certificate", ErrUnauthorizedCertificate)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.hasEpoch {
		return fmt.Errorf("%w: no verified epoch loaded", ErrUnauthorizedCertificate)
	}
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	zoneSuffix := "." + m.zone
	for _, rawName := range cert.DNSNames {
		name := types.NormalizeHostname(rawName)
		if name != m.zone && !strings.HasSuffix(name, zoneSuffix) {
			continue
		}
		if strings.HasPrefix(name, "*.") {
			return fmt.Errorf("%w: wildcard SAN %q forbidden", ErrUnauthorizedCertificate, rawName)
		}
		leaf, ok := m.activeLeaf[name]
		if !ok {
			return fmt.Errorf("%w: unregistered fqdn %q", ErrUnauthorizedCertificate, name)
		}
		if m.state.Timestamp >= leaf.ExpiresAt {
			return fmt.Errorf("%w: expired leaf for %q", ErrUnauthorizedCertificate, name)
		}
		if spki != leaf.TLSSPKISHA256 && (leaf.NextTLSSPKISHA256 == ([32]byte{}) || spki != leaf.NextTLSSPKISHA256) {
			return fmt.Errorf("%w: spki mismatch for %q", ErrUnauthorizedCertificate, name)
		}
	}
	return nil
}
