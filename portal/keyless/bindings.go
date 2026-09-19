package keyless

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	ksigner "github.com/gosuda/keyless_tls/relay/signer"
)

// BindingRegistry owns Portal's connection-binding policy for keyless transcript signing.
type BindingRegistry struct {
	mu      sync.Mutex
	entries map[[16]byte]*bindingEntry
	ttl     time.Duration
}

type bindingEntry struct {
	leaseID   string
	expiresAt time.Time
	helloHash [32]byte
}

// NewBindingRegistry constructs a binding registry with the given lifetime.
func NewBindingRegistry(ttl time.Duration) *BindingRegistry {
	return &BindingRegistry{entries: make(map[[16]byte]*bindingEntry), ttl: ttl}
}

// Issue mints a binding. A nil ClientHello leaves it unusable until FixHello.
func (b *BindingRegistry) Issue(leaseID string, clientHello []byte) [16]byte {
	var binding [16]byte
	if _, err := rand.Read(binding[:]); err != nil {
		panic(fmt.Sprintf("issue lease binding: %v", err))
	}
	var helloHash [32]byte
	if len(clientHello) > 0 {
		helloHash = sha256.Sum256(clientHello)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[binding] = &bindingEntry{leaseID: leaseID, expiresAt: time.Now().Add(b.ttl), helloHash: helloHash}
	return binding
}

// FixHello pins a ClientHello to a binding issued without one.
func (b *BindingRegistry) FixHello(binding [16]byte, clientHello []byte) error {
	if len(clientHello) == 0 {
		return errors.New("client hello span is required")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.entries[binding]
	if !ok {
		return errors.New("binding is unknown")
	}
	if !time.Now().Before(entry.expiresAt) {
		return errors.New("binding is expired")
	}
	if entry.helloHash != ([32]byte{}) {
		return errors.New("binding hello is already fixed")
	}
	entry.helloHash = sha256.Sum256(clientHello)
	return nil
}

// ValidateAndConsume validates the lease and ClientHello and spends the binding.
func (b *BindingRegistry) ValidateAndConsume(binding []byte, leaseID string, clientHello []byte) error {
	if len(binding) != 16 {
		return fmt.Errorf("%w: binding must be 16 bytes", ksigner.ErrPermissionDenied)
	}
	if len(clientHello) == 0 {
		return fmt.Errorf("%w: client hello transcript is required", ksigner.ErrPermissionDenied)
	}
	helloHash := sha256.Sum256(clientHello)
	var key [16]byte
	copy(key[:], binding)
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.entries[key]
	if !ok || !time.Now().Before(entry.expiresAt) {
		return fmt.Errorf("%w: binding is unknown or expired", ksigner.ErrPermissionDenied)
	}
	if entry.leaseID != leaseID {
		return fmt.Errorf("%w: binding does not belong to the signing lease", ksigner.ErrPermissionDenied)
	}
	if entry.helloHash == ([32]byte{}) {
		return fmt.Errorf("%w: binding hello was never fixed", ksigner.ErrPermissionDenied)
	}
	if entry.helloHash != helloHash {
		return fmt.Errorf("%w: client hello does not match the routed connection", ksigner.ErrPermissionDenied)
	}
	delete(b.entries, key)
	return nil
}

// Discard revokes a binding that was not delivered to a live stream.
func (b *BindingRegistry) Discard(binding [16]byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.entries, binding)
}

// SweepExpired reclaims expired, unused bindings.
func (b *BindingRegistry) SweepExpired(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for binding, entry := range b.entries {
		if !now.Before(entry.expiresAt) {
			delete(b.entries, binding)
		}
	}
}
