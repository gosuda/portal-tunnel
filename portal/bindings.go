package portal

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	ksigner "github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

// defaultBindingTTL bounds how long a minted connection binding stays
// valid: long enough to cover the tenant handshake that presents it,
// short enough that stale bindings die on their own.
const defaultBindingTTL = 5 * time.Minute

// bindingSize is the wire width of a connection binding. It matches the
// 16 bytes the TLS activation framing carries between relay and tenant.
const bindingSize = 16

type signLeaseIDContextKey struct{}

// withSignLeaseID stashes the token-verified lease of a /v1/sign request
// in its context; the transcript validator reads it back.
func withSignLeaseID(ctx context.Context, leaseID string) context.Context {
	return context.WithValue(ctx, signLeaseIDContextKey{}, leaseID)
}

func signLeaseIDFromContext(ctx context.Context) string {
	leaseID, _ := ctx.Value(signLeaseIDContextKey{}).(string)
	return leaseID
}

// bindingRegistry mints the per-connection 16-byte bindings that ride the
// reverse-session framing to the tenant and must be presented back on every
// /v1/sign request. A binding is live for one TTL window, owned by exactly
// one lease, and consumed by exactly one transcript signature.
type bindingRegistry struct {
	mu      sync.Mutex
	entries map[[16]byte]*bindingEntry
	ttl     time.Duration
}

type bindingEntry struct {
	leaseID   string
	expiresAt time.Time
	consumed  bool
}

func newBindingRegistry(ttl time.Duration) *bindingRegistry {
	return &bindingRegistry{
		entries: make(map[[16]byte]*bindingEntry),
		ttl:     ttl,
	}
}

// issue mints a fresh binding for leaseID. Output is 128 bits of
// crypto/rand, so a collision would replace an unconsumed entry with an
// equivalent fresh one and never resurrect a consumed binding.
func (b *bindingRegistry) issue(leaseID string) [16]byte {
	var binding [16]byte
	if _, err := rand.Read(binding[:]); err != nil {
		// crypto/rand failure is unrecoverable process state; the zero
		// binding must never validate.
		panic(fmt.Sprintf("issue lease binding: %v", err))
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[binding] = &bindingEntry{leaseID: leaseID, expiresAt: time.Now().Add(b.ttl)}
	return binding
}

// validateAndConsume accepts exactly one signature per binding, only while
// it is unexpired and only for the lease it was issued to. Errors wrap
// ksigner.ErrPermissionDenied so the sign endpoint answers 403.
func (b *bindingRegistry) validateAndConsume(binding []byte, leaseID string) error {
	if len(binding) != bindingSize {
		return fmt.Errorf("%w: binding must be %d bytes", ksigner.ErrPermissionDenied, bindingSize)
	}
	var key [16]byte
	copy(key[:], binding)

	b.mu.Lock()
	defer b.mu.Unlock()

	entry, ok := b.entries[key]
	if !ok || entry.consumed || !time.Now().Before(entry.expiresAt) {
		return fmt.Errorf("%w: binding is unknown, expired, or already used", ksigner.ErrPermissionDenied)
	}
	if entry.leaseID != leaseID {
		return fmt.Errorf("%w: binding does not belong to the signing lease", ksigner.ErrPermissionDenied)
	}
	entry.consumed = true
	return nil
}

// sweepExpired drops entries past their expiry. Expiry is already enforced
// on lookup, so the sweep only reclaims memory between janitor ticks.
func (b *bindingRegistry) sweepExpired(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for binding, entry := range b.entries {
		if !now.Before(entry.expiresAt) {
			delete(b.entries, binding)
		}
	}
}

// transcriptValidator gates /v1/sign transcript signatures on the relay
// binding: the token-verified request lease must own a live, unconsumed
// binding, and presenting it consumes it. This is the fail-closed half that
// keeps relay key possession from being usable without a routed connection.
func (s *Server) transcriptValidator() ksigner.TranscriptValidatorFunc {
	return func(ctx context.Context, req *signrpc.TranscriptSignRequest) error {
		leaseID := signLeaseIDFromContext(ctx)
		if leaseID == "" {
			return fmt.Errorf("%w: signing request is not bound to a verified lease", ksigner.ErrPermissionDenied)
		}
		return s.registry.bindings.validateAndConsume(req.Binding, leaseID)
	}
}
