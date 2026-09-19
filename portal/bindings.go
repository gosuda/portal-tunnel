package portal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
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

// Layout of the first TLS record on a routed connection: a 5-byte record
// header wrapping one complete ClientHello handshake message (1 type byte +
// 3-byte length + body). Routing only accepts connections whose ClientHello
// parses from this single record, which is what makes the relay-observed
// bytes comparable to the tenant-side transcript.
const (
	tlsRecordHeaderLen          = 5
	tlsContentTypeHandshake     = 22
	tlsHandshakeTypeClientHello = 1
)

// helloSpanFromFirstRecord extracts the exact ClientHello handshake-message
// bytes that t13server hashes into a transcript signature: skip the record
// header, take the 4-byte handshake header, and cut the span at its declared
// message length. The returned span equals TranscriptSignRequest.ClientHello
// for the same connection.
func helloSpanFromFirstRecord(record []byte) ([]byte, error) {
	if len(record) < tlsRecordHeaderLen+4 {
		return nil, errors.New("first TLS record is too short for a client hello")
	}
	if record[0] != tlsContentTypeHandshake {
		return nil, errors.New("first TLS record is not a handshake record")
	}
	body := record[tlsRecordHeaderLen:]
	if body[0] != tlsHandshakeTypeClientHello {
		return nil, errors.New("first handshake message is not a client hello")
	}
	msgLen := int(body[1]&0x7f)<<16 | int(body[2])<<8 | int(body[3])
	if msgLen <= 0 || 4+msgLen > len(body) {
		return nil, errors.New("client hello handshake message is incomplete")
	}
	return body[:4+msgLen], nil
}

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
// one lease, pinned to the sha256 of one ClientHello transcript, and spent
// by exactly one transcript signature.
type bindingRegistry struct {
	mu      sync.Mutex
	entries map[[16]byte]*bindingEntry
	ttl     time.Duration
}

type bindingEntry struct {
	leaseID   string
	expiresAt time.Time
	// helloHash pins the binding to the ClientHello of the connection it
	// was minted for. Zero means the hello is not fixed yet; validation
	// always denies a pending binding.
	helloHash [32]byte
}

func newBindingRegistry(ttl time.Duration) *bindingRegistry {
	return &bindingRegistry{
		entries: make(map[[16]byte]*bindingEntry),
		ttl:     ttl,
	}
}

// issue mints a fresh binding for leaseID. clientHello is the relay-observed
// ClientHello span routed with the connection; nil is reserved for the
// relay-self-initiated cache path, where the relay itself is the TLS client
// and no routed hello exists yet — such bindings stay unusable until fixHello
// pins the relay's own hello. Output is 128 bits of crypto/rand, so a
// collision would replace an unconsumed entry with an equivalent fresh one
// and never resurrect a consumed binding.
func (b *bindingRegistry) issue(leaseID string, clientHello []byte) [16]byte {
	var binding [16]byte
	if _, err := rand.Read(binding[:]); err != nil {
		// crypto/rand failure is unrecoverable process state; the zero
		// binding must never validate.
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

// fixHello pins clientHello onto a binding issued without one. It fails for
// unknown or expired bindings and refuses to overwrite an already-fixed
// hello. On the cache path the relay fixes before the SDK ever sees the
// ClientHello, so a failed fix leaves the binding permanently unusable and
// every /v1/sign against it denied.
func (b *bindingRegistry) fixHello(binding [16]byte, clientHello []byte) error {
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

// validateAndConsume accepts exactly one signature per binding, only while
// it is unexpired, only for the lease it was issued to, and only for the
// exact ClientHello transcript the binding was pinned to — a signature over
// another connection's handshake must never validate. A successful
// validation deletes the entry outright, so consumption is immediate rather
// than deferred to the TTL sweep. Errors wrap ksigner.ErrPermissionDenied so
// the sign endpoint answers 403.
func (b *bindingRegistry) validateAndConsume(binding []byte, leaseID string, clientHello []byte) error {
	if len(binding) != bindingSize {
		return fmt.Errorf("%w: binding must be %d bytes", ksigner.ErrPermissionDenied, bindingSize)
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

// discard removes a binding outright. It reclaims a binding whose stream
// claim failed after issue, so a dead connection cannot leave a live entry
// behind until the TTL sweep.
func (b *bindingRegistry) discard(binding [16]byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.entries, binding)
}

// sweepExpired drops entries past their expiry. Expiry is already enforced
// on lookup, so the sweep only reclaims memory between janitor ticks;
// consumed bindings are already gone by the time it runs.
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
// binding: the token-verified request lease must own a live binding, the
// request transcript must hash to the ClientHello the connection was routed
// with, and presenting the binding consumes it. This is the fail-closed half
// that keeps relay key possession from being usable without a routed
// connection, and keeps one connection's transcript from being signed under
// another connection's binding.
func (s *Server) transcriptValidator() ksigner.TranscriptValidatorFunc {
	return func(ctx context.Context, req *signrpc.TranscriptSignRequest) error {
		leaseID := signLeaseIDFromContext(ctx)
		if leaseID == "" {
			return fmt.Errorf("%w: signing request is not bound to a verified lease", ksigner.ErrPermissionDenied)
		}
		return s.registry.bindings.validateAndConsume(req.Binding, leaseID, req.ClientHello)
	}
}
