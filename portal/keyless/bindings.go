package keyless

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
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
		return errors.New("binding must be 16 bytes")
	}
	if len(clientHello) == 0 {
		return errors.New("client hello transcript is required")
	}
	helloHash := sha256.Sum256(clientHello)
	var key [16]byte
	copy(key[:], binding)
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.entries[key]
	if !ok || !time.Now().Before(entry.expiresAt) {
		return errors.New("binding is unknown or expired")
	}
	if entry.leaseID != leaseID {
		return errors.New("binding does not belong to the signing lease")
	}
	if entry.helloHash == ([32]byte{}) {
		return errors.New("binding hello was never fixed")
	}
	if entry.helloHash != helloHash {
		return errors.New("client hello does not match the routed connection")
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

const (
	tlsRecordHeaderLen      = 5
	tlsHandshakeContentType = 22
	clientHelloType         = 1
	maxTLSRecordPayload     = 1 << 14
	maxClientHelloSize      = 128 << 10
)

type clientHelloAccumulator struct {
	pending  []byte
	hello    []byte
	expected int
}

func (a *clientHelloAccumulator) clone() clientHelloAccumulator {
	clone := *a
	clone.pending = append([]byte(nil), a.pending...)
	clone.hello = append([]byte(nil), a.hello...)
	return clone
}

func (a *clientHelloAccumulator) add(p []byte) ([]byte, bool, error) {
	a.pending = append(a.pending, p...)
	for len(a.pending) >= tlsRecordHeaderLen {
		if a.pending[0] != tlsHandshakeContentType {
			return nil, false, errors.New("client hello contains a non-handshake TLS record")
		}
		recordLen := int(a.pending[3])<<8 | int(a.pending[4])
		if recordLen == 0 || recordLen > maxTLSRecordPayload {
			return nil, false, errors.New("client hello TLS record has invalid length")
		}
		if len(a.pending) < tlsRecordHeaderLen+recordLen {
			return nil, false, nil
		}
		body := a.pending[tlsRecordHeaderLen : tlsRecordHeaderLen+recordLen]
		a.pending = a.pending[tlsRecordHeaderLen+recordLen:]
		if a.expected == 0 && len(a.hello) < 4 {
			need := min(4-len(a.hello), len(body))
			a.hello = append(a.hello, body[:need]...)
			body = body[need:]
			if len(a.hello) == 4 {
				if a.hello[0] != clientHelloType {
					return nil, false, errors.New("first TLS handshake message is not a client hello")
				}
				messageLen := int(a.hello[1])<<16 | int(a.hello[2])<<8 | int(a.hello[3])
				a.expected = 4 + messageLen
				if messageLen == 0 || a.expected > maxClientHelloSize {
					return nil, false, errors.New("client hello handshake has invalid length")
				}
			}
		}
		if a.expected > 0 {
			need := min(a.expected-len(a.hello), len(body))
			a.hello = append(a.hello, body[:need]...)
			if len(a.hello) == a.expected {
				return append([]byte(nil), a.hello...), true, nil
			}
		}
	}
	if len(a.pending) > maxTLSRecordPayload+tlsRecordHeaderLen {
		return nil, false, errors.New("client hello TLS record exceeds limit")
	}
	return nil, false, nil
}

// FixHelloOnWrite wraps conn and pins the binding to its first ClientHello
// before forwarding the write that completes the handshake message.
func (b *BindingRegistry) FixHelloOnWrite(conn net.Conn, binding [16]byte) net.Conn {
	return &helloFixingConn{Conn: conn, bindings: b, binding: binding}
}

type helloFixingConn struct {
	net.Conn
	mu       sync.Mutex
	capture  clientHelloAccumulator
	fixed    bool
	bindings *BindingRegistry
	binding  [16]byte
}

func (c *helloFixingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fixed {
		return c.Conn.Write(p)
	}

	preview := c.capture.clone()
	hello, complete, err := preview.add(p)
	if err != nil {
		return 0, fmt.Errorf("capture client hello for binding: %w", err)
	}
	if complete {
		if err := c.bindings.FixHello(c.binding, hello); err != nil {
			return 0, fmt.Errorf("fix binding client hello: %w", err)
		}
		c.fixed = true
		return c.Conn.Write(p)
	}

	n, err := c.Conn.Write(p)
	if n > 0 {
		if _, _, captureErr := c.capture.add(p[:n]); captureErr != nil {
			return n, fmt.Errorf("capture client hello for binding: %w", captureErr)
		}
	}
	return n, err
}
