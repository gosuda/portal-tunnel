package pepper

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const (
	DefaultMinEntropyBits = 256

	ErrPFSHandshakeFailed   = "ERR_PFS_HANDSHAKE_FAILED"
	ErrOnionIntegrityVoid   = "ERR_ONION_INTEGRITY_VOID"
	ErrPepperEntropyLow     = "ERR_PEPPER_ENTROPY_LOW"
	ErrPepperStaticEntry    = "ERR_PEPPER_STATIC_ENTRY"
	ErrPepperStaticIdentity = "ERR_PEPPER_STATIC_IDENTITY"
)

var (
	ErrStaticKeyMaterial = errors.New(ErrPFSHandshakeFailed)
	ErrEntropyLow        = errors.New(ErrPepperEntropyLow)
)

type ActivePolicy struct {
	MinEntropyBits int
	MultiHopDepth  int
	ExplicitPath   []string
	Discovery      bool
	IdentityJSON   string
}

func (p ActivePolicy) Validate() error {
	minEntropyBits := p.MinEntropyBits
	if minEntropyBits <= 0 {
		minEntropyBits = DefaultMinEntropyBits
	}
	switch {
	case len(p.ExplicitPath) > 0:
		return errors.New(ErrPepperStaticEntry)
	case strings.TrimSpace(p.IdentityJSON) != "":
		return errors.New(ErrPepperStaticIdentity)
	case p.MultiHopDepth < 2:
		return errors.New("pepper active requires automatic --multi-hop-depth 2+")
	case !p.Discovery:
		return errors.New("pepper active requires discovery for randomized bridge selection")
	}
	return RequireEntropy(minEntropyBits)
}

func RequireEntropy(minBits int) error {
	if minBits <= 0 {
		minBits = DefaultMinEntropyBits
	}
	data, err := os.ReadFile("/proc/sys/kernel/random/entropy_avail")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%w: read entropy pool: %w", ErrEntropyLow, err)
	}
	available, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("%w: parse entropy pool: %w", ErrEntropyLow, err)
	}
	if available < minBits {
		return fmt.Errorf("%w: available=%d required=%d", ErrEntropyLow, available, minBits)
	}
	return nil
}

type LockedKey struct {
	bytes []byte
}

func NewLockedKey(key []byte) (*LockedKey, error) {
	if len(key) == 0 {
		return nil, errors.New("locked key is required")
	}
	buf := append([]byte(nil), key...)
	if err := lockMemory(buf); err != nil {
		Zero(buf)
		return nil, fmt.Errorf("mlock pepper key: %w", err)
	}
	return &LockedKey{bytes: buf}, nil
}

func (k *LockedKey) WithBytes(fn func([]byte) error) error {
	if k == nil || len(k.bytes) == 0 {
		return errors.New("locked key is closed")
	}
	return fn(k.bytes)
}

func (k *LockedKey) Close() error {
	if k == nil || len(k.bytes) == 0 {
		return nil
	}
	Zero(k.bytes)
	err := unlockMemory(k.bytes)
	k.bytes = nil
	return err
}

func Zero(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

type EphemeralX25519 struct {
	private *LockedKey
	Public  [32]byte
}

func NewEphemeralX25519() (*EphemeralX25519, error) {
	var private [32]byte
	if _, err := io.ReadFull(rand.Reader, private[:]); err != nil {
		return nil, fmt.Errorf("%w: generate x25519 key: %w", ErrStaticKeyMaterial, err)
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	locked, err := NewLockedKey(private[:])
	Zero(private[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStaticKeyMaterial, err)
	}

	var public [32]byte
	if err := locked.WithBytes(func(key []byte) error {
		pub, err := curve25519.X25519(key, curve25519.Basepoint)
		if err != nil {
			return err
		}
		copy(public[:], pub)
		Zero(pub)
		return nil
	}); err != nil {
		_ = locked.Close()
		return nil, fmt.Errorf("%w: derive x25519 public key: %w", ErrStaticKeyMaterial, err)
	}
	return &EphemeralX25519{private: locked, Public: public}, nil
}

func (e *EphemeralX25519) Shared(peerPublic [32]byte, forbiddenPeerPublicKeys ...[32]byte) (*LockedKey, error) {
	if e == nil || e.private == nil {
		return nil, errors.New(ErrPFSHandshakeFailed)
	}
	for _, forbidden := range forbiddenPeerPublicKeys {
		if peerPublic == forbidden {
			return nil, ErrStaticKeyMaterial
		}
	}
	var shared []byte
	if err := e.private.WithBytes(func(key []byte) error {
		var err error
		shared, err = curve25519.X25519(key, peerPublic[:])
		return err
	}); err != nil {
		return nil, fmt.Errorf("%w: derive x25519 shared secret: %w", ErrStaticKeyMaterial, err)
	}
	locked, err := NewLockedKey(shared)
	Zero(shared)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStaticKeyMaterial, err)
	}
	return locked, nil
}

func (e *EphemeralX25519) Close() error {
	if e == nil || e.private == nil {
		return nil
	}
	return e.private.Close()
}
