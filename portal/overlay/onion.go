package overlay

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	onionKeySize   = chacha20poly1305.KeySize
	onionNonceSize = chacha20poly1305.NonceSize
	onionHeaderLen = 5 // next hop (4 bytes) + ttl (1 byte)
)

var (
	ErrInvalidRoute    = errors.New("onion route must include ingress and at least one hop")
	ErrKeyCount        = errors.New("onion key count must match hop count")
	ErrTTLTooSmall     = errors.New("onion ttl must cover every hop")
	ErrIntegrity       = errors.New("onion payload failed integrity check")
	ErrBodyTooShort    = errors.New("onion layer body too short")
	ErrKeyLength       = errors.New("onion key must be 32 bytes")
	ErrOnionNeverBuilt = errors.New("onion payload empty")
)

// BuildOnionPayload seals payload bytes into a Tor-style onion for the provided
// route. The caller supplies hop secrets (one per hop after the ingress). Each
// layer discloses only the next hop ID and the remaining TTL.
func BuildOnionPayload(route []uint32, hopKeys [][]byte, payload []byte, ttl uint8) ([]byte, error) {
	if len(route) < 2 {
		return nil, ErrInvalidRoute
	}
	if len(hopKeys) != len(route)-1 {
		return nil, ErrKeyCount
	}
	for _, key := range hopKeys {
		if len(key) != onionKeySize {
			return nil, ErrKeyLength
		}
	}
	hopCount := len(route) - 1
	if int(ttl) < hopCount {
		return nil, ErrTTLTooSmall
	}
	layerTTL := make([]uint8, hopCount)
	for i := 0; i < hopCount; i++ {
		layerTTL[i] = ttl - uint8(i)
	}

	layer := append([]byte(nil), payload...)
	for i := hopCount - 1; i >= 0; i-- {
		nextHop := uint32(0)
		if i+2 < len(route) {
			nextHop = route[i+2]
		}
		layerTTLValue := layerTTL[i]
		var err error
		layer, err = sealOnionLayer(hopKeys[i], nextHop, layerTTLValue, layer)
		if err != nil {
			return nil, err
		}
	}
	if len(layer) == 0 {
		return nil, ErrOnionNeverBuilt
	}
	return layer, nil
}

// DeriveOnionKeys deterministically expands a secret seed into hop keys using
// HKDF-SHA256. This keeps the implementation self-contained without external
// key agreement plumbing.
func DeriveOnionKeys(seed []byte, hopCount int, label string) ([][]byte, error) {
	if hopCount <= 0 {
		return nil, ErrInvalidRoute
	}
	totalBytes := hopCount * onionKeySize
	blob, err := hkdf.Key(sha256.New, seed, nil, label, totalBytes)
	if err != nil {
		return nil, err
	}
	keys := make([][]byte, hopCount)
	for i := 0; i < hopCount; i++ {
		start := i * onionKeySize
		key := make([]byte, onionKeySize)
		copy(key, blob[start:start+onionKeySize])
		keys[i] = key
	}
	return keys, nil
}

// PeelOnionLayer authenticates and unwraps a single onion layer. It returns the
// next hop ID (0 means terminate locally), remaining TTL, and the inner payload
// (either another onion layer or the plaintext payload).
func PeelOnionLayer(key []byte, packet []byte) (uint32, uint8, []byte, error) {
	if len(key) != onionKeySize {
		return 0, 0, nil, ErrKeyLength
	}
	if len(packet) <= onionNonceSize {
		return 0, 0, nil, ErrBodyTooShort
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return 0, 0, nil, err
	}
	nonce := packet[:onionNonceSize]
	ciphertext := packet[onionNonceSize:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, 0, nil, ErrIntegrity
	}
	if len(plaintext) < onionHeaderLen {
		return 0, 0, nil, ErrBodyTooShort
	}
	nextHop := binary.BigEndian.Uint32(plaintext[:4])
	ttl := plaintext[4]
	inner := make([]byte, len(plaintext)-onionHeaderLen)
	copy(inner, plaintext[onionHeaderLen:])
	return nextHop, ttl, inner, nil
}

func sealOnionLayer(key []byte, nextHop uint32, ttl uint8, inner []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	header := make([]byte, onionHeaderLen+len(inner))
	binary.BigEndian.PutUint32(header[0:4], nextHop)
	header[4] = ttl
	copy(header[onionHeaderLen:], inner)

	nonce := make([]byte, onionNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce, header, nil)
	out := make([]byte, len(nonce)+len(sealed))
	copy(out, nonce)
	copy(out[len(nonce):], sealed)
	return out, nil
}
