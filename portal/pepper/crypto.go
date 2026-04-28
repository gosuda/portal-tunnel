package pepper

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	LabelE2EBundle = "pepper/v1/e2e-bundle"
	LabelOnionHop  = "pepper/v1/onion-hop"
	LabelHopMAC    = "pepper/v1/hop-mac"
	LabelControl   = "pepper/v1/control"
	LabelCover     = "pepper/v1/cover"
	LabelReplay    = "pepper/v1/replay"
)

func DeriveKey(secret, salt []byte, label string, size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid derived key size: %d", size)
	}
	reader := hkdf.New(sha256.New, secret, salt, []byte(label))
	key := make([]byte, size)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

type AEAD struct {
	key []byte
}

func NewE2EBundleAEAD(secret, salt []byte) (*AEAD, error) {
	key, err := DeriveKey(secret, salt, LabelE2EBundle, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	return &AEAD{key: key}, nil
}

func (a *AEAD) Key() []byte {
	return append([]byte(nil), a.key...)
}

func (a *AEAD) Seal(plaintext, aad []byte) ([]byte, []byte, error) {
	cipher, err := chacha20poly1305.New(a.key)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return cipher.Seal(nil, nonce, plaintext, aad), nonce, nil
}

func (a *AEAD) Open(ciphertext, nonce, aad []byte) ([]byte, error) {
	cipher, err := chacha20poly1305.New(a.key)
	if err != nil {
		return nil, err
	}
	return cipher.Open(nil, nonce, ciphertext, aad)
}
