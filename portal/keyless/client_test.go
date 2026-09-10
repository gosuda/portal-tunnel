package keyless

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func TestVerifySignatureAcceptsMatchingKey(t *testing.T) {
	t.Parallel()
	digest := sha256.Sum256([]byte("pt377 digest"))
	for name, fixture := range signingFixtures(t, digest[:]) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := verifySignature(fixture.public, digest[:], fixture.opts, fixture.signature); err != nil {
				t.Fatalf("verifySignature() = %v, want nil", err)
			}
		})
	}
}

func TestVerifySignatureRejectsWrongKey(t *testing.T) {
	t.Parallel()
	digest := sha256.Sum256([]byte("pt377 digest"))
	for name, fixture := range signingFixtures(t, digest[:]) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := verifySignature(fixture.other, digest[:], fixture.opts, fixture.signature)
			if err == nil {
				t.Fatal("verifySignature() = nil, want error for signature from a different key")
			}
		})
	}
}

func TestVerifySignatureRejectsTamperedSignature(t *testing.T) {
	t.Parallel()
	digest := sha256.Sum256([]byte("pt377 digest"))
	for name, fixture := range signingFixtures(t, digest[:]) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tampered := make([]byte, len(fixture.signature))
			copy(tampered, fixture.signature)
			tampered[len(tampered)-1] ^= 0xff
			if err := verifySignature(fixture.public, digest[:], fixture.opts, tampered); err == nil {
				t.Fatal("verifySignature() = nil, want error for tampered signature")
			}
		})
	}
}

type signFixture struct {
	public    crypto.PublicKey
	other     crypto.PublicKey
	opts      crypto.SignerOpts
	signature []byte
}

func signingFixtures(t *testing.T, digest []byte) map[string]signFixture {
	t.Helper()
	fixtures := make(map[string]signFixture)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	otherRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other rsa key: %v", err)
	}
	pssOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	pssSignature, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, digest, pssOpts)
	if err != nil {
		t.Fatalf("sign pss: %v", err)
	}
	fixtures["rsa-pss"] = signFixture{
		public:    &rsaKey.PublicKey,
		other:     &otherRSA.PublicKey,
		opts:      pssOpts,
		signature: pssSignature,
	}

	pkcsSignature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("sign pkcs1v15: %v", err)
	}
	fixtures["rsa-pkcs1v15"] = signFixture{
		public:    &rsaKey.PublicKey,
		other:     &otherRSA.PublicKey,
		opts:      crypto.SHA256,
		signature: pkcsSignature,
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	otherECDSA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other ecdsa key: %v", err)
	}
	ecdsaSignature, err := ecdsa.SignASN1(rand.Reader, ecdsaKey, digest)
	if err != nil {
		t.Fatalf("sign ecdsa: %v", err)
	}
	fixtures["ecdsa"] = signFixture{
		public:    &ecdsaKey.PublicKey,
		other:     &otherECDSA.PublicKey,
		opts:      crypto.SHA256,
		signature: ecdsaSignature,
	}

	return fixtures
}

func TestVerifySignatureUnsupportedKey(t *testing.T) {
	t.Parallel()
	err := verifySignature(struct{ crypto.PublicKey }{}, nil, crypto.SHA256, nil)
	if err == nil {
		t.Fatal("verifySignature() = nil, want error for unsupported key type")
	}
}
