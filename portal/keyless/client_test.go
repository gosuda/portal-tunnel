package keyless

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
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

	rsaKey := mustRSAKey(t)
	otherRSA := mustRSAKey(t)
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

	pssAutoOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}
	pssAutoSignature, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, digest, pssAutoOpts)
	if err != nil {
		t.Fatalf("sign pss auto salt: %v", err)
	}
	fixtures["rsa-pss-auto"] = signFixture{
		public:    &rsaKey.PublicKey,
		other:     &otherRSA.PublicKey,
		opts:      pssAutoOpts,
		signature: pssAutoSignature,
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

	ecdsaKey := mustECDSAKey(t)
	otherECDSA := mustECDSAKey(t)
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

func TestVerifyRemoteSignerAcceptsMatchingKey(t *testing.T) {
	t.Parallel()
	for name, signer := range selfTestSigners(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := verifyRemoteSigner(signer, signer.Public()); err != nil {
				t.Fatalf("verifyRemoteSigner() error = %v", err)
			}
		})
	}
}
func TestVerifyRemoteSignerRejectsSwappedKeypair(t *testing.T) {
	t.Parallel()
	// Faithful to #377: RemoteSigner.Public() is parsed from the pinned
	// certificate (keypair A) while /v1/sign returns signatures from keypair B.
	cases := map[string]struct{ pinned, swapped crypto.Signer }{
		"rsa":   {pinned: mustRSAKey(t), swapped: mustRSAKey(t)},
		"ecdsa": {pinned: mustECDSAKey(t), swapped: mustECDSAKey(t)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			signer := swappedKeySigner{signWith: tc.swapped, present: tc.pinned.Public()}
			err := verifyRemoteSigner(signer, signer.Public())
			if err == nil {
				t.Fatal("verifyRemoteSigner() = nil, want keypair mismatch failure")
			}
			if !strings.Contains(err.Error(), "keypairs differ") {
				t.Fatalf("error should name the keypair mismatch, got: %v", err)
			}
		})
	}
}

func TestVerifyRemoteSignerRejectsTamperedSignature(t *testing.T) {
	t.Parallel()
	for name, signer := range selfTestSigners(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := verifyRemoteSigner(tamperingSigner{inner: signer}, signer.Public())
			if err == nil {
				t.Fatal("verifyRemoteSigner() = nil, want tampered signature failure")
			}
		})
	}
}

func TestVerifyRemoteSignerPropagatesSignError(t *testing.T) {
	t.Parallel()
	rsaKey := mustRSAKey(t)
	err := verifyRemoteSigner(failingSigner{public: rsaKey.Public()}, rsaKey.Public())
	if err == nil {
		t.Fatal("verifyRemoteSigner() = nil, want sign error propagation")
	}
	if !strings.Contains(err.Error(), "sign self-test challenge") {
		t.Fatalf("error should name the sign step, got: %v", err)
	}
}

func TestVerifyRemoteSignerUnsupportedKey(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	if err := verifyRemoteSigner(priv, priv.Public()); err == nil {
		t.Fatal("verifyRemoteSigner() = nil, want error for unsupported key type")
	} else if !strings.Contains(err.Error(), "unsupported pinned key type") {
		t.Fatalf("error should name the unsupported key type, got: %v", err)
	}
}

func selfTestSigners(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	return map[string]crypto.Signer{
		"rsa":   mustRSAKey(t),
		"ecdsa": mustECDSAKey(t),
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return key
}

func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	return key
}

// swappedKeySigner mimics a RemoteSigner whose pinned certificate advertises
// keypair A while the signing endpoint holds keypair B.
type swappedKeySigner struct {
	signWith crypto.Signer
	present  crypto.PublicKey
}

func (s swappedKeySigner) Public() crypto.PublicKey { return s.present }

func (s swappedKeySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.signWith.Sign(rand, digest, opts)
}

type tamperingSigner struct {
	inner crypto.Signer
}

func (s tamperingSigner) Public() crypto.PublicKey { return s.inner.Public() }

func (s tamperingSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signature, err := s.inner.Sign(rand, digest, opts)
	if err != nil {
		return nil, err
	}
	signature[len(signature)-1] ^= 0x01
	return signature, nil
}

type failingSigner struct {
	public crypto.PublicKey
}

func (s failingSigner) Public() crypto.PublicKey { return s.public }

func (s failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("sign endpoint unavailable")
}
