package portal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
)

func ecKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// A renewal replaces the relay's private key, and /v1/sign must sign with the
// key whose certificate the relay serves now, not with the one from startup.
func TestSignerFollowsTheServedKey(t *testing.T) {
	t.Parallel()

	server := &Server{registry: &leaseRegistry{bindings: keyless.NewBindingRegistry(time.Minute)}}
	keyA, keyB := ecKeyPEM(t), ecKeyPEM(t)

	signerA, err := server.signerFor(keyA)
	if err != nil {
		t.Fatalf("signerFor(keyA) error = %v", err)
	}
	if again, err := server.signerFor(keyA); err != nil || again != signerA {
		t.Fatalf("signerFor(keyA) = %p, %v; want the signer it already built (%p)", again, err, signerA)
	}

	signerB, err := server.signerFor(keyB)
	if err != nil {
		t.Fatalf("signerFor(keyB) error = %v", err)
	}
	if signerB == signerA {
		t.Fatal("signerFor(keyB) returned the signer built from keyA")
	}

	if _, err := server.signerFor([]byte("not a key")); err == nil {
		t.Fatal("signerFor(garbage) error = nil, want one")
	}
	if again, err := server.signerFor(keyB); err != nil || again != signerB {
		t.Fatalf("signerFor(keyB) after a failure = %p, %v; want the signer that was in use (%p)", again, err, signerB)
	}
}
