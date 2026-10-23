package portal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
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

// A renewal replaces the served certificate and with it the relay's private
// key, and /v1/sign must sign with the key of the certificate the relay serves
// now, not with the one from startup.
func TestSignerFollowsTheServedCertificate(t *testing.T) {
	t.Parallel()

	server := &Server{registry: &leaseRegistry{bindings: keyless.NewBindingRegistry(time.Minute)}}
	first := &acme.TLSMaterial{KeyPEM: ecKeyPEM(t)}
	renewed := &acme.TLSMaterial{KeyPEM: ecKeyPEM(t)}

	signerFirst, err := server.signerFor(first)
	if err != nil {
		t.Fatalf("signerFor(first) error = %v", err)
	}
	if again, err := server.signerFor(first); err != nil || again != signerFirst {
		t.Fatalf("signerFor(first) = %p, %v; want the signer it already built (%p)", again, err, signerFirst)
	}

	signerRenewed, err := server.signerFor(renewed)
	if err != nil {
		t.Fatalf("signerFor(renewed) error = %v", err)
	}
	if signerRenewed == signerFirst {
		t.Fatal("signerFor(renewed) returned the signer built from the first certificate")
	}

	if _, err := server.signerFor(&acme.TLSMaterial{KeyPEM: []byte("not a key")}); err == nil {
		t.Fatal("signerFor(unusable key) error = nil, want one")
	}
	if again, err := server.signerFor(renewed); err != nil || again != signerRenewed {
		t.Fatalf("signerFor(renewed) after a failure = %p, %v; want the signer that was in use (%p)", again, err, signerRenewed)
	}
}
