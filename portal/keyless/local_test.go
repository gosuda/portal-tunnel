package keyless

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateCertificateFiles(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeLocalPair(t, certFile, keyFile, "tenant.test.example")
	otherCert, otherKey := filepath.Join(dir, "other.pem"), filepath.Join(dir, "other.key")
	writeLocalPair(t, otherCert, otherKey, "tenant.test.example")
	corrupt := filepath.Join(dir, "corrupt.pem")
	if err := os.WriteFile(corrupt, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.pem")
	for _, tc := range []struct {
		name, cert, key string
	}{
		{"missing certificate", missing, keyFile},
		{"missing key", certFile, missing},
		{"corrupt certificate", corrupt, keyFile},
		{"corrupt key", certFile, corrupt},
		{"mismatched key", certFile, otherKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateCertificateFiles(tc.cert, tc.key); !errors.Is(err, ErrLocalCertificate) {
				t.Fatalf("ValidateCertificateFiles() = %v, want local certificate error", err)
			}
		})
	}
	if err := ValidateCertificateFiles(certFile, keyFile); err != nil {
		t.Fatalf("valid pair rejected before hostname assignment: %v", err)
	}
}
