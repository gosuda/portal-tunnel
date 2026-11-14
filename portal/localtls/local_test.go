package localtls

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestManualCertificateFilesRecoverAfterReplacement(t *testing.T) {
	const hostname = "tenant.test.example"
	dir := t.TempDir()
	cfg := ClientConfig{
		RelayURL: "https://127.0.0.1:1",
		Hostname: hostname,
		CertFile: filepath.Join(dir, "cert.pem"),
		KeyFile:  filepath.Join(dir, "key.pem"),
	}
	client, err := NewClient(t.Context(), cfg)
	if client != nil || !errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrLocalCertificate) {
		t.Fatalf("missing replacement returned %v, %v", client, err)
	}
	writeLocalPair(t, cfg.CertFile, cfg.KeyFile, hostname)
	client, err = NewClient(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if !client.Ready() {
		t.Fatal("valid replacement is not ready")
	}
}

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
