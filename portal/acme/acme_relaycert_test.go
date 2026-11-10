package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/lego"
)

func writeManualRelayCertificate(t *testing.T, keyDir, baseDomain string) error {
	t.Helper()

	certFile, keyFile := certificateFilePaths(keyDir, lego.LEDirectoryProduction)
	return writeRelayCertificate(t, certFile, keyFile, baseDomain, time.Now().UTC().Add(90*24*time.Hour))
}

func writeRelayCertificate(t *testing.T, certFile, keyFile, baseDomain string, notAfter time.Time) error {
	t.Helper()

	privateKey, err := generateWriteRelayCertificateKey()
	if err != nil {
		return err
	}

	der, keyDER, err := createWriteRelayCertificateDER(privateKey, baseDomain, notAfter)
	if err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyFile, keyPEM, 0o600)
}

func createWriteRelayCertificateDER(privateKey *ecdsa.PrivateKey, baseDomain string, notAfter time.Time) (der, keyDER []byte, err error) {
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName: baseDomain,
		},
		NotBefore:             notAfter.Add(-91 * 24 * time.Hour),
		NotAfter:              notAfter,
		DNSNames:              []string{baseDomain, "*." + baseDomain},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err = x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err = x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	return der, keyDER, nil
}

func generateWriteRelayCertificateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
