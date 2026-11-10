package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"time"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

func ensureLocalDevelopmentCertificate(keyDir, baseHost string) error {
	domains := localDevelopmentDomains(baseHost)
	keyFile := filepath.Join(keyDir, keyFileName)
	certFile := filepath.Join(keyDir, fullChainFileName)
	if !needLocalDevCertRenewal(keyFile, certFile, domains) {
		return nil
	}
	if err := utils.EnsureParentDir(keyFile); err != nil {
		return err
	}
	privateKey, err := generateLocalDevKey()
	if err != nil {
		return err
	}
	return issueLocalDevCertWithKey(certFile, keyFile, baseHost, domains, privateKey)
}

func needLocalDevCertRenewal(keyFile, certFile string, domains []string) bool {
	if !utils.FileExists(keyFile) || !utils.FileExists(certFile) {
		return true
	}
	cert, err := loadCertificate(certFile)
	return err != nil || !localDevelopmentCertificateReusable(cert, domains, time.Now().UTC())
}

func generateLocalDevKey() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate local dev private key: %w", err)
	}
	return privateKey, nil
}

func issueLocalDevCertWithKey(certFile, keyFile, baseHost string, domains []string, privateKey *ecdsa.PrivateKey) error {
	serialNumber, err := generateLocalDevSerial()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	template := buildLocalDevCertTemplate(baseHost, domains, now, serialNumber)
	certPEM, keyPEM, err := createLocalDevCertPEM(template, privateKey)
	if err != nil {
		return err
	}
	return writeLocalDevCertFiles(certFile, keyFile, certPEM, keyPEM)
}

func generateLocalDevSerial() (*big.Int, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generate local dev certificate serial: %w", err)
	}
	return serialNumber, nil
}

func buildLocalDevCertTemplate(baseHost string, domains []string, now time.Time, serialNumber *big.Int) *x509.Certificate {
	notBefore := now.Add(-1 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   baseHost,
			Organization: []string{"Portal Local Development"},
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(localDevelopmentCertificateValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, domain := range domains {
		if ip := net.ParseIP(domain); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, domain)
		}
	}
	return template
}

func createLocalDevCertPEM(template *x509.Certificate, privateKey *ecdsa.PrivateKey) ([]byte, []byte, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create local dev certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal local dev private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func writeLocalDevCertFiles(certFile, keyFile string, certPEM, keyPEM []byte) error {
	if err := utils.WriteFileAtomic(certFile, certPEM, 0o644); err != nil {
		return fmt.Errorf("write local dev certificate: %w", err)
	}
	if err := utils.WriteFileAtomic(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write local dev private key: %w", err)
	}
	return nil
}

func localDevelopmentCertificateReusable(cert *x509.Certificate, domains []string, now time.Time) bool {
	return certificateUsable(cert, domains, now.Add(defaultRenewThreshold)) &&
		cert.NotAfter.Sub(cert.NotBefore) <= localDevelopmentCertificateValidity
}

func localDevelopmentDomains(baseHost string) []string {
	baseHost = utils.NormalizeBaseDomain(baseHost)
	domains := []string{"localhost", "*.localhost", "127.0.0.1", "::1"}
	if baseHost != "" && baseHost != "localhost" {
		domains = append(domains, baseHost)
		if net.ParseIP(baseHost) == nil {
			domains = append(domains, "*."+baseHost)
		}
	}
	return domains
}
