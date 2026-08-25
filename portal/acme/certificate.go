package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	lego "github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

const localDevelopmentCertificateTTL = 3650 * 24 * time.Hour

type acmeUser struct {
	Key          crypto.PrivateKey
	Registration *registration.Resource
	Email        string
}

func (m *Manager) shouldRenew() bool {
	certFile := filepath.Join(m.cfg.KeyDir, fullChainFileName)
	needsRenewal, err := certNeedsRenewal(certFile, certificateDomains(m.cfg.BaseDomain))
	return err == nil && needsRenewal
}

func (m *Manager) shouldRenewTenant() bool {
	certFile := filepath.Join(m.cfg.KeyDir, tenantKeyDirName, fullChainFileName)
	needsRenewal, err := certNeedsRenewal(certFile, tenantCertificateDomains(m.cfg.BaseDomain))
	return err == nil && needsRenewal
}

func certificateDomains(baseDomain string) []string {
	return []string{baseDomain, "*." + baseDomain}
}

func tenantCertificateDomains(baseDomain string) []string {
	return []string{"*." + baseDomain}
}

func certNeedsRenewal(certFile string, domains []string) (bool, error) {
	cert, err := loadCertificate(certFile)
	if err != nil {
		return false, err
	}
	if time.Until(cert.NotAfter) < 30*24*time.Hour {
		return true, nil
	}
	return !certificateCoversDomains(cert, domains), nil
}

func certCoversDomains(certFile string, domains []string) (bool, error) {
	cert, err := loadCertificate(certFile)
	if err != nil {
		return false, err
	}
	return certificateCoversDomains(cert, domains), nil
}

func loadCertificate(certFile string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	return utils.ParseCertificatePEM(certPEM)
}

func certificateCoversDomains(cert *x509.Certificate, domains []string) bool {
	if cert == nil {
		return false
	}
	for _, domain := range domains {
		if wildcardDomain, ok := strings.CutPrefix(domain, "*."); ok {
			if cert.VerifyHostname("probe."+wildcardDomain) != nil {
				return false
			}
			continue
		}
		if cert.VerifyHostname(domain) != nil {
			return false
		}
	}
	return true
}

func newClient(ctx context.Context, email, accountKeyFile, registrationFile string, dnsProvider DNSProvider) (*lego.Client, error) {
	accountKey, err := loadOrCreateAccountKey(accountKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load acme account key: %w", err)
	}

	var accountReg registration.Resource
	accountRegPtr := (*registration.Resource)(nil)
	ok, err := utils.ReadJSONFileIfExists(registrationFile, &accountReg)
	if err != nil {
		return nil, fmt.Errorf("load acme registration: %w", err)
	}
	if ok {
		accountRegPtr = &accountReg
	}

	user := &acmeUser{
		Email:        email,
		Key:          accountKey,
		Registration: accountRegPtr,
	}

	clientConfig := lego.NewConfig(user)
	clientConfig.CADirURL = lego.LEDirectoryProduction
	clientConfig.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("create acme client: %w", err)
	}

	challengeProvider, err := dnsProvider.ChallengeProvider(ctx)
	if err != nil {
		return nil, fmt.Errorf("create dns challenge provider: %w", err)
	}
	if err := client.Challenge.SetDNS01Provider(challengeProvider); err != nil {
		return nil, fmt.Errorf("set dns01 provider: %w", err)
	}

	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("register acme account: %w", err)
		}
		user.Registration = reg
		if err := utils.WriteJSONFile(registrationFile, reg, 0o600); err != nil {
			return nil, fmt.Errorf("persist acme registration: %w", err)
		}
	}

	return client, nil
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.Key }

func loadOrCreateAccountKey(path string) (crypto.PrivateKey, error) {
	keyPEM, err := os.ReadFile(path)
	if err == nil {
		return utils.ParsePrivateKeyPEM(keyPEM)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate account key: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal account key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err := utils.WriteFileAtomic(path, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("persist account key: %w", err)
	}
	return key, nil
}

func ensureLocalDevelopmentCertificate(keyDir, baseHost string) error {
	return ensureLocalDevelopmentCertificateForDomains(keyDir, baseHost, localDevelopmentDomains(baseHost), true)
}

func ensureLocalDevelopmentTenantCertificate(keyDir, baseHost string) error {
	baseHost = utils.NormalizeBaseDomain(baseHost)
	return ensureLocalDevelopmentCertificateForDomains(keyDir, "*."+baseHost, tenantCertificateDomains(baseHost), false)
}

func ensureLocalDevelopmentCertificateForDomains(keyDir, commonName string, domains []string, isCA bool) error {
	keyFile := filepath.Join(keyDir, keyFileName)
	certFile := filepath.Join(keyDir, fullChainFileName)

	if utils.FileExists(keyFile) && utils.FileExists(certFile) {
		covered, err := certCoversDomains(certFile, domains)
		cert, certErr := loadCertificate(certFile)
		if err == nil && certErr == nil && covered && cert.IsCA == isCA {
			return nil
		}
	}

	if err := utils.EnsureParentDir(keyFile); err != nil {
		return err
	}
	if err := utils.EnsureParentDir(certFile); err != nil {
		return err
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate local dev private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate local dev certificate serial: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Portal Local Development"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(localDevelopmentCertificateTTL),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	for _, domain := range domains {
		if ip := net.ParseIP(domain); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		template.DNSNames = append(template.DNSNames, domain)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("create local dev certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal local dev private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := utils.WriteFileAtomic(certFile, certPEM, 0o644); err != nil {
		return fmt.Errorf("write local dev certificate: %w", err)
	}
	if err := utils.WriteFileAtomic(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write local dev private key: %w", err)
	}
	return nil
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
