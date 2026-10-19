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
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	lego "github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	localDevelopmentCertificateTTL = 3650 * 24 * time.Hour
	defaultRenewThreshold          = 30 * 24 * time.Hour
	// maxRenewExpiryFloor bounds how long ARI may defer renewal: a certificate
	// with less lifetime left is renewed whatever the CA suggests.
	maxRenewExpiryFloor = 7 * 24 * time.Hour
	// minARIRecheckDelay keeps a CA's Retry-After from driving the renewal
	// check faster than hourly.
	minARIRecheckDelay = time.Hour
)

type acmeUser struct {
	Key          crypto.PrivateKey
	Registration *registration.Resource
	Email        string
}

// shouldRenew reports whether the certificate on disk should be renewed now,
// the RFC 9773 ReplacesCertID to renew it with, and how long the maintenance
// loop should wait before checking again.
func (m *Manager) shouldRenew(ctx context.Context) (bool, string, time.Duration) {
	certFile := filepath.Join(m.cfg.KeyDir, fullChainFileName)
	cert, err := loadCertificate(certFile)
	if err != nil {
		return false, "", defaultRenewInterval
	}
	domains := certificateDomains(m.cfg.BaseDomain)
	now := time.Now().UTC()
	var ari *certificate.RenewalInfoResponse
	// A certificate that no longer covers the domains or has already expired
	// is replaced without consulting ARI.
	if certificateCoversDomains(cert, domains) && now.Before(cert.NotAfter) {
		client, clientErr := m.newClient(ctx)
		if clientErr == nil {
			ari, clientErr = client.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: cert})
		}
		if clientErr != nil {
			log.Debug().Err(clientErr).Str("base_domain", m.cfg.BaseDomain).Msg("acme renewal information unavailable")
		}
	}
	return evaluateRenewal(cert, domains, ari, now)
}

func certificateDomains(baseDomain string) []string {
	return []string{baseDomain, "*." + baseDomain}
}

// evaluateRenewal decides whether cert should be renewed now. It returns the
// RFC 9773 ReplacesCertID when the CA's ARI response guided the renewal, and
// the delay before the next check.
//
// ARI schedules renewals only while cert is unexpired and covers domains and
// the CA returned a usable window; otherwise the 30-day remaining-lifetime
// threshold applies. ARI never defers renewal past the expiry floor.
func evaluateRenewal(cert *x509.Certificate, domains []string, ari *certificate.RenewalInfoResponse, now time.Time) (renew bool, replacesCertID string, recheck time.Duration) {
	recheck = defaultRenewInterval
	if cert == nil {
		return false, "", recheck
	}
	remaining := cert.NotAfter.Sub(now)
	if !certificateCoversDomains(cert, domains) || remaining <= 0 {
		return true, "", recheck
	}
	if ari == nil || ari.SuggestedWindow.Start.IsZero() || !ari.SuggestedWindow.End.After(ari.SuggestedWindow.Start) {
		return remaining < defaultRenewThreshold, "", recheck
	}

	// MakeARICertID fails only for certificates without an authority key id;
	// those still renew, just without naming the certificate they replace.
	certID, _ := certificate.MakeARICertID(cert)
	if ari.RetryAfter > 0 {
		recheck = min(max(ari.RetryAfter, minARIRecheckDelay), defaultRenewInterval)
	}
	floor := renewExpiryFloor(cert)
	// ShouldRenewAt returns nil only when the time it picked in the window
	// falls after the next check; anything else is due before then, so
	// renew now (RFC 9773, section 4.1).
	if remaining < floor || ari.ShouldRenewAt(now, recheck) != nil {
		return true, certID, recheck
	}
	return false, "", min(recheck, remaining-floor)
}

// renewExpiryFloor is the remaining lifetime below which cert is renewed
// regardless of ARI: a tenth of its lifetime, at most maxRenewExpiryFloor.
func renewExpiryFloor(cert *x509.Certificate) time.Duration {
	if lifetime := cert.NotAfter.Sub(cert.NotBefore); lifetime > 0 {
		return min(maxRenewExpiryFloor, lifetime/10)
	}
	return maxRenewExpiryFloor
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
		if cert.VerifyHostname(domain) != nil {
			return false
		}
	}
	return true
}

func (m *Manager) newClient(ctx context.Context) (*lego.Client, error) {
	email := defaultACMEEmailPrefix + m.cfg.BaseDomain
	accountKeyFile := filepath.Join(m.cfg.KeyDir, accountKeyFileName)
	registrationFile := filepath.Join(m.cfg.KeyDir, registrationFileName)
	dnsProvider := m.dns
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
	domains := localDevelopmentDomains(baseHost)
	keyFile := filepath.Join(keyDir, keyFileName)
	certFile := filepath.Join(keyDir, fullChainFileName)

	if utils.FileExists(keyFile) && utils.FileExists(certFile) {
		covered, err := certCoversDomains(certFile, domains)
		if err == nil && covered {
			return nil
		}
	}

	if err := utils.EnsureParentDir(keyFile); err != nil {
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
			CommonName:   baseHost,
			Organization: []string{"Portal Local Development"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(localDevelopmentCertificateTTL),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
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
