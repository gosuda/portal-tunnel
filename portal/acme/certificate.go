package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	lego "github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errInvalidPrivateKeyPEM        = errors.New("invalid private key pem")
	errUnsupportedPrivateKeyType   = errors.New("unsupported private key type")
	errACMECADirectoryURLMustValid = errors.New("acme ca directory url must be a valid URL without credentials, query, or fragment")
	errACMECADirectoryURLMustUse   = errors.New("acme ca directory url must use https")
)

const (
	localDevelopmentCertificateValidity = 825 * 24 * time.Hour
	defaultRenewThreshold               = 30 * 24 * time.Hour
	maxRenewExpiryFloor                 = 7 * 24 * time.Hour
	minARIRecheckDelay                  = time.Hour
)

type acmeUser struct {
	Key          crypto.PrivateKey
	Registration *registration.Resource
	Email        string
}

func (m *Manager) shouldRenew(ctx context.Context) (bool, string, time.Duration) {
	certFile, _ := m.certificateFiles()
	cert, err := loadCertificate(certFile)
	if err != nil {
		return false, "", defaultRenewInterval
	}
	domains := certificateDomains(m.cfg.BaseDomain)
	now := time.Now().UTC()
	var ari *certificate.RenewalInfoResponse
	if certificateUsable(cert, domains, now) {
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

func evaluateRenewal(cert *x509.Certificate, domains []string, ari *certificate.RenewalInfoResponse, now time.Time) (renew bool, replacesCertID string, recheck time.Duration) {
	recheck = defaultRenewInterval
	if cert == nil {
		return false, "", recheck
	}
	if !certificateUsable(cert, domains, now) {
		return true, "", recheck
	}
	remaining := cert.NotAfter.Sub(now)
	if ari == nil || ari.SuggestedWindow.Start.IsZero() || !ari.SuggestedWindow.End.After(ari.SuggestedWindow.Start) {
		return remaining < defaultRenewThreshold, "", recheck
	}

	certID, _ := certificate.MakeARICertID(cert)
	if ari.RetryAfter > 0 {
		recheck = min(max(ari.RetryAfter, minARIRecheckDelay), defaultRenewInterval)
	}
	floor := renewExpiryFloor(cert)
	if remaining < floor || ari.ShouldRenewAt(now, recheck) != nil {
		return true, certID, recheck
	}
	return false, "", min(recheck, remaining-floor)
}

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

func (m *Manager) reusableCertificate(now time.Time) (certFile, keyFile string, ok bool) {
	certFile, keyFile, err := m.TLSFiles()
	if err != nil {
		return "", "", false
	}
	cert, err := loadCertificate(certFile)
	if err != nil {
		return "", "", false
	}
	return certFile, keyFile, certificateUsable(cert, certificateDomains(m.cfg.BaseDomain), now)
}

func certificateUsable(cert *x509.Certificate, domains []string, now time.Time) bool {
	return certificateCoversDomains(cert, domains) && now.Before(cert.NotAfter)
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

// NormalizeCADirURL validates an optional ACME CA directory URL and defaults
// an empty value to Let's Encrypt production. Only HTTPS directories are
// accepted; it returns the canonical form used to name the CA's files.
func NormalizeCADirURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return lego.LEDirectoryProduction, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errACMECADirectoryURLMustValid, err)
	}
	if parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errACMECADirectoryURLMustValid
	}
	if parsed.Scheme != "https" {
		return "", errACMECADirectoryURLMustUse
	}
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed.String(), nil
}

func registrationFilePath(keyDir, caDirURL string) string {
	if caDirURL == lego.LEDirectoryProduction {
		return filepath.Join(keyDir, registrationFileName)
	}
	return filepath.Join(keyDir, "acme-registration-"+caDirectoryDigest(caDirURL)+".json")
}

func certificateFilePaths(keyDir, caDirURL string) (certFile, keyFile string) {
	if caDirURL == lego.LEDirectoryProduction {
		return filepath.Join(keyDir, fullChainFileName), filepath.Join(keyDir, keyFileName)
	}
	digest := caDirectoryDigest(caDirURL)
	return filepath.Join(keyDir, "fullchain-"+digest+".pem"), filepath.Join(keyDir, "privatekey-"+digest+".pem")
}

func caDirectoryDigest(caDirURL string) string {
	sum := sha256.Sum256([]byte(caDirURL))
	return fmt.Sprintf("%x", sum[:8])
}

func (m *Manager) certificateFiles() (certFile, keyFile string) {
	if utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return certificateFilePaths(m.cfg.KeyDir, lego.LEDirectoryProduction)
	}
	return certificateFilePaths(m.cfg.KeyDir, m.cfg.CADirURL)
}

func (m *Manager) newClient(ctx context.Context) (*lego.Client, error) {
	email := defaultACMEEmailPrefix + m.cfg.BaseDomain
	accountKeyFile := filepath.Join(m.cfg.KeyDir, accountKeyFileName)
	registrationFile := registrationFilePath(m.cfg.KeyDir, m.cfg.CADirURL)
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
	clientConfig.CADirURL = m.cfg.CADirURL
	clientConfig.Certificate.KeyType = certcrypto.RSA2048
	clientConfig.HTTPClient.Transport = acmeRequestTransport{ctx: ctx, transport: clientConfig.HTTPClient.Transport}

	client, err := lego.NewClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("create acme client: %w", err)
	}
	if user.Registration == nil && client.GetExternalAccountRequired() {
		return nil, fmt.Errorf("acme directory %s requires external account binding, which is not supported", m.cfg.CADirURL)
	}

	challengeProvider, err := m.dns.ChallengeProvider(ctx)
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
		return parseAccountKeyPEM(keyPEM)
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

	now := time.Now().UTC()
	if utils.FileExists(keyFile) && utils.FileExists(certFile) {
		cert, err := loadCertificate(certFile)
		if err == nil && localDevelopmentCertificateReusable(cert, domains, now) {
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

func parseAccountKeyPEM(keyPEM []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errInvalidPrivateKeyPEM
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch typed := key.(type) {
		case *ecdsa.PrivateKey:
			return typed, nil
		case *rsa.PrivateKey:
			return typed, nil
		}
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errUnsupportedPrivateKeyType
}

// acmeRequestTransport binds lego's context-free order API to the operation
// lifetime, including account registration and order-finalization requests.
type acmeRequestTransport struct {
	ctx       context.Context
	transport http.RoundTripper
}

func (t acmeRequestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.transport.RoundTrip(req.WithContext(t.ctx))
}
