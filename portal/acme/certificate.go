package acme

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
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

func (m *Manager) newClient(ctx context.Context) (*lego.Client, error) {
	email := defaultACMEEmailPrefix + m.cfg.BaseDomain
	user, registrationFile, err := m.newClientLoadUser(email, true)
	if err != nil {
		return nil, err
	}
	return m.newClientWithLoadedUser(ctx, user, registrationFile)
}

func (m *Manager) newClientLoadUser(email string, createKey bool) (*acmeUser, string, error) {
	accountKeyFile := filepath.Join(m.cfg.KeyDir, accountKeyFileName)
	registrationFile := registrationFilePath(m.cfg.KeyDir, m.cfg.CADirURL)
	var accountKey crypto.PrivateKey
	var err error
	if createKey {
		accountKey, err = loadOrCreateAccountKey(accountKeyFile)
	} else {
		var accountKeyPEM []byte
		accountKeyPEM, err = os.ReadFile(accountKeyFile)
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", ErrTenantIssuanceDisabled
		}
		if err == nil {
			accountKey, err = parseAccountKeyPEM(accountKeyPEM)
		}
	}
	if err != nil {
		return nil, "", fmt.Errorf("load acme account key: %w", err)
	}
	var accountReg registration.Resource
	accountRegPtr := (*registration.Resource)(nil)
	ok, err := utils.ReadJSONFileIfExists(registrationFile, &accountReg)
	if err != nil {
		return nil, "", fmt.Errorf("load acme registration: %w", err)
	}
	if ok {
		accountRegPtr = &accountReg
	}
	user := &acmeUser{
		Email:        email,
		Key:          accountKey,
		Registration: accountRegPtr,
	}
	return user, registrationFile, nil
}

func (m *Manager) newClientWithLoadedUser(ctx context.Context, user *acmeUser, registrationFile string) (*lego.Client, error) {
	client, err := m.newClientBuildWithUser(ctx, user)
	if err != nil {
		return nil, err
	}
	challengeProvider, err := m.dns.ChallengeProvider(ctx)
	if err != nil {
		return nil, fmt.Errorf("create dns challenge provider: %w", err)
	}
	provider := dnsChallengeProvider{Provider: challengeProvider, ctx: ctx}
	if err := client.Challenge.SetDNS01Provider(provider, dns01.WrapPreCheck(provider.checkPropagation)); err != nil {
		return nil, fmt.Errorf("set dns01 provider: %w", err)
	}
	if err := m.newClientRegisterUser(client, user, registrationFile); err != nil {
		return nil, err
	}
	return client, nil
}

func (m *Manager) newClientBuildWithUser(ctx context.Context, user *acmeUser) (*lego.Client, error) {
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
	return client, nil
}

func (m *Manager) newClientRegisterUser(client *lego.Client, user *acmeUser, registrationFile string) error {
	if user.Registration != nil {
		return nil
	}
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("register acme account: %w", err)
	}
	user.Registration = reg
	if err := utils.WriteJSONFile(registrationFile, reg, 0o600); err != nil {
		return fmt.Errorf("persist acme registration: %w", err)
	}
	return nil
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.Key }

// acmeRequestTransport binds lego's context-free order API to the operation
// lifetime, including account registration and order-finalization requests.
type acmeRequestTransport struct {
	ctx       context.Context
	transport http.RoundTripper
}

func (t acmeRequestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.transport.RoundTrip(req.WithContext(t.ctx))
}
