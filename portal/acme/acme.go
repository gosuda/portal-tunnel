package acme

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-acme/lego/v4/certificate"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// ConfigDiagnostics reports ACME and ENS capability state from configuration
// only. Runtime reachability and provider API access are intentionally deferred
// until the manager starts.
func ConfigDiagnostics(cfg Config) []types.FeatureDiagnostic {
	provider := cmp.Or(strings.ToLower(strings.TrimSpace(cfg.DNSProvider)), TypeEmbedded)
	acmeDiagnostic := types.FeatureDiagnostic{Name: "acme", By: "ACME_DNS_PROVIDER=" + provider}
	if host := utils.NormalizeHostname(cfg.BaseDomain); host == "" || utils.IsLocalRelayHost(host) {
		acmeDiagnostic.State = types.FeatureBlocked
		acmeDiagnostic.Missing = fmt.Sprintf("PORTAL_URL host %q is local-only; managed issuance is skipped for local hosts and a development certificate is used instead", host)
	} else if provider == TypeEmbedded {
		acmeDiagnostic.State = types.FeatureEnabled
		acmeDiagnostic.Detail = fmt.Sprintf("the relay serves its own zone on port %d; delegate the base domain with an NS record and open 53/tcp+udp. Valid manual fullchain.pem and privatekey.pem under IDENTITY_PATH override issuance only when neither acme-account.key nor acme-registration.json exists; DNS/ECH management continues", cfg.EmbeddedDNSPort)
	} else if required, supported := providerCredentialNames(provider); !supported {
		acmeDiagnostic.State = types.FeatureBlocked
		acmeDiagnostic.Missing = "unsupported provider; use embedded, cloudflare, gcloud, hetzner, njalla, route53 or vultr"
	} else if missing := missingProviderCredentials(cfg, required); len(missing) > 0 {
		acmeDiagnostic.State = types.FeatureBlocked
		acmeDiagnostic.Missing = strings.Join(missing, ", ") + " is empty"
	} else {
		acmeDiagnostic.State = types.FeatureEnabled
		acmeDiagnostic.Detail = "supported external DNS backend; embedded remains the canonical default; managed issuance and renewal under IDENTITY_PATH"
		if len(required) == 0 {
			acmeDiagnostic.Detail += "; credentials come from the ambient provider chain"
		}
	}

	ensDiagnostic := types.FeatureDiagnostic{Name: "ens-gasless"}
	if !cfg.ENSGaslessEnabled {
		ensDiagnostic.State, ensDiagnostic.By = types.FeatureDisabled, "ENS_GASLESS_ENABLED=false"
	} else if acmeDiagnostic.State == types.FeatureBlocked {
		ensDiagnostic.State, ensDiagnostic.By = types.FeatureBlocked, "ENS_GASLESS_ENABLED=true"
		ensDiagnostic.Missing = "the DNS provider it shares with ACME is blocked: " + acmeDiagnostic.Missing
	} else if provider == TypeHetzner || provider == TypeNjalla {
		ensDiagnostic.State, ensDiagnostic.By = types.FeatureBlocked, "ENS_GASLESS_ENABLED=true"
		ensDiagnostic.Missing = provider + " does not support ENS DNSSEC automation; use embedded, cloudflare, gcloud, route53 or vultr"
	} else {
		ensDiagnostic.State, ensDiagnostic.By = types.FeatureEnabled, "ENS_GASLESS_ENABLED=true"
		ensDiagnostic.Detail = "DNSSEC and ENS TXT automation through " + provider
		if provider == TypeEmbedded {
			ensDiagnostic.Detail += "; publish the startup DS at the parent after delegation is reachable; local signing does not verify the parent chain"
		}
	}
	return []types.FeatureDiagnostic{acmeDiagnostic, ensDiagnostic}
}

func providerCredentialNames(provider string) ([]string, bool) {
	switch provider {
	case TypeCloudflare:
		return []string{"CLOUDFLARE_TOKEN"}, true
	case TypeHetzner:
		return []string{"HETZNER_API_TOKEN"}, true
	case TypeNjalla:
		return []string{"NJALLA_TOKEN"}, true
	case TypeVultr:
		return []string{"VULTR_API_KEY"}, true
	case TypeGCloud, TypeRoute53:
		return nil, true
	default:
		return nil, false
	}
}

func missingProviderCredentials(cfg Config, names []string) []string {
	values := map[string]string{
		"CLOUDFLARE_TOKEN":  cfg.CloudflareToken,
		"HETZNER_API_TOKEN": cfg.HetznerAPIToken,
		"NJALLA_TOKEN":      cfg.NjallaToken,
		"VULTR_API_KEY":     cfg.VultrAPIKey,
	}
	var missing []string
	for _, name := range names {
		if strings.TrimSpace(values[name]) == "" {
			missing = append(missing, name)
		}
	}
	return missing
}

const (
	fullChainFileName      = "fullchain.pem"
	keyFileName            = "privatekey.pem"
	accountKeyFileName     = "acme-account.key"
	registrationFileName   = "acme-registration.json"
	defaultACMEEmailPrefix = "acme@"
)

type Config struct {
	BaseDomain         string
	KeyDir             string
	DNSProvider        string
	ENSGaslessEnabled  bool
	ENSGaslessAddress  string
	EmbeddedDNSPort    int
	CloudflareToken    string
	GCPProjectID       string
	GCPManagedZone     string
	HetznerAPIToken    string
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	AWSSessionToken    string
	AWSRegion          string
	AWSHostedZoneID    string
	AWSKMSKeyARN       string
	VultrAPIKey        string
	NjallaToken        string
}

type Manager struct {
	stopCh       chan struct{}
	stopCtx      context.Context
	stopErr      error
	workerCancel context.CancelFunc
	cfg          Config
	wg           sync.WaitGroup
	commandMu    sync.RWMutex
	dns          DNSProvider
	startOnce    sync.Once
	stopOnce     sync.Once
	ensStatus    *utils.Snapshot[types.ENSStatus]
	echCommands  chan echDNSCommand
	ensCommands  chan ensDNSCommand

	// pendingDNSAddress is guarded by commandMu and cleared only after A-record synchronization.
	pendingDNSAddress bool
}

func NewManager(cfg Config) (*Manager, error) {
	cfg.BaseDomain = utils.NormalizeBaseDomain(cfg.BaseDomain)
	cfg.KeyDir = strings.TrimSpace(cfg.KeyDir)
	cfg.DNSProvider = strings.ToLower(strings.TrimSpace(cfg.DNSProvider))
	if cfg.DNSProvider == "" {
		cfg.DNSProvider = TypeEmbedded
	}
	cfg.ENSGaslessAddress = strings.TrimSpace(cfg.ENSGaslessAddress)
	cfg.CloudflareToken = strings.TrimSpace(cfg.CloudflareToken)
	cfg.GCPProjectID = strings.TrimSpace(cfg.GCPProjectID)
	cfg.GCPManagedZone = strings.TrimSpace(cfg.GCPManagedZone)
	cfg.HetznerAPIToken = strings.TrimSpace(cfg.HetznerAPIToken)
	cfg.AWSAccessKeyID = strings.TrimSpace(cfg.AWSAccessKeyID)
	cfg.AWSSecretAccessKey = strings.TrimSpace(cfg.AWSSecretAccessKey)
	cfg.AWSSessionToken = strings.TrimSpace(cfg.AWSSessionToken)
	cfg.AWSRegion = strings.TrimSpace(cfg.AWSRegion)
	cfg.AWSHostedZoneID = strings.TrimSpace(cfg.AWSHostedZoneID)
	cfg.AWSKMSKeyARN = strings.TrimSpace(cfg.AWSKMSKeyARN)
	cfg.VultrAPIKey = strings.TrimSpace(cfg.VultrAPIKey)
	cfg.NjallaToken = strings.TrimSpace(cfg.NjallaToken)
	if cfg.ENSGaslessEnabled {
		if cfg.ENSGaslessAddress == "" {
			return nil, errors.New("ens gasless address is required when ens gasless import is enabled")
		}
		address, err := identity.NormalizeEVMAddress(cfg.ENSGaslessAddress)
		if err != nil {
			return nil, fmt.Errorf("normalize ens gasless address: %w", err)
		}
		cfg.ENSGaslessAddress = address
	}

	if cfg.KeyDir == "" {
		return nil, errors.New("acme key directory is required")
	}
	if cfg.BaseDomain == "" {
		return nil, errors.New("acme base domain is required")
	}
	if utils.IsLocalRelayHost(cfg.BaseDomain) {
		return &Manager{
			cfg:       cfg,
			stopCh:    make(chan struct{}),
			ensStatus: utils.NewSnapshot(newENSStatus(cfg, nil)),
		}, nil
	}

	manager := &Manager{
		cfg:         cfg,
		stopCh:      make(chan struct{}),
		echCommands: make(chan echDNSCommand, 256),
		ensCommands: make(chan ensDNSCommand, 256),
		ensStatus:   utils.NewSnapshot(newENSStatus(cfg, nil)),
	}

	acmeDNS, err := newDNSProvider(cfg.DNSProvider, cfg)
	if err != nil {
		return nil, fmt.Errorf("create acme dns provider: %w", err)
	}
	manager.dns = acmeDNS

	return manager, nil
}

func (m *Manager) EnsureCertificate(ctx context.Context) (string, string, error) {
	if m == nil {
		return "", "", errors.New("acme manager is nil")
	}

	if utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		if err := ensureLocalDevelopmentCertificate(m.cfg.KeyDir, m.cfg.BaseDomain); err != nil {
			return "", "", err
		}
		return m.TLSFiles()
	}
	if err := m.reconcileTrackedENSGaslessHostnames(ctx); err != nil {
		return "", "", err
	}
	if err := m.syncENSGasless(ctx); err != nil {
		return "", "", err
	}
	certFile, keyFile, manual, err := m.manualCertificateOverride()
	if err != nil {
		return "", "", err
	}
	if _, err := m.syncDNS(ctx); err != nil {
		return "", "", fmt.Errorf("ensure dns records: %w", err)
	}
	if manual {
		return certFile, keyFile, nil
	}

	certFile, keyFile, err = m.TLSFiles()
	if err == nil {
		covered, err := certCoversDomains(certFile, certificateDomains(m.cfg.BaseDomain))
		if err == nil && covered {
			return certFile, keyFile, nil
		}
	}

	if err := m.provision(ctx); err != nil {
		return "", "", err
	}
	return m.TLSFiles()
}

func (m *Manager) EnsureTLSMaterial(ctx context.Context) ([]byte, []byte, error) {
	certFile, keyFile, err := m.EnsureCertificate(ctx)
	if err != nil {
		return nil, nil, err
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read api tls certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read api tls private key: %w", err)
	}
	return certPEM, keyPEM, nil
}

func (m *Manager) Start(ctx context.Context) {
	if m == nil || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return
	}

	m.startOnce.Do(func() {
		m.commandMu.Lock()
		defer m.commandMu.Unlock()
		select {
		case <-m.stopCh:
			return
		default:
		}
		workerCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		m.workerCancel = cancel
		m.wg.Add(1)
		go m.maintenanceLoop(workerCtx)
	})
}

func (m *Manager) Stop(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.stopOnce.Do(func() {
		m.commandMu.Lock()
		m.stopCtx = ctx
		if m.workerCancel != nil {
			m.workerCancel()
		}
		close(m.stopCh)
		m.commandMu.Unlock()
	})
	m.wg.Wait()
	if dnsServer, ok := m.dns.(interface{ Stop() error }); ok {
		m.stopErr = errors.Join(m.stopErr, dnsServer.Stop())
	}
	return m.stopErr
}

func (m *Manager) TLSFiles() (string, string, error) {
	if m == nil {
		return "", "", errors.New("acme manager is nil")
	}
	certFile := filepath.Join(m.cfg.KeyDir, fullChainFileName)
	keyFile := filepath.Join(m.cfg.KeyDir, keyFileName)
	if !utils.FileExists(certFile) || !utils.FileExists(keyFile) {
		return "", "", errors.New("relay certificate files do not exist")
	}
	return certFile, keyFile, nil
}

func (m *Manager) manualCertificateOverride() (string, string, bool, error) {
	if m == nil || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return "", "", false, nil
	}
	certFile := filepath.Join(m.cfg.KeyDir, fullChainFileName)
	keyFile := filepath.Join(m.cfg.KeyDir, keyFileName)
	if !utils.FileExists(certFile) || !utils.FileExists(keyFile) {
		return "", "", false, nil
	}
	var err error
	covered, err := certCoversDomains(certFile, certificateDomains(m.cfg.BaseDomain))
	if err != nil {
		return "", "", false, fmt.Errorf("validate relay certificate: %w", err)
	}
	hasACMEState := utils.FileExists(filepath.Join(m.cfg.KeyDir, accountKeyFileName)) || utils.FileExists(filepath.Join(m.cfg.KeyDir, registrationFileName))
	if !covered {
		if !hasACMEState {
			return "", "", false, fmt.Errorf("manual relay certificate must cover %s and *.%s", m.cfg.BaseDomain, m.cfg.BaseDomain)
		}
		return "", "", false, nil
	}
	if hasACMEState {
		return "", "", false, nil
	}
	return certFile, keyFile, true, nil
}

func (m *Manager) provision(ctx context.Context) error {
	keyFile := filepath.Join(m.cfg.KeyDir, keyFileName)
	certFile := filepath.Join(m.cfg.KeyDir, fullChainFileName)
	accountKeyFile := filepath.Join(m.cfg.KeyDir, accountKeyFileName)
	registrationFile := filepath.Join(m.cfg.KeyDir, registrationFileName)
	domains := certificateDomains(m.cfg.BaseDomain)

	for _, path := range []string{keyFile, certFile, accountKeyFile, registrationFile} {
		if err := utils.EnsureParentDir(path); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("acme provisioning canceled: %w", err)
	}

	client, err := newClient(ctx, defaultACMEEmailPrefix+m.cfg.BaseDomain, accountKeyFile, registrationFile, m.dns)
	if err != nil {
		return err
	}

	obtained, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	})
	if err != nil {
		return fmt.Errorf("obtain certificate: %w", err)
	}
	if len(obtained.Certificate) == 0 || len(obtained.PrivateKey) == 0 {
		return errors.New("acme obtain response missing certificate or private key")
	}

	if err := utils.WriteFileAtomic(certFile, obtained.Certificate, 0o644); err != nil {
		return fmt.Errorf("write certificate chain: %w", err)
	}
	if err := utils.WriteFileAtomic(keyFile, obtained.PrivateKey, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	return nil
}
