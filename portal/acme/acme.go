package acme

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errEnsGaslessAddressRequiredWhenEns       = errors.New("ens gasless address is required when ens gasless import is enabled")
	errACMEKeyDirectoryIsRequired             = errors.New("acme key directory is required")
	errACMEBaseDomainIsRequired               = errors.New("acme base domain is required")
	errACMEManagerIsNil                       = errors.New("acme manager is nil")
	errRelayCertificateFilesDoNotExist        = errors.New("relay certificate files do not exist")
	errACMEObtainResponseMissingCertificateOr = errors.New("acme obtain response missing certificate or private key")
)

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
	CADirURL           string
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
	dns          dnsProvider
	startOnce    sync.Once
	stopOnce     sync.Once
	ensStatus    *utils.Snapshot[types.ENSStatus]
	ensCommands  chan ensDNSCommand
	material     *utils.Snapshot[servedMaterial]

	pendingDNSAddress bool
}

func NewManager(cfg Config) (*Manager, error) {
	baseCfg, err := newManagerBaseConfig(cfg)
	if err != nil {
		return nil, err
	}
	return newManagerWithBaseConfig(baseCfg)
}

func newManagerBaseConfig(cfg Config) (Config, error) {
	cfg.BaseDomain = utils.NormalizeBaseDomain(cfg.BaseDomain)
	cfg.KeyDir = strings.TrimSpace(cfg.KeyDir)
	caDirURL, err := NormalizeCADirURL(cfg.CADirURL)
	if err != nil {
		return Config{}, err
	}
	cfg.CADirURL = caDirURL
	cfg.DNSProvider = strings.ToLower(strings.TrimSpace(cfg.DNSProvider))
	if cfg.DNSProvider == "" {
		cfg.DNSProvider = TypeEmbedded
	}
	return cfg, nil
}

func newManagerWithBaseConfig(cfg Config) (*Manager, error) {
	cfg = newManagerTrimProviderTokens(cfg)
	trimmed, err := newManagerENSGaslessAddress(cfg)
	if err != nil {
		return nil, err
	}
	return buildManagerFromConfig(trimmed)
}

func newManagerTrimProviderTokens(cfg Config) Config {
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
	return cfg
}

func newManagerENSGaslessAddress(cfg Config) (Config, error) {
	if !cfg.ENSGaslessEnabled {
		return cfg, nil
	}
	if cfg.ENSGaslessAddress == "" {
		return Config{}, errEnsGaslessAddressRequiredWhenEns
	}
	address, err := identity.NormalizeEVMAddress(cfg.ENSGaslessAddress)
	if err != nil {
		return Config{}, fmt.Errorf("normalize ens gasless address: %w", err)
	}
	cfg.ENSGaslessAddress = address
	return cfg, nil
}

func buildManagerFromConfig(cfg Config) (*Manager, error) {
	if cfg.KeyDir == "" {
		return nil, errACMEKeyDirectoryIsRequired
	}
	if cfg.BaseDomain == "" {
		return nil, errACMEBaseDomainIsRequired
	}
	if utils.IsLocalRelayHost(cfg.BaseDomain) {
		return &Manager{
			cfg:       cfg,
			stopCh:    make(chan struct{}),
			ensStatus: utils.NewSnapshot(newENSStatus(cfg, nil)),
			material:  utils.NewSnapshot(servedMaterial{}),
		}, nil
	}
	manager := &Manager{
		cfg:         cfg,
		stopCh:      make(chan struct{}),
		ensCommands: make(chan ensDNSCommand, 256),
		ensStatus:   utils.NewSnapshot(newENSStatus(cfg, nil)),
		material:    utils.NewSnapshot(servedMaterial{}),
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
		return "", "", errACMEManagerIsNil
	}
	if utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return m.ensureCertificateLocalHost()
	}
	return m.ensureCertificateRemote(ctx)
}

func (m *Manager) ensureCertificateLocalHost() (string, string, error) {
	if err := ensureLocalDevelopmentCertificate(m.cfg.KeyDir, m.cfg.BaseDomain); err != nil {
		return "", "", err
	}
	return m.TLSFiles()
}

func (m *Manager) ensureCertificateRemote(ctx context.Context) (string, string, error) {
	if err := m.reconcileTrackedENSGaslessHostnames(ctx); err != nil {
		return "", "", err
	}
	if err := m.syncENSGasless(ctx); err != nil {
		return "", "", err
	}
	return m.ensureCertificateAfterENS(ctx)
}

func (m *Manager) ensureCertificateAfterENS(ctx context.Context) (string, string, error) {
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
	if certFile, keyFile, ok := m.reusableCertificate(time.Now()); ok {
		return certFile, keyFile, nil
	}
	if err := m.provision(ctx, ""); err != nil {
		return "", "", err
	}
	return m.TLSFiles()
}

// EnsureTLSMaterial makes sure the relay certificate exists and serves it;
// TLSMaterial, GetCertificate and SigningKey read what it loaded.
func (m *Manager) EnsureTLSMaterial(ctx context.Context) error {
	certFile, keyFile, err := m.EnsureCertificate(ctx)
	if err != nil {
		return err
	}
	return m.loadTLSMaterial(certFile, keyFile)
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
		return "", "", errACMEManagerIsNil
	}
	certFile, keyFile := m.certificateFiles()
	if !utils.FileExists(certFile) || !utils.FileExists(keyFile) {
		return "", "", errRelayCertificateFilesDoNotExist
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

func (m *Manager) provision(ctx context.Context, replacesCertID string) error {
	certFile, keyFile := m.certificateFiles()
	accountKeyFile := filepath.Join(m.cfg.KeyDir, accountKeyFileName)
	if err := provisionEnsureParentDirs(keyFile, certFile, accountKeyFile); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("acme provisioning canceled: %w", err)
	}
	client, err := m.newClient(ctx)
	if err != nil {
		return err
	}
	return m.provisionWithClient(ctx, client, replacesCertID)
}

func provisionEnsureParentDirs(keyFile, certFile, accountKeyFile string) error {
	for _, path := range []string{keyFile, certFile, accountKeyFile} {
		if err := utils.EnsureParentDir(path); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) provisionWithClient(ctx context.Context, client *lego.Client, replacesCertID string) error {
	domains := certificateDomains(m.cfg.BaseDomain)
	obtained, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains:        domains,
		Bundle:         true,
		ReplacesCertID: strings.TrimSpace(replacesCertID),
	})
	if err != nil {
		return fmt.Errorf("obtain certificate: %w", err)
	}
	certFile, keyFile := m.certificateFiles()
	return m.provisionPersistObtained(certFile, keyFile, obtained.Certificate, obtained.PrivateKey)
}

func (m *Manager) provisionPersistObtained(certFile, keyFile string, certPEM, keyPEM []byte) error {
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return errACMEObtainResponseMissingCertificateOr
	}
	material, err := newTLSMaterial(certPEM, keyPEM)
	if err != nil {
		return err
	}
	if err := utils.WriteFileAtomic(certFile, certPEM, 0o644); err != nil {
		return fmt.Errorf("write certificate chain: %w", err)
	}
	if err := utils.WriteFileAtomic(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	m.serve(material)
	return nil
}
