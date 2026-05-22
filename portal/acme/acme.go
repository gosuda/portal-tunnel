package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	lego "github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	fullChainFileName           = "fullchain.pem"
	keyFileName                 = "privatekey.pem"
	accountKeyFileName          = "acme-account.key"
	registrationFileName        = "acme-registration.json"
	ensGaslessHostnamesFileName = "ens-gasless-hostnames.json"
	gaslessENSTXTPrefix         = "ENS1 "
	defaultENSGaslessResolver   = "0x238A8F792dFA6033814B18618aD4100654aeef01"
	defaultACMEEmailPrefix      = "acme@"
	defaultRenewInterval        = 24 * time.Hour
	defaultDNSSyncInterval      = 10 * time.Minute
	defaultSyncTimeout          = 2 * time.Minute
)

type Config struct {
	BaseDomain         string
	KeyDir             string
	DNSProvider        string
	ENSGaslessEnabled  bool
	ENSGaslessAddress  string
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
	stopCh        chan struct{}
	cfg           Config
	wg            sync.WaitGroup
	dns           DNSProvider
	startOnce     sync.Once
	stopOnce      sync.Once
	dnssecLogOnce sync.Once
	ensLogOnce    sync.Once
	ensStatus     *utils.Snapshot[types.ENSStatus]
	trackedMu     sync.Mutex
	echMu         sync.Mutex
	echRecords    map[string]HTTPSRecord
}

type HTTPSRecord struct {
	Priority      uint16
	Target        string
	Port          int
	ECHConfigList []byte
}

func (r HTTPSRecord) Normalized() (HTTPSRecord, error) {
	target := strings.TrimSpace(r.Target)
	if target == "" {
		target = "."
	}
	if target != "." {
		target = strings.TrimSuffix(target, ".")
		if target == "" {
			target = "."
		} else {
			target += "."
		}
	}
	priority := r.Priority
	if priority == 0 {
		priority = 1
	}
	if len(r.ECHConfigList) == 0 {
		return HTTPSRecord{}, errors.New("ech config list is required")
	}
	if r.Port < 0 || r.Port > 65535 {
		return HTTPSRecord{}, errors.New("https record port must be between 0 and 65535")
	}
	return HTTPSRecord{
		Priority:      priority,
		Target:        target,
		Port:          r.Port,
		ECHConfigList: bytes.Clone(r.ECHConfigList),
	}, nil
}

func (r HTTPSRecord) Content() (string, error) {
	normalized, err := r.Normalized()
	if err != nil {
		return "", err
	}
	return strings.Join([]string{
		strconv.Itoa(int(normalized.Priority)),
		normalized.Target,
		normalized.SvcParams(),
	}, " "), nil
}

func (r HTTPSRecord) SvcParams() string {
	normalized, err := r.Normalized()
	if err != nil {
		return ""
	}
	params := []string{
		`ech="` + base64.StdEncoding.EncodeToString(normalized.ECHConfigList) + `"`,
	}
	if normalized.Port > 0 && normalized.Port != 443 {
		params = append(params, "port="+strconv.Itoa(normalized.Port))
	}
	return strings.Join(params, " ")
}

type acmeUser struct {
	Key          crypto.PrivateKey
	Registration *registration.Resource
	Email        string
}

func NewManager(cfg Config) (*Manager, error) {
	cfg.BaseDomain = utils.NormalizeBaseDomain(cfg.BaseDomain)
	cfg.KeyDir = strings.TrimSpace(cfg.KeyDir)
	cfg.DNSProvider = strings.ToLower(strings.TrimSpace(cfg.DNSProvider))
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
		cfg:       cfg,
		stopCh:    make(chan struct{}),
		ensStatus: utils.NewSnapshot(newENSStatus(cfg, nil)),
	}

	acmeDNS, err := NewDNSProvider(cfg.DNSProvider, cfg)
	if err != nil {
		return nil, fmt.Errorf("create acme dns provider: %w", err)
	}
	manager.dns = acmeDNS

	if cfg.ENSGaslessEnabled && manager.dns == nil {
		return nil, errors.New("ens gasless automation requires ACME_DNS_PROVIDER")
	}

	return manager, nil
}

func newENSStatus(cfg Config, dns DNSProvider) types.ENSStatus {
	provider := strings.TrimSpace(cfg.DNSProvider)
	if dns != nil {
		provider = dns.Name()
	}
	return types.ENSStatus{
		Enabled:  cfg.ENSGaslessEnabled && !utils.IsLocalRelayHost(cfg.BaseDomain),
		Provider: provider,
		Address:  strings.TrimSpace(cfg.ENSGaslessAddress),
	}
}

func (m *Manager) ENSStatus() types.ENSStatus {
	if m == nil {
		return types.ENSStatus{}
	}
	status := types.ENSStatus{}
	if m.ensStatus != nil {
		status = m.ensStatus.Load()
	}
	if status.Provider == "" && m.dns != nil {
		status.Provider = m.dns.Name()
	}
	return status
}

func (m *Manager) setENSStatus(state, record, message string, syncErr error) {
	if m == nil {
		return
	}
	status := newENSStatus(m.cfg, m.dns)
	status.DNSSECState = strings.TrimSpace(state)
	status.DSRecord = strings.TrimSpace(record)
	status.Message = strings.TrimSpace(message)
	status.Verified = syncErr == nil && ensDNSSECVerified(status.DNSSECState)
	if syncErr != nil {
		status.LastError = syncErr.Error()
	}

	if m.ensStatus == nil {
		m.ensStatus = utils.NewSnapshot(status)
		return
	}
	m.ensStatus.Store(status)
}

func ensDNSSECVerified(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "active", "on", "signing", "transfer":
		return true
	default:
		return false
	}
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
	certFile, keyFile, manual, err := m.manualCertificateOverride()
	if err != nil {
		return "", "", err
	}
	if manual {
		if err := m.syncENSGasless(ctx); err != nil {
			return "", "", err
		}
		return certFile, keyFile, nil
	}
	if !m.managedACME() {
		return m.ensureManualCertificate()
	}

	if err := m.syncDNS(ctx); err != nil {
		return "", "", fmt.Errorf("ensure dns records: %w", err)
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
	if m == nil || utils.IsLocalRelayHost(m.cfg.BaseDomain) || (!m.cfg.ENSGaslessEnabled && !m.managedACME()) {
		return
	}

	m.startOnce.Do(func() {
		m.wg.Add(1)
		go m.maintenanceLoop(ctx)
	})
}

func (m *Manager) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
	m.wg.Wait()
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

func (m *Manager) managedACME() bool {
	return m != nil && m.dns != nil
}

func (m *Manager) ensureManualCertificate() (string, string, error) {
	certFile, keyFile, err := m.TLSFiles()
	if err != nil {
		return "", "", fmt.Errorf("manual certificate mode requires %s and %s in %s or configure ACME_DNS_PROVIDER", fullChainFileName, keyFileName, m.cfg.KeyDir)
	}

	covered, err := certCoversDomains(certFile, certificateDomains(m.cfg.BaseDomain))
	if err != nil {
		return "", "", fmt.Errorf("validate relay certificate: %w", err)
	}
	if !covered {
		return "", "", fmt.Errorf("manual relay certificate must cover %s and *.%s", m.cfg.BaseDomain, m.cfg.BaseDomain)
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

func (m *Manager) maintenanceLoop(ctx context.Context) {
	defer m.wg.Done()

	renewTicker := time.NewTicker(defaultRenewInterval)
	dnsTicker := time.NewTicker(defaultDNSSyncInterval)
	defer renewTicker.Stop()
	defer dnsTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-dnsTicker.C:
			syncCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
			err := errors.Join(m.syncDNS(syncCtx), m.syncECHRecords(syncCtx))
			cancel()
			if err != nil {
				log.Warn().Err(err).Str("base_domain", m.cfg.BaseDomain).Msg("sync dns records")
			}
		case <-renewTicker.C:
			_, _, manual, err := m.manualCertificateOverride()
			if err != nil || manual || !m.managedACME() || !m.shouldRenew() {
				continue
			}
			renewCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
			err = m.provision(renewCtx)
			cancel()
			if err != nil {
				log.Warn().Err(err).Str("base_domain", m.cfg.BaseDomain).Msg("renew acme certificate")
			}
		}
	}
}

func (m *Manager) syncDNS(ctx context.Context) error {
	if m == nil || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}
	if err := m.syncENSGasless(ctx); err != nil {
		return err
	}
	_, _, manual, err := m.manualCertificateOverride()
	if err != nil {
		return err
	}
	if manual || !m.managedACME() {
		return nil
	}

	publicIP, err := utils.ResolvePublicIPv4(ctx)
	if err != nil {
		return fmt.Errorf("detect public ip: %w", err)
	}

	return m.dns.EnsureARecords(ctx, m.cfg.BaseDomain, publicIP)
}

func (m *Manager) SyncECHConfig(ctx context.Context, hostname string, echConfigList []byte, port int) error {
	if m == nil || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}
	if m.dns == nil {
		return nil
	}
	hostname = utils.NormalizeHostname(hostname)
	if hostname == "" {
		return errors.New("hostname is required")
	}
	if !utils.HostnameMatchesBaseDomain(hostname, m.cfg.BaseDomain) {
		return fmt.Errorf("hostname %q is outside acme base domain %q", hostname, m.cfg.BaseDomain)
	}
	echConfigList, err := keyless.NormalizeEncryptedClientHelloConfigList(echConfigList)
	if err != nil {
		return err
	}
	record := HTTPSRecord{
		Priority:      1,
		Target:        ".",
		Port:          port,
		ECHConfigList: echConfigList,
	}
	record, err = record.Normalized()
	if err != nil {
		return err
	}
	content, err := record.Content()
	if err != nil {
		return err
	}
	svcParams := record.SvcParams()

	m.echMu.Lock()
	if m.echRecords == nil {
		m.echRecords = make(map[string]HTTPSRecord)
	}
	m.echRecords[hostname] = record
	m.echMu.Unlock()

	publicIP, err := utils.ResolvePublicIPv4(ctx)
	if err != nil {
		return fmt.Errorf("detect public ip for ECH hostname %s: %w", hostname, err)
	}
	if err := m.dns.EnsureARecord(ctx, hostname, publicIP); err != nil {
		return fmt.Errorf("ensure ECH A record for %s: %w", hostname, err)
	}

	if err := m.dns.EnsureHTTPSRecord(ctx, hostname, record.Priority, record.Target, svcParams, content); err != nil {
		return err
	}
	return nil
}

func (m *Manager) DeleteECHConfig(ctx context.Context, hostname string) error {
	if m == nil || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}
	if m.dns == nil {
		return nil
	}
	hostname = utils.NormalizeHostname(hostname)
	if hostname == "" {
		return nil
	}
	if !utils.HostnameMatchesBaseDomain(hostname, m.cfg.BaseDomain) {
		return nil
	}

	if err := m.dns.DeleteHTTPSRecord(ctx, hostname); err != nil {
		return err
	}
	if hostname != m.cfg.BaseDomain {
		if err := m.dns.DeleteARecord(ctx, hostname); err != nil {
			return fmt.Errorf("delete ECH A record for %s: %w", hostname, err)
		}
	}

	m.echMu.Lock()
	delete(m.echRecords, hostname)
	m.echMu.Unlock()
	return nil
}

func (m *Manager) syncECHRecords(ctx context.Context) error {
	if m == nil || m.dns == nil || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}

	m.echMu.Lock()
	records := make(map[string]HTTPSRecord, len(m.echRecords))
	for hostname, record := range m.echRecords {
		records[hostname] = record
	}
	m.echMu.Unlock()

	var syncErr error
	publicIP := ""
	if len(records) > 0 {
		var err error
		publicIP, err = utils.ResolvePublicIPv4(ctx)
		if err != nil {
			return fmt.Errorf("detect public ip for ECH records: %w", err)
		}
	}
	for hostname, record := range records {
		if err := m.dns.EnsureARecord(ctx, hostname, publicIP); err != nil {
			syncErr = errors.Join(syncErr, fmt.Errorf("ensure ECH A record for %s: %w", hostname, err))
			continue
		}
		content, err := record.Content()
		if err != nil {
			syncErr = errors.Join(syncErr, fmt.Errorf("build ECH HTTPS record for %s: %w", hostname, err))
			continue
		}
		if err := m.dns.EnsureHTTPSRecord(ctx, hostname, record.Priority, record.Target, record.SvcParams(), content); err != nil {
			syncErr = errors.Join(syncErr, fmt.Errorf("ensure ECH HTTPS record for %s: %w", hostname, err))
		}
	}
	return syncErr
}

func (m *Manager) syncENSGasless(ctx context.Context) error {
	if m == nil || !m.cfg.ENSGaslessEnabled || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}
	if m.dns == nil {
		return errors.New("ACME_DNS_PROVIDER is required")
	}

	state, dsRecord, message, err := m.dns.EnsureDNSSEC(ctx, m.cfg.BaseDomain)
	if err != nil {
		m.setENSStatus("", "", "", err)
		return fmt.Errorf("ensure dnssec: %w", err)
	}
	m.dnssecLogOnce.Do(func() {
		event := log.Info().
			Str("provider", m.dns.Name()).
			Str("base_domain", m.cfg.BaseDomain).
			Str("state", strings.TrimSpace(state))
		if strings.TrimSpace(dsRecord) != "" {
			event = event.Str("ds_record", strings.TrimSpace(dsRecord))
		}
		if strings.TrimSpace(message) != "" {
			event = event.Str("message", strings.TrimSpace(message))
		}
		event.Msg("dnssec configured")
	})

	if err := m.SyncENSGaslessHostname(ctx, m.cfg.BaseDomain, m.cfg.ENSGaslessAddress); err != nil {
		err = fmt.Errorf("ensure ens gasless txt: %w", err)
		m.setENSStatus(state, dsRecord, message, err)
		return err
	}
	if err := m.syncTrackedENSGaslessHostARecords(ctx); err != nil {
		m.setENSStatus(state, dsRecord, message, err)
		return err
	}
	m.setENSStatus(state, dsRecord, message, nil)
	m.ensLogOnce.Do(func() {
		log.Info().
			Str("provider", m.dns.Name()).
			Str("base_domain", m.cfg.BaseDomain).
			Str("address", m.cfg.ENSGaslessAddress).
			Msg("ens gasless dns import configured")
	})
	return nil
}

func (m *Manager) SyncENSGaslessHostname(ctx context.Context, hostname, address string) error {
	if m == nil || !m.cfg.ENSGaslessEnabled || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}
	if m.dns == nil {
		return errors.New("ACME_DNS_PROVIDER is required")
	}

	hostname = utils.NormalizeHostname(hostname)
	if hostname == "" {
		return errors.New("hostname is required")
	}
	if !utils.HostnameMatchesBaseDomain(hostname, m.cfg.BaseDomain) {
		return fmt.Errorf("hostname %q is outside acme base domain %q", hostname, m.cfg.BaseDomain)
	}

	address, err := identity.NormalizeEVMAddress(address)
	if err != nil {
		return fmt.Errorf("normalize ens gasless address: %w", err)
	}
	if err := m.syncENSGaslessHostnameARecord(ctx, hostname); err != nil {
		return err
	}
	if err := m.dns.EnsureTXTRecord(ctx, hostname, gaslessENSTXTPrefix+defaultENSGaslessResolver+" "+strings.TrimSpace(address)); err != nil {
		return err
	}
	return m.updateTrackedENSGaslessHostnames(func(hostnames []string) []string {
		return append(hostnames, hostname)
	})
}

func (m *Manager) DeleteENSGaslessHostname(ctx context.Context, hostname string) error {
	if m == nil || !m.cfg.ENSGaslessEnabled || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}
	if m.dns == nil {
		return errors.New("ACME_DNS_PROVIDER is required")
	}

	hostname = utils.NormalizeHostname(hostname)
	if hostname == "" {
		return nil
	}
	if !utils.HostnameMatchesBaseDomain(hostname, m.cfg.BaseDomain) {
		return nil
	}
	if hostname == m.cfg.BaseDomain {
		return nil
	}
	if err := m.dns.DeleteTXTRecords(ctx, hostname, gaslessENSTXTPrefix); err != nil {
		return err
	}
	if err := m.dns.DeleteARecord(ctx, hostname); err != nil {
		return err
	}
	return m.updateTrackedENSGaslessHostnames(func(hostnames []string) []string {
		filtered := hostnames[:0]
		for _, tracked := range hostnames {
			if tracked == hostname {
				continue
			}
			filtered = append(filtered, tracked)
		}
		return filtered
	})
}

func (m *Manager) reconcileTrackedENSGaslessHostnames(ctx context.Context) error {
	if m == nil || !m.cfg.ENSGaslessEnabled || utils.IsLocalRelayHost(m.cfg.BaseDomain) || m.dns == nil {
		return nil
	}

	var cleanupErr error
	if err := m.updateTrackedENSGaslessHostnames(func(hostnames []string) []string {
		remaining := hostnames[:0]
		for _, hostname := range hostnames {
			if err := m.dns.DeleteTXTRecords(ctx, hostname, gaslessENSTXTPrefix); err != nil {
				remaining = append(remaining, hostname)
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("delete ens gasless txt for %s: %w", hostname, err))
				continue
			}
			if err := m.dns.DeleteARecord(ctx, hostname); err != nil {
				remaining = append(remaining, hostname)
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("delete ens gasless A record for %s: %w", hostname, err))
			}
		}
		return remaining
	}); err != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("persist ens gasless hostnames: %w", err))
	}
	return cleanupErr
}

func (m *Manager) syncTrackedENSGaslessHostARecords(ctx context.Context) error {
	hostnames, err := m.trackedENSGaslessHostnames()
	if err != nil || len(hostnames) == 0 {
		return err
	}

	publicIP, err := utils.ResolvePublicIPv4(ctx)
	if err != nil {
		return fmt.Errorf("detect public ip: %w", err)
	}
	for _, hostname := range hostnames {
		if err := m.dns.EnsureARecord(ctx, hostname, publicIP); err != nil {
			return fmt.Errorf("ensure ens gasless A record for %s: %w", hostname, err)
		}
	}
	return nil
}

func (m *Manager) syncENSGaslessHostnameARecord(ctx context.Context, hostname string) error {
	hostname = utils.NormalizeHostname(hostname)
	if hostname == "" || hostname == m.cfg.BaseDomain {
		return nil
	}

	publicIP, err := utils.ResolvePublicIPv4(ctx)
	if err != nil {
		return fmt.Errorf("detect public ip: %w", err)
	}
	if err := m.dns.EnsureARecord(ctx, hostname, publicIP); err != nil {
		return fmt.Errorf("ensure ens gasless A record for %s: %w", hostname, err)
	}
	return nil
}

func (m *Manager) trackedENSGaslessHostnames() ([]string, error) {
	if m == nil {
		return nil, nil
	}

	path := filepath.Join(m.cfg.KeyDir, ensGaslessHostnamesFileName)
	var hostnames []string
	if _, err := utils.ReadJSONFileIfExists(path, &hostnames); err != nil {
		return nil, err
	}
	return utils.NormalizeChildHostnames(hostnames, m.cfg.BaseDomain), nil
}

func (m *Manager) updateTrackedENSGaslessHostnames(update func([]string) []string) error {
	if m == nil {
		return nil
	}

	m.trackedMu.Lock()
	defer m.trackedMu.Unlock()

	path := filepath.Join(m.cfg.KeyDir, ensGaslessHostnamesFileName)
	hostnames, err := m.trackedENSGaslessHostnames()
	if err != nil {
		return err
	}
	if update != nil {
		hostnames = utils.NormalizeChildHostnames(update(hostnames), m.cfg.BaseDomain)
	}
	if len(hostnames) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return utils.WriteJSONFile(path, hostnames, 0o600)
}

func (m *Manager) shouldRenew() bool {
	certFile := filepath.Join(m.cfg.KeyDir, fullChainFileName)
	needsRenewal, err := certNeedsRenewal(certFile, certificateDomains(m.cfg.BaseDomain))
	return err == nil && needsRenewal
}

func certificateDomains(baseDomain string) []string {
	return []string{baseDomain, "*." + baseDomain}
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
	for _, domain := range domains {
		if wildcardDomain, ok := strings.CutPrefix(domain, "*."); ok {
			if !certificateCoversHostname(cert, "probe."+wildcardDomain) {
				return false
			}
			continue
		}
		if !certificateCoversHostname(cert, domain) {
			return false
		}
	}
	return true
}

func certificateCoversHostname(cert *x509.Certificate, hostname string) bool {
	return cert != nil && cert.VerifyHostname(hostname) == nil
}

func newClient(ctx context.Context, email, accountKeyFile, registrationFile string, dnsProvider DNSProvider) (*lego.Client, error) {
	accountKey, err := loadOrCreateAccountKey(accountKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load acme account key: %w", err)
	}

	var accountReg registration.Resource
	accountRegPtr := (*registration.Resource)(nil)
	if ok, err := utils.ReadJSONFileIfExists(registrationFile, &accountReg); err != nil {
		return nil, fmt.Errorf("load acme registration: %w", err)
	} else if ok {
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

	if dnsProvider == nil {
		return nil, errors.New("ACME_DNS_PROVIDER is required")
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
