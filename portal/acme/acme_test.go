package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
)

type retryDNSProvider struct {
	deleteHTTPSCalls int
	failDeleteHTTPS  bool
	deleteACalls     int
	deleteTXTCalls   int
	failDeleteTXT    bool
}

func (p *retryDNSProvider) Name() string { return "retry" }
func (p *retryDNSProvider) ChallengeProvider(context.Context) (challenge.Provider, error) {
	return nil, nil
}
func (p *retryDNSProvider) EnsureARecords(context.Context, string, string) error { return nil }
func (p *retryDNSProvider) EnsureARecord(context.Context, string, string) error  { return nil }
func (p *retryDNSProvider) DeleteARecord(context.Context, string) error {
	p.deleteACalls++
	return nil
}
func (p *retryDNSProvider) EnsureTXTRecord(context.Context, string, string) error {
	return nil
}
func (p *retryDNSProvider) DeleteTXTRecords(context.Context, string, string) error {
	p.deleteTXTCalls++
	if p.failDeleteTXT {
		p.failDeleteTXT = false
		return errors.New("temporary delete failure")
	}
	return nil
}
func (p *retryDNSProvider) EnsureHTTPSRecord(context.Context, string, dnsrecord.HTTPSRecord) error {
	return nil
}
func (p *retryDNSProvider) DeleteHTTPSRecord(context.Context, string) error {
	p.deleteHTTPSCalls++
	if p.failDeleteHTTPS {
		p.failDeleteHTTPS = false
		return errors.New("temporary delete failure")
	}
	return nil
}
func (p *retryDNSProvider) EnsureDNSSEC(context.Context, string) (string, string, string, error) {
	return "", "", "", nil
}

func TestECHDNSChannelQueuesDeleteForWorker(t *testing.T) {
	provider := &retryDNSProvider{failDeleteHTTPS: true}
	manager := &Manager{
		cfg:         Config{BaseDomain: "example.com"},
		dns:         provider,
		stopCh:      make(chan struct{}),
		echCommands: make(chan echDNSCommand, 1),
	}

	if err := manager.DeleteECHConfig(context.Background(), "tenant.example.com"); err != nil {
		t.Fatalf("DeleteECHConfig() error = %v", err)
	}
	if provider.deleteHTTPSCalls != 0 {
		t.Fatalf("DeleteECHConfig() called provider synchronously: calls = %d", provider.deleteHTTPSCalls)
	}
	command := <-manager.echCommands
	if err := manager.applyECHCommand(context.Background(), command); err == nil {
		t.Fatal("applyECHCommand() error = nil, want transient provider error")
	}
	if provider.deleteHTTPSCalls != 1 {
		t.Fatalf("DeleteHTTPSRecord() calls = %d, want 1", provider.deleteHTTPSCalls)
	}
	if err := manager.applyECHCommand(context.Background(), command); err != nil {
		t.Fatalf("applyECHCommand() retry error = %v", err)
	}
	if provider.deleteHTTPSCalls != 2 {
		t.Fatalf("DeleteHTTPSRecord() calls after retry = %d, want 2", provider.deleteHTTPSCalls)
	}
}

func TestENSDNSChannelQueuesDeleteForWorker(t *testing.T) {
	provider := &retryDNSProvider{failDeleteTXT: true}
	manager := &Manager{
		cfg: Config{
			BaseDomain:        "example.com",
			KeyDir:            t.TempDir(),
			ENSGaslessEnabled: true,
		},
		dns:         provider,
		stopCh:      make(chan struct{}),
		ensCommands: make(chan ensDNSCommand, 1),
	}

	if err := manager.DeleteENSGaslessHostname(context.Background(), "tenant.example.com"); err != nil {
		t.Fatalf("DeleteENSGaslessHostname() error = %v", err)
	}
	if provider.deleteTXTCalls != 0 || provider.deleteACalls != 0 {
		t.Fatalf("DeleteENSGaslessHostname() called provider synchronously: TXT = %d, A = %d", provider.deleteTXTCalls, provider.deleteACalls)
	}
	command := <-manager.ensCommands
	if err := manager.applyENSCommand(context.Background(), command); err == nil {
		t.Fatal("applyENSCommand() error = nil, want transient provider error")
	}
	if provider.deleteTXTCalls != 1 || provider.deleteACalls != 0 {
		t.Fatalf("provider calls after failure: TXT = %d, A = %d; want TXT = 1, A = 0", provider.deleteTXTCalls, provider.deleteACalls)
	}
	if err := manager.applyENSCommand(context.Background(), command); err != nil {
		t.Fatalf("applyENSCommand() retry error = %v", err)
	}
	if provider.deleteTXTCalls != 2 || provider.deleteACalls != 1 {
		t.Fatalf("provider calls after retry: TXT = %d, A = %d; want TXT = 2, A = 1", provider.deleteTXTCalls, provider.deleteACalls)
	}
}

func TestEnsureCertificateGeneratesLocalDevelopmentMaterial(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()
	manager, err := NewManager(Config{
		BaseDomain: "localhost",
		KeyDir:     keyDir,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	certPEM, keyPEM, err := manager.EnsureTLSMaterial(context.Background())
	if err != nil {
		t.Fatalf("EnsureTLSMaterial() error = %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatalf("EnsureTLSMaterial() returned empty PEM material")
	}

	certFile, _, err := manager.TLSFiles()
	if err != nil {
		t.Fatalf("TLSFiles() error = %v", err)
	}
	covered, err := certCoversDomains(certFile, []string{"localhost"})
	if err != nil {
		t.Fatalf("certCoversDomains() error = %v", err)
	}
	if !covered {
		t.Fatal("certCoversDomains() = false, want true")
	}
}

func TestEnsureTLSMaterialUsesManualCertificateWithDefaultEmbeddedProvider(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()
	if err := writeManualRelayCertificate(t, keyDir, "portal.example.com"); err != nil {
		t.Fatalf("writeManualRelayCertificate() error = %v", err)
	}

	manager, err := NewManager(Config{
		BaseDomain:      "portal.example.com",
		KeyDir:          keyDir,
		EmbeddedDNSPort: 0,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { _ = manager.Stop(context.Background()) })

	certPEM, keyPEM, err := manager.EnsureTLSMaterial(context.Background())
	if err != nil {
		t.Fatalf("EnsureTLSMaterial() error = %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatalf("EnsureTLSMaterial() returned empty PEM material")
	}
}

func TestNewManagerDefaultsToEmbeddedProvider(t *testing.T) {
	t.Parallel()

	manager, err := NewManager(Config{
		BaseDomain:      "portal.example.com",
		KeyDir:          t.TempDir(),
		EmbeddedDNSPort: 0,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if manager.dns == nil || manager.dns.Name() != TypeEmbedded {
		t.Fatalf("dns provider = %v, want embedded default", manager.dns)
	}
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v, want embedded listeners closed", err)
	}
}

func TestNewManagerRejectsENSGaslessWithEmbeddedProvider(t *testing.T) {
	t.Parallel()

	_, err := NewManager(Config{
		BaseDomain:        "portal.example.com",
		KeyDir:            t.TempDir(),
		DNSProvider:       TypeEmbedded,
		ENSGaslessEnabled: true,
		ENSGaslessAddress: "0x1234567890123456789012345678901234567890",
	})
	if err == nil {
		t.Fatal("NewManager() error = nil, want embedded ENS gasless error")
	}
	if got := err.Error(); got != "ens gasless automation is not supported by the embedded dns provider yet" {
		t.Fatalf("NewManager() error = %q, want embedded dnssec guidance", got)
	}
}

func TestManagerStopsEmbeddedDNSServer(t *testing.T) {
	t.Parallel()

	manager, err := NewManager(Config{
		BaseDomain:      "portal.example.com",
		KeyDir:          t.TempDir(),
		DNSProvider:     TypeEmbedded,
		EmbeddedDNSPort: 0,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v, want embedded provider", err)
	}
	if manager.dns == nil || manager.dns.Name() != TypeEmbedded {
		t.Fatalf("dns provider = %v, want embedded", manager.dns)
	}
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v, want embedded listeners closed", err)
	}
}

func TestEnsureTLSMaterialUsesManualCertificateWithDNSProvider(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()
	if err := writeManualRelayCertificate(t, keyDir, "portal.example.com"); err != nil {
		t.Fatalf("writeManualRelayCertificate() error = %v", err)
	}

	manager, err := NewManager(Config{
		BaseDomain:  "portal.example.com",
		KeyDir:      keyDir,
		DNSProvider: TypeRoute53,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	certPEM, keyPEM, err := manager.EnsureTLSMaterial(context.Background())
	if err != nil {
		t.Fatalf("EnsureTLSMaterial() error = %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatalf("EnsureTLSMaterial() returned empty PEM material")
	}
}

func writeManualRelayCertificate(t *testing.T, keyDir, baseDomain string) error {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName: baseDomain,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		DNSNames:              []string{baseDomain, "*." + baseDomain},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(filepath.Join(keyDir, fullChainFileName), certPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(keyDir, keyFileName), keyPEM, 0o600)
}

func containsAll(text string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(text, part) {
			return false
		}
	}
	return true
}
