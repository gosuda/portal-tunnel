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
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
)

type echTestDNSProvider struct {
	mu sync.Mutex

	failEnsureA     int
	failEnsureHTTPS int
	failDeleteA     int

	ensureHTTPSCalls int
	deleteHTTPSCalls int
	deleteACalls     int

	ensureHTTPSDone chan struct{}
	deleteADone     chan struct{}
	deleteStarted   chan struct{}
	deleteBlock     chan struct{}
	deleteStartOnce sync.Once
}

func (*echTestDNSProvider) Name() string { return "test" }
func (*echTestDNSProvider) ChallengeProvider(context.Context) (challenge.Provider, error) {
	return nil, nil
}
func (*echTestDNSProvider) EnsureARecords(context.Context, string, string) error { return nil }
func (p *echTestDNSProvider) EnsureARecord(context.Context, string, string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failEnsureA > 0 {
		p.failEnsureA--
		return errors.New("ensure A failed")
	}
	return nil
}
func (p *echTestDNSProvider) DeleteARecord(context.Context, string) error {
	p.mu.Lock()
	p.deleteACalls++
	if p.failDeleteA > 0 {
		p.failDeleteA--
		p.mu.Unlock()
		return errors.New("delete A failed")
	}
	done := p.deleteADone
	p.mu.Unlock()
	if done != nil {
		select {
		case done <- struct{}{}:
		default:
		}
	}
	return nil
}
func (*echTestDNSProvider) EnsureTXTRecord(context.Context, string, string) error  { return nil }
func (*echTestDNSProvider) DeleteTXTRecords(context.Context, string, string) error { return nil }
func (p *echTestDNSProvider) EnsureHTTPSRecord(context.Context, string, uint16, string, string, string) error {
	p.mu.Lock()
	p.ensureHTTPSCalls++
	if p.failEnsureHTTPS > 0 {
		p.failEnsureHTTPS--
		p.mu.Unlock()
		return errors.New("ensure HTTPS failed")
	}
	done := p.ensureHTTPSDone
	p.mu.Unlock()
	if done != nil {
		select {
		case done <- struct{}{}:
		default:
		}
	}
	return nil
}
func (p *echTestDNSProvider) DeleteHTTPSRecord(ctx context.Context, _ string) error {
	p.mu.Lock()
	p.deleteHTTPSCalls++
	started := p.deleteStarted
	block := p.deleteBlock
	p.mu.Unlock()
	if started != nil {
		p.deleteStartOnce.Do(func() { close(started) })
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
func (*echTestDNSProvider) EnsureDNSSEC(context.Context, string) (string, string, string, error) {
	return "", "", "", nil
}

func newECHTestManager(provider DNSProvider) *Manager {
	return &Manager{
		cfg:         Config{BaseDomain: "example.com"},
		dns:         provider,
		stopCh:      make(chan struct{}),
		resolveIPv4: func(context.Context) (string, error) { return "203.0.113.10", nil },
	}
}

func testECHConfigList(t *testing.T, hostname string) []byte {
	t.Helper()
	_, configList, err := keyless.EncryptedClientHelloMaterials("test seed", hostname)
	if err != nil {
		t.Fatalf("EncryptedClientHelloMaterials() error = %v", err)
	}
	return configList
}

func waitECHTestSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for ECH DNS operation")
	}
}

func TestECHRetryDelayUsesBoundedExponentialBackoff(t *testing.T) {
	for failures, upper := range []time.Duration{
		time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
	} {
		delay := echRetryDelay(failures + 1)
		if delay < upper/2 || delay > upper {
			t.Fatalf("echRetryDelay(%d) = %v, want jittered range [%v, %v]", failures+1, delay, upper/2, upper)
		}
	}
	delay := echRetryDelay(100)
	if delay < defaultECHRetryMax/2 || delay > defaultECHRetryMax {
		t.Fatalf("echRetryDelay(100) = %v, want bounded range [%v, %v]", delay, defaultECHRetryMax/2, defaultECHRetryMax)
	}
}

func TestECHDNSRetriesCreateAndUpdate(t *testing.T) {
	provider := &echTestDNSProvider{
		failEnsureA:     1,
		ensureHTTPSDone: make(chan struct{}, 1),
	}
	manager := newECHTestManager(provider)
	defer manager.Stop()
	hostname := "tunnel.example.com"
	configList := testECHConfigList(t, hostname)

	if err := manager.SyncECHConfig(context.Background(), hostname, configList, 443); err == nil {
		t.Fatal("SyncECHConfig(create) error = nil, want provider failure")
	}
	waitECHTestSignal(t, provider.ensureHTTPSDone)

	provider.mu.Lock()
	provider.failEnsureHTTPS = 1
	provider.mu.Unlock()
	if err := manager.SyncECHConfig(context.Background(), hostname, configList, 8443); err == nil {
		t.Fatal("SyncECHConfig(update) error = nil, want provider failure")
	}
	waitECHTestSignal(t, provider.ensureHTTPSDone)
}

func TestECHDNSDeleteRetryResumesAndRemovesState(t *testing.T) {
	provider := &echTestDNSProvider{deleteADone: make(chan struct{}, 1)}
	manager := newECHTestManager(provider)
	defer manager.Stop()
	hostname := "tunnel.example.com"
	if err := manager.SyncECHConfig(context.Background(), hostname, testECHConfigList(t, hostname), 443); err != nil {
		t.Fatalf("SyncECHConfig() error = %v", err)
	}
	provider.mu.Lock()
	provider.failDeleteA = 1
	provider.mu.Unlock()

	if err := manager.DeleteECHConfig(context.Background(), hostname); err == nil {
		t.Fatal("DeleteECHConfig() error = nil, want provider failure")
	}
	waitECHTestSignal(t, provider.deleteADone)

	provider.mu.Lock()
	deleteHTTPSCalls := provider.deleteHTTPSCalls
	deleteACalls := provider.deleteACalls
	provider.mu.Unlock()
	if deleteHTTPSCalls != 1 {
		t.Fatalf("DeleteHTTPSRecord() calls = %d, want 1", deleteHTTPSCalls)
	}
	if deleteACalls != 2 {
		t.Fatalf("DeleteARecord() calls = %d, want 2", deleteACalls)
	}
	deadline := time.Now().Add(time.Second)
	for {
		manager.echMu.Lock()
		_, exists := manager.echRecords[hostname]
		manager.echMu.Unlock()
		if !exists {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ECH DNS state remains after successful delete retry")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestECHDNSStaleDeleteCannotRemoveNewCreate(t *testing.T) {
	provider := &echTestDNSProvider{
		deleteStarted: make(chan struct{}),
		deleteBlock:   make(chan struct{}),
	}
	manager := newECHTestManager(provider)
	defer manager.Stop()
	hostname := "tunnel.example.com"
	configList := testECHConfigList(t, hostname)
	if err := manager.SyncECHConfig(context.Background(), hostname, configList, 443); err != nil {
		t.Fatalf("SyncECHConfig(initial) error = %v", err)
	}

	deleteDone := make(chan error, 1)
	go func() { deleteDone <- manager.DeleteECHConfig(context.Background(), hostname) }()
	<-provider.deleteStarted
	createDone := make(chan error, 1)
	go func() { createDone <- manager.SyncECHConfig(context.Background(), hostname, configList, 8443) }()
	deadline := time.Now().Add(time.Second)
	for manager.echMu.TryLock() {
		manager.echMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("replacement create did not acquire ECH state map lock")
		}
		time.Sleep(time.Millisecond)
	}
	close(provider.deleteBlock)
	if err := <-deleteDone; err != nil {
		t.Fatalf("DeleteECHConfig() error = %v", err)
	}
	if err := <-createDone; err != nil {
		t.Fatalf("SyncECHConfig(replacement) error = %v", err)
	}

	manager.echMu.Lock()
	state := manager.echRecords[hostname]
	if state != nil {
		state.mu.Lock()
	}
	manager.echMu.Unlock()
	if state == nil {
		t.Fatal("replacement ECH DNS state was removed by stale delete")
	}
	present := state.present
	state.mu.Unlock()
	if !present {
		t.Fatal("replacement ECH DNS state is not present")
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

func TestEnsureTLSMaterialUsesManualCertificateWithoutDNSProvider(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()
	if err := writeManualRelayCertificate(t, keyDir, "portal.example.com"); err != nil {
		t.Fatalf("writeManualRelayCertificate() error = %v", err)
	}

	manager, err := NewManager(Config{
		BaseDomain: "portal.example.com",
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
}

func TestEnsureTLSMaterialRequiresManualCertificateWhenProviderUnset(t *testing.T) {
	t.Parallel()

	manager, err := NewManager(Config{
		BaseDomain: "portal.example.com",
		KeyDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	_, _, err = manager.EnsureTLSMaterial(context.Background())
	if err == nil {
		t.Fatal("EnsureTLSMaterial() error = nil, want missing manual certificate error")
	}
	if got := err.Error(); got == "" || !containsAll(got, "manual certificate mode requires", "fullchain.pem", "privatekey.pem") {
		t.Fatalf("EnsureTLSMaterial() error = %q, want manual certificate guidance", got)
	}
}

func TestNewManagerRejectsENSGaslessWithoutDNSProvider(t *testing.T) {
	t.Parallel()

	_, err := NewManager(Config{
		BaseDomain:        "portal.example.com",
		KeyDir:            t.TempDir(),
		ENSGaslessEnabled: true,
		ENSGaslessAddress: "0x1234567890123456789012345678901234567890",
	})
	if err == nil {
		t.Fatal("NewManager() error = nil, want ENS gasless provider error")
	}
	if got := err.Error(); got != "ens gasless automation requires ACME_DNS_PROVIDER" {
		t.Fatalf("NewManager() error = %q, want ENS gasless provider guidance", got)
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
