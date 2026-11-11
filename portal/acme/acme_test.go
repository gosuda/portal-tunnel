package acme

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

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

	if err := manager.EnsureTLSMaterial(context.Background()); err != nil {
		t.Fatalf("EnsureTLSMaterial() error = %v", err)
	}
	if manager.TLSMaterial() == nil {
		t.Fatal("EnsureTLSMaterial() loaded no certificate")
	}

	certFile, _, err := manager.TLSFiles()
	if err != nil {
		t.Fatalf("TLSFiles() error = %v", err)
	}
	cert, err := loadCertificate(certFile)
	if err != nil {
		t.Fatalf("loadCertificate() error = %v", err)
	}
	if !localDevelopmentCertificateReusable(cert, localDevelopmentDomains("localhost"), time.Now().UTC()) {
		t.Fatalf("issued certificate valid from %v to %v is replaced on the next start", cert.NotBefore, cert.NotAfter)
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
	if status := manager.ENSStatus(); status.Provider != TypeEmbedded {
		t.Fatalf("ENSStatus().Provider = %q, want embedded default", status.Provider)
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

	if err := manager.EnsureTLSMaterial(context.Background()); err != nil {
		t.Fatalf("EnsureTLSMaterial() error = %v", err)
	}
	if manager.TLSMaterial() == nil {
		t.Fatal("EnsureTLSMaterial() loaded no certificate")
	}
}

func TestNewManagerRejectsEmptyKeyDirectory(t *testing.T) {
	workingDir := t.TempDir()
	t.Chdir(workingDir)

	for _, provider := range []string{"", TypeEmbedded, TypeCloudflare, TypeGCloud, TypeHetzner, TypeNjalla, TypeRoute53, TypeVultr} {
		for _, keyDir := range []string{"", " \t"} {
			manager, err := NewManager(Config{
				BaseDomain:      "portal.example.com",
				KeyDir:          keyDir,
				DNSProvider:     provider,
				EmbeddedDNSPort: 0,
			})
			if manager != nil {
				_ = manager.Stop(context.Background())
				t.Fatalf("NewManager(DNSProvider=%q, KeyDir=%q) returned a manager for an empty key directory", provider, keyDir)
			}
			if err == nil || err.Error() != "acme key directory is required" {
				t.Fatalf("NewManager(DNSProvider=%q, KeyDir=%q) error = %v, want key-directory error before creating provider resources", provider, keyDir, err)
			}
		}
	}
	entries, err := os.ReadDir(workingDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("NewManager() created files with an empty key directory: %v", entries)
	}
}

func TestManagedCertificateRequiresPublicAddress(t *testing.T) {
	outage := errors.New("public IP discovery is unavailable")
	originalClient := utils.DefaultHTTPClient
	utils.DefaultHTTPClient = &http.Client{Transport: publicIPTransport{err: outage}}
	t.Cleanup(func() { utils.DefaultHTTPClient = originalClient })

	for _, provider := range []string{TypeEmbedded, TypeCloudflare} {
		for _, cached := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cached=%t", provider, cached), func(t *testing.T) {
				keyDir := t.TempDir()
				if cached {
					seedManualCertCache(t, keyDir)
				}
				manager := newTestManager(t, Config{
					BaseDomain:  "portal.example.com",
					KeyDir:      keyDir,
					DNSProvider: provider,
				})
				checkPublicAddressFailure(t, manager, outage)
			})
		}
	}
}

func seedManualCertCache(t *testing.T, keyDir string) {
	t.Helper()
	if err := writeManualRelayCertificate(t, keyDir, "portal.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, accountKeyFileName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func checkPublicAddressFailure(t *testing.T, manager *Manager, outage error) {
	t.Helper()
	if err := manager.EnsureTLSMaterial(context.Background()); !errors.Is(err, outage) || manager.TLSMaterial() != nil {
		t.Fatalf("EnsureTLSMaterial() = %v with certificate loaded %v, want discovery failure for managed issuance", err, manager.TLSMaterial() != nil)
	}
}

func newTestManager(t *testing.T, cfg Config) *Manager {
	t.Helper()
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Stop(context.Background()); err != nil {
			t.Errorf("Stop(): %v", err)
		}
	})
	return manager
}

func TestManualEmbeddedCertificateDoesNotIgnoreCancellation(t *testing.T) {
	keyDir := t.TempDir()
	if err := writeManualRelayCertificate(t, keyDir, "portal.example.com"); err != nil {
		t.Fatal(err)
	}
	manager := newTestManager(t, Config{
		BaseDomain: "portal.example.com",
		KeyDir:     keyDir,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := manager.EnsureTLSMaterial(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("EnsureTLSMaterial() error = %v, want caller cancellation preserved", err)
	}
}
