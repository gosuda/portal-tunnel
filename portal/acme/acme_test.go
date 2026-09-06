package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/embedded"
	"github.com/gosuda/portal-tunnel/v2/types"
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

// Without ACME state or ENS automation, an operator-supplied certificate wins
// over managed issuance and loading it does not need provider credentials.
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

func TestNewDNSProviderRejectsEmptyEmbeddedKeyDirectory(t *testing.T) {
	t.Chdir(t.TempDir())

	for _, provider := range []string{"", TypeEmbedded} {
		for _, keyDir := range []string{"", " \t"} {
			dnsProvider, err := NewDNSProvider(provider, Config{
				BaseDomain:      "portal.example.com",
				KeyDir:          keyDir,
				EmbeddedDNSPort: 0,
			})
			if err == nil {
				if server, ok := dnsProvider.(interface{ Stop() error }); ok {
					_ = server.Stop()
				}
				t.Fatalf("NewDNSProvider(%q, KeyDir=%q) accepted an empty key directory", provider, keyDir)
			}
			if !strings.Contains(err.Error(), "key directory is required") {
				t.Fatalf("NewDNSProvider() error = %v, want key-directory error before binding DNS", err)
			}
		}
	}
}

// Public-IP discovery is the only external dependency in this manual-certificate
// scenario. DNS answers below still travel through the real embedded listeners.
type publicIPv4Transport struct{}

func (publicIPv4Transport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("203.0.113.10")),
		Header:     make(http.Header),
	}, nil
}

func TestManualEmbeddedCertificateServesDNSAndKeepsENSPending(t *testing.T) {
	originalClient := utils.DefaultHTTPClient
	utils.DefaultHTTPClient = &http.Client{Transport: publicIPv4Transport{}}
	t.Cleanup(func() { utils.DefaultHTTPClient = originalClient })

	for _, ensEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("ens=%t", ensEnabled), func(t *testing.T) {
			const baseDomain = "portal.example.com"
			keyDir := t.TempDir()
			if err := writeManualRelayCertificate(t, keyDir, baseDomain); err != nil {
				t.Fatal(err)
			}
			manager, err := NewManager(Config{
				BaseDomain:        baseDomain,
				KeyDir:            keyDir,
				EmbeddedDNSPort:   0,
				ENSGaslessEnabled: ensEnabled,
				ENSGaslessAddress: "0x1234567890123456789012345678901234567890",
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := manager.Stop(context.Background()); err != nil {
					t.Errorf("Stop(): %v", err)
				}
			})
			provider, ok := manager.dns.(*embedded.Provider)
			if !ok {
				t.Fatalf("provider = %T, want embedded", manager.dns)
			}
			addr := utils.HostPortOrLoopback(provider.Addr())
			for range 2 {
				certPEM, keyPEM, err := manager.EnsureTLSMaterial(context.Background())
				if err != nil || len(certPEM) == 0 || len(keyPEM) == 0 {
					t.Fatalf("EnsureTLSMaterial() = %d certificate bytes, %d key bytes, %v", len(certPEM), len(keyPEM), err)
				}
				status := manager.ENSStatus()
				if status.Enabled != ensEnabled || status.Verified {
					t.Fatalf("ENSStatus() = %+v, local signing must not verify ENS", status)
				}
				dnssecSynced := status.DNSSECState == "pending" && status.DSRecord != "" && status.LastError == ""
				if ensEnabled && !dnssecSynced {
					t.Fatalf("ENSStatus() = %+v, want pending DS publication with successful synchronization", status)
				}
				for _, network := range []string{"udp", "tcp"} {
					client := &dns.Client{Net: network, Timeout: time.Second}
					for _, name := range []string{baseDomain, "ns." + baseDomain, "tenant." + baseDomain} {
						query := new(dns.Msg)
						query.SetQuestion(dns.Fqdn(name), dns.TypeA)
						answer, _, err := client.Exchange(query, addr)
						if err != nil {
							t.Fatal(err)
						}
						if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
							t.Fatalf("%s A %s = %v, want initialized manual-certificate address", network, name, answer)
						}
						a, ok := answer.Answer[0].(*dns.A)
						if !ok || a.A.String() != "203.0.113.10" {
							t.Fatalf("%s A %s = %v, want relay public IP", network, name, answer.Answer)
						}
					}
					if ensEnabled {
						query := new(dns.Msg)
						query.SetQuestion(dns.Fqdn(baseDomain), dns.TypeTXT)
						answer, _, err := client.Exchange(query, addr)
						if err != nil {
							t.Fatal(err)
						}
						if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
							t.Fatalf("%s TXT = %v, want ENS publication despite pending verification", network, answer)
						}
						txt, ok := answer.Answer[0].(*dns.TXT)
						if !ok || !strings.HasPrefix(strings.Join(txt.Txt, ""), "ENS1 ") {
							t.Fatalf("%s TXT = %v, want ENS1 record", network, answer.Answer)
						}
					}
				}
			}
			if _, err := os.Stat(filepath.Join(keyDir, types.DNSSECKeyFileName)); err != nil {
				t.Fatalf("persistent DNSSEC key: %v", err)
			}
		})
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
