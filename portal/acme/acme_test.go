package acme

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/miekg/dns"

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
	if status := manager.ENSStatus(); status.Provider != TypeEmbedded {
		t.Fatalf("ENSStatus().Provider = %q, want embedded default", status.Provider)
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

// Public-IP discovery is the only external dependency in this manual-certificate
// scenario. DNS answers below still travel through the real embedded listeners.
type publicIPv4Transport struct {
	err      error
	ip       string
	requests *atomic.Int32
}

func (transport publicIPv4Transport) RoundTrip(*http.Request) (*http.Response, error) {
	if transport.requests != nil {
		transport.requests.Add(1)
	}
	if transport.err != nil {
		return nil, transport.err
	}
	ip := cmp.Or(transport.ip, "203.0.113.10")
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(ip)),
		Header:     make(http.Header),
	}, nil
}

func TestManualEmbeddedCertificateServesDNSAndKeepsENSPending(t *testing.T) {
	originalClient := utils.DefaultHTTPClient
	t.Cleanup(func() { utils.DefaultHTTPClient = originalClient })

	for _, ensEnabled := range []bool{false, true} {
		for _, discoveryOutage := range []bool{false, true} {
			t.Run(fmt.Sprintf("ens=%t/discovery_outage=%t", ensEnabled, discoveryOutage), func(t *testing.T) {
				transport := publicIPv4Transport{}
				if discoveryOutage {
					transport.err = errors.New("public IPv4 discovery is unavailable")
				}
				utils.DefaultHTTPClient = &http.Client{Transport: transport}

				const baseDomain = "portal.example.com"
				keyDir := t.TempDir()
				if err := writeManualRelayCertificate(t, keyDir, baseDomain); err != nil {
					t.Fatal(err)
				}
				manager, cfg := newEmbeddedDNSManager(t, Config{
					BaseDomain:        baseDomain,
					KeyDir:            keyDir,
					ENSGaslessEnabled: ensEnabled,
					ENSGaslessAddress: "0x1234567890123456789012345678901234567890",
				})
				certPEM, keyPEM, err := manager.EnsureTLSMaterial(context.Background())
				if err != nil {
					t.Fatalf("EnsureTLSMaterial(): %v", err)
				}
				if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
					t.Fatalf("EnsureTLSMaterial() returned unusable certificate: %v", err)
				}

				publicIP := "203.0.113.10"
				if discoveryOutage {
					publicIP = ""
				}
				assertManualEmbeddedDNS(t, manager, cfg, publicIP)

				utils.DefaultHTTPClient = &http.Client{Transport: publicIPv4Transport{}}
				certPEM, keyPEM, err = manager.EnsureTLSMaterial(context.Background())
				if err != nil {
					t.Fatalf("reload manual certificate after discovery recovers: %v", err)
				}
				if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
					t.Fatalf("recovered EnsureTLSMaterial() returned unusable certificate: %v", err)
				}
				assertManualEmbeddedDNS(t, manager, cfg, "203.0.113.10")
				if _, err := os.Stat(filepath.Join(keyDir, types.DNSSECKeyFileName)); err != nil {
					t.Fatalf("persistent DNSSEC key: %v", err)
				}
			})
		}
	}
}

func TestManualEmbeddedCertificateRetriesPendingAddressInitialization(t *testing.T) {
	originalClient := utils.DefaultHTTPClient
	t.Cleanup(func() { utils.DefaultHTTPClient = originalClient })

	for _, discoveryOutage := range []bool{false, true} {
		t.Run(fmt.Sprintf("discovery_outage=%t", discoveryOutage), func(t *testing.T) {
			var requests atomic.Int32
			transport := publicIPv4Transport{requests: &requests}
			if discoveryOutage {
				transport.err = errors.New("public IPv4 discovery is unavailable")
			}
			utils.DefaultHTTPClient = &http.Client{Transport: transport}

			const baseDomain = "portal.example.com"
			keyDir := t.TempDir()
			if err := writeManualRelayCertificate(t, keyDir, baseDomain); err != nil {
				t.Fatal(err)
			}
			// Keep real DNS listeners outside the fake-time bubble so idle
			// network goroutines do not prevent the maintenance clock advancing.
			manager, cfg := newEmbeddedDNSManager(t, Config{
				BaseDomain: baseDomain,
				KeyDir:     keyDir,
			})
			certPEM, keyPEM, err := manager.EnsureTLSMaterial(context.Background())
			if err != nil {
				t.Fatalf("EnsureTLSMaterial(): %v", err)
			}
			if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
				t.Fatalf("EnsureTLSMaterial() returned unusable certificate: %v", err)
			}
			publicIP := "203.0.113.10"
			if discoveryOutage {
				publicIP = ""
			}
			assertManualEmbeddedDNS(t, manager, cfg, publicIP)
			startupRequests := requests.Load()

			synctest.Test(t, func(t *testing.T) {
				// synctest advances time only when every select channel belongs
				// to its bubble, making the idle maintenance loop durably blocked.
				// The manager has not started or accepted commands, so re-home
				// only these empty lifecycle channels, not the real DNS listeners.
				// Operations and assertions use public lifecycle and DNS wire.
				manager.stopCh = make(chan struct{})
				manager.echCommands = make(chan echDNSCommand, cap(manager.echCommands))
				manager.ensCommands = make(chan ensDNSCommand, cap(manager.ensCommands))
				defer func() {
					if err := manager.Stop(context.Background()); err != nil {
						t.Errorf("Stop(): %v", err)
					}
				}()
				manager.Start(context.Background())
				synctest.Wait()

				<-time.After(10*time.Minute - time.Second)
				synctest.Wait()
				if got := requests.Load(); got != startupRequests {
					t.Fatalf("discovery requests before retry tick = %d, want %d", got, startupRequests)
				}
				<-time.After(time.Second)
				synctest.Wait()
				if got := requests.Load(); discoveryOutage && got <= startupRequests {
					t.Fatalf("discovery requests after failed retry = %d, want more than %d", got, startupRequests)
				} else if !discoveryOutage && got != startupRequests {
					t.Fatalf("healthy initialization retried discovery: requests = %d, want %d", got, startupRequests)
				}
				assertManualEmbeddedDNS(t, manager, cfg, publicIP)

				// Recovery must come from Start's existing retry ticker, not a
				// second EnsureTLSMaterial call or a private synchronization API.
				utils.DefaultHTTPClient = &http.Client{Transport: publicIPv4Transport{requests: &requests}}
				<-time.After(10 * time.Minute)
				synctest.Wait()
				assertManualEmbeddedDNS(t, manager, cfg, "203.0.113.10")
				initializedRequests := requests.Load()

				// A new advertised address must wait for the normal refresh;
				// neither successful startup nor a recovered retry stays pending.
				utils.DefaultHTTPClient = &http.Client{Transport: publicIPv4Transport{
					ip:       "203.0.113.20",
					requests: &requests,
				}}
				<-time.After(160*time.Minute - time.Second)
				synctest.Wait()
				if got := requests.Load(); got != initializedRequests {
					t.Fatalf("successful initialization retried before normal refresh: requests = %d, want %d", got, initializedRequests)
				}
				assertManualEmbeddedDNS(t, manager, cfg, "203.0.113.10")

				<-time.After(time.Second)
				synctest.Wait()
				if got := requests.Load(); got != initializedRequests+1 {
					t.Fatalf("discovery requests after three-hour refresh = %d, want %d", got, initializedRequests+1)
				}
				assertManualEmbeddedDNS(t, manager, cfg, "203.0.113.20")
			})
		})
	}
}

func assertManualEmbeddedDNS(t *testing.T, manager *Manager, cfg Config, publicIP string) {
	t.Helper()

	status := manager.ENSStatus()
	if status.Enabled != cfg.ENSGaslessEnabled || status.Verified {
		t.Fatalf("ENSStatus() = %+v, local signing must not verify ENS", status)
	}
	dnssecSynced := status.DNSSECState == "pending" && status.DSRecord != "" && status.LastError == ""
	if cfg.ENSGaslessEnabled && !dnssecSynced {
		t.Fatalf("ENSStatus() = %+v, want pending DS publication with successful synchronization", status)
	}

	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(cfg.EmbeddedDNSPort))
	for _, network := range []string{"udp", "tcp"} {
		client := &dns.Client{Net: network, Timeout: time.Second}
		for _, name := range []string{cfg.BaseDomain, "ns." + cfg.BaseDomain, "tenant." + cfg.BaseDomain} {
			assertEmbeddedDNSAddress(t, client, addr, name, publicIP)
		}
		query := new(dns.Msg)
		query.SetQuestion(dns.Fqdn(cfg.BaseDomain), dns.TypeTXT)
		answer, _, err := client.Exchange(query, addr)
		if err != nil {
			t.Fatal(err)
		}
		if answer.Rcode != dns.RcodeSuccess || !answer.Authoritative {
			t.Fatalf("%s TXT = %v, want authoritative answer", network, answer)
		}
		if !cfg.ENSGaslessEnabled {
			if len(answer.Answer) != 0 {
				t.Fatalf("%s TXT = %v, ENS must remain opt-in", network, answer)
			}
			continue
		}
		if len(answer.Answer) != 1 {
			t.Fatalf("%s TXT = %v, want ENS publication despite pending verification", network, answer)
		}
		txt, ok := answer.Answer[0].(*dns.TXT)
		if !ok || !strings.HasPrefix(strings.Join(txt.Txt, ""), "ENS1 ") {
			t.Fatalf("%s TXT = %v, want ENS1 record", network, answer.Answer)
		}
	}
}

func assertEmbeddedDNSAddress(t *testing.T, client *dns.Client, addr, name, publicIP string) {
	t.Helper()

	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), dns.TypeA)
	answer, _, err := client.Exchange(query, addr)
	if err != nil {
		t.Fatal(err)
	}
	if !answer.Authoritative {
		t.Fatalf("%s A %s = %v, want authoritative answer", client.Net, name, answer)
	}
	if publicIP == "" {
		if len(answer.Answer) != 0 || (answer.Rcode != dns.RcodeSuccess && answer.Rcode != dns.RcodeNameError) {
			t.Fatalf("%s A %s = %v, want no address during discovery outage", client.Net, name, answer)
		}
		return
	}
	if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
		t.Fatalf("%s A %s = %v, want initialized manual-certificate address", client.Net, name, answer)
	}
	a, ok := answer.Answer[0].(*dns.A)
	if !ok || a.A.String() != publicIP {
		t.Fatalf("%s A %s = %v, want relay public IP %s", client.Net, name, answer.Answer, publicIP)
	}
}

func TestManagedCertificateRequiresPublicIPv4(t *testing.T) {
	outage := errors.New("public IPv4 discovery is unavailable")
	originalClient := utils.DefaultHTTPClient
	utils.DefaultHTTPClient = &http.Client{Transport: publicIPv4Transport{err: outage}}
	t.Cleanup(func() { utils.DefaultHTTPClient = originalClient })

	for _, provider := range []string{TypeEmbedded, TypeCloudflare} {
		for _, cached := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cached=%t", provider, cached), func(t *testing.T) {
				keyDir := t.TempDir()
				if cached {
					if err := writeManualRelayCertificate(t, keyDir, "portal.example.com"); err != nil {
						t.Fatal(err)
					}
					// Existing ACME state distinguishes a cached managed certificate
					// from an operator-supplied certificate.
					if err := os.WriteFile(filepath.Join(keyDir, accountKeyFileName), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				manager, err := NewManager(Config{
					BaseDomain:  "portal.example.com",
					KeyDir:      keyDir,
					DNSProvider: provider,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := manager.Stop(context.Background()); err != nil {
						t.Errorf("Stop(): %v", err)
					}
				})
				certPEM, keyPEM, err := manager.EnsureTLSMaterial(context.Background())
				if !errors.Is(err, outage) || len(certPEM) != 0 || len(keyPEM) != 0 {
					t.Fatalf("EnsureTLSMaterial() = %d certificate bytes, %d key bytes, %v, want discovery failure for managed issuance", len(certPEM), len(keyPEM), err)
				}
			})
		}
	}
}

func TestManualEmbeddedCertificateDoesNotIgnoreCancellation(t *testing.T) {
	keyDir := t.TempDir()
	if err := writeManualRelayCertificate(t, keyDir, "portal.example.com"); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(Config{
		BaseDomain: "portal.example.com",
		KeyDir:     keyDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Stop(context.Background()); err != nil {
			t.Errorf("Stop(): %v", err)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := manager.EnsureTLSMaterial(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("EnsureTLSMaterial() error = %v, want caller cancellation preserved", err)
	}
}

func TestEnsureTLSMaterialRejectsDNSRecordUpdateFailure(t *testing.T) {
	var updates atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "api.cloudflare.com" {
			_, _ = io.WriteString(w, "203.0.113.10")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones":
			_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"test-zone","name":"portal.example.com"}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones/test-zone/dns_records":
			_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"test-record","type":"A","name":"portal.example.com","content":"198.51.100.1"}]}`)
		case r.Method == http.MethodPut && r.URL.Path == "/client/v4/zones/test-zone/dns_records/test-record":
			updates.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":1000,"message":"DNS record update rejected"}]}`)
		default:
			t.Errorf("unexpected DNS API request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)

	// Keep both public-IP discovery and the provider API on the local TLS server.
	// Its certificate is test-only; no requests leave the loopback connection.
	client := utils.NewHTTPClient(
		utils.WithHTTPTLSConfig(&tls.Config{InsecureSkipVerify: true}),
		utils.WithHTTPDialContext(func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		}),
	)
	client.Transport.(*http.Transport).Proxy = nil
	t.Cleanup(client.CloseIdleConnections)
	originalClient := utils.DefaultHTTPClient
	utils.DefaultHTTPClient = client
	t.Cleanup(func() { utils.DefaultHTTPClient = originalClient })

	manager, err := NewManager(Config{
		BaseDomain:      "portal.example.com",
		KeyDir:          t.TempDir(),
		DNSProvider:     TypeCloudflare,
		CloudflareToken: "test-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Stop(context.Background()); err != nil {
			t.Errorf("Stop(): %v", err)
		}
	})
	certPEM, keyPEM, err := manager.EnsureTLSMaterial(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ensure dns records: ensure A record") || !strings.Contains(err.Error(), "DNS record update rejected") {
		t.Fatalf("EnsureTLSMaterial() error = %v, want fatal DNS record update failure", err)
	}
	if len(certPEM) != 0 || len(keyPEM) != 0 || updates.Load() != 1 {
		t.Fatalf("EnsureTLSMaterial() = %d certificate bytes, %d key bytes, %d DNS updates, want no certificate after one failed update", len(certPEM), len(keyPEM), updates.Load())
	}
}

func newEmbeddedDNSManager(t *testing.T, cfg Config) (*Manager, Config) {
	t.Helper()

	addressInUse := syscall.EADDRINUSE
	if runtime.GOOS == "windows" {
		// Winsock bind returns WSAEADDRINUSE, not syscall.EADDRINUSE.
		addressInUse = syscall.Errno(10048)
	}
	const attempts = 5
	var lastErr error
	for range attempts {
		listener, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatalf("allocate DNS probe port: %v", err)
		}
		cfg.EmbeddedDNSPort = listener.Addr().(*net.TCPAddr).Port
		if err := listener.Close(); err != nil {
			t.Fatalf("release DNS probe port: %v", err)
		}
		// Exercise the public configured-port path. Another listener can take
		// either protocol's port before NewManager binds it; retry only that race.
		manager, err := NewManager(cfg)
		if err == nil {
			t.Cleanup(func() {
				if err := manager.Stop(context.Background()); err != nil {
					t.Errorf("Stop(): %v", err)
				}
			})
			return manager, cfg
		}
		var bindErr *os.SyscallError
		if !errors.As(err, &bindErr) || bindErr.Syscall != "bind" || !errors.Is(bindErr, addressInUse) {
			t.Fatalf("NewManager(): %v", err)
		}
		lastErr = err
	}
	t.Fatalf("NewManager() could not bind a DNS port after %d attempts: %v", attempts, lastErr)
	return nil, cfg
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
