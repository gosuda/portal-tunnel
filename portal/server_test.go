package portal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	testLeasePortsMu sync.Mutex
	testLeasePorts   = make(map[int]struct{})
)

func tempIdentityPath(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func tempLeasePort(t *testing.T) int {
	t.Helper()

	for attempt := 0; attempt < 100; attempt++ {
		probe, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("allocate probe port: %v", err)
		}
		_, portText, err := net.SplitHostPort(probe.Addr().String())
		if closeErr := probe.Close(); closeErr != nil {
			t.Fatalf("close probe port: %v", closeErr)
		}
		if err != nil {
			t.Fatalf("parse probe port: %v", err)
		}
		start, err := strconv.Atoi(portText)
		if err != nil {
			t.Fatalf("parse probe port %q: %v", portText, err)
		}
		if start <= 0 || start > 65535 {
			continue
		}
		if !reserveTestLeasePort(start) {
			continue
		}
		if tempLeasePortAvailable(start) {
			return start
		}
		releaseTestLeasePort(start)
	}
	t.Fatalf("could not find a free lease port")
	return 0
}

func reserveTestLeasePort(port int) bool {
	testLeasePortsMu.Lock()
	defer testLeasePortsMu.Unlock()

	if _, exists := testLeasePorts[port]; exists {
		return false
	}
	testLeasePorts[port] = struct{}{}
	return true
}

func releaseTestLeasePort(port int) {
	testLeasePortsMu.Lock()
	defer testLeasePortsMu.Unlock()

	delete(testLeasePorts, port)
}

func tempLeasePortAvailable(port int) bool {
	addr := ":" + strconv.Itoa(port)
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	defer tcpListener.Close()

	udpListener, err := net.ListenPacket("udp", addr)
	if err != nil {
		return false
	}
	defer udpListener.Close()

	return true
}

func newTestClient(t *testing.T, cancel context.CancelFunc, server *Server) *http.Client {
	t.Helper()
	client := utils.NewHTTPClient(
		utils.WithHTTPTLSConfig(&tls.Config{InsecureSkipVerify: true}),
	)
	t.Cleanup(func() {
		client.CloseIdleConnections()
		cancel()
		if err := server.Wait(); err != nil {
			t.Fatalf("Wait() error = %v", err)
		}
	})
	return client
}

func writeManualRelayCertificate(t *testing.T, keyDir, baseDomain string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
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
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(filepath.Join(keyDir, "fullchain.pem"), certPEM, 0o644); err != nil {
		t.Fatalf("WriteFile(cert) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "privatekey.pem"), keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}
}

func TestRelayDiscoveryEnabledServesDiscoveryEnvelope(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:        "https://portal.example.com",
		IdentityPath:     tempIdentityPath(t),
		DiscoveryEnabled: true,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, types.PathDiscovery, nil)
	rec := httptest.NewRecorder()
	server.handleRelayDiscovery(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET relay discovery status = %d, want %d", rec.Code, http.StatusOK)
	}
	var envelope types.APIEnvelope[types.DiscoveryResponse]
	if err := json.NewDecoder(rec.Body).Decode(&envelope); err != nil {
		t.Fatalf("json.Decode() error = %v", err)
	}
	if !envelope.OK || envelope.Data.ProtocolVersion != types.DiscoveryVersion {
		t.Fatalf("discovery envelope = %+v, want ok discovery response", envelope)
	}
}

func TestServerStartInitializesLocalACMEAndSigner(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:     "https://localhost:4017",
		IdentityPath:  tempIdentityPath(t),
		ACME:          acme.Config{KeyDir: t.TempDir()},
		APIListenAddr: "127.0.0.1:0",
		SNIListenAddr: "127.0.0.1:0",
		MinPort:       40000,
		MaxPort:       40000,
		UDPEnabled:    true,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := server.Start(ctx, nil); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	client := newTestClient(t, cancel, server)

	healthResp, err := client.Get("https://" + utils.HostPortOrLoopback(server.apiListener.Addr().String()) + types.PathHealthz)
	if err != nil {
		t.Fatalf("GET /api/healthz error = %v", err)
	}
	defer healthResp.Body.Close()

	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/healthz status = %d, want %d", healthResp.StatusCode, http.StatusOK)
	}

	var healthEnvelope types.APIEnvelope[map[string]string]
	if err := json.NewDecoder(healthResp.Body).Decode(&healthEnvelope); err != nil {
		t.Fatalf("decode /api/healthz response: %v", err)
	}
	if !healthEnvelope.OK || healthEnvelope.Data["status"] != "ok" {
		t.Fatalf("GET /api/healthz response = %+v, want ok status", healthEnvelope)
	}

	signResp, err := client.Get("https://" + utils.HostPortOrLoopback(server.apiListener.Addr().String()) + types.PathV1Sign)
	if err != nil {
		t.Fatalf("GET /v1/sign error = %v", err)
	}
	defer signResp.Body.Close()

	if signResp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /v1/sign status = %d, want %d", signResp.StatusCode, http.StatusForbidden)
	}
}

func TestServerStartEnablesPProfOnSeparateHTTPListener(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:       "https://localhost:4017",
		IdentityPath:    tempIdentityPath(t),
		ACME:            acme.Config{KeyDir: t.TempDir()},
		APIListenAddr:   "127.0.0.1:0",
		SNIListenAddr:   "127.0.0.1:0",
		PProfEnabled:    true,
		PProfListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := server.Start(ctx, nil); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	client := newTestClient(t, cancel, server)
	if server.pprofListener == nil {
		t.Fatal("pprofListener = nil, want listener")
	}

	resp, err := client.Get("http://" + utils.HostPortOrLoopback(server.pprofListener.Addr().String()) + "/debug/pprof/")
	if err != nil {
		t.Fatalf("GET /debug/pprof/ error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /debug/pprof/ status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestServerStartDomainReportsCompatibilityInfo(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:     "https://localhost:4017",
		IdentityPath:  tempIdentityPath(t),
		ACME:          acme.Config{KeyDir: t.TempDir()},
		SNIPort:       4443,
		APIListenAddr: "127.0.0.1:0",
		SNIListenAddr: "127.0.0.1:0",
		X402Enabled:   true,
		X402Network:   " sui:testnet ",
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := server.Start(ctx, nil); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	client := newTestClient(t, cancel, server)

	resp, err := client.Get("https://" + utils.HostPortOrLoopback(server.apiListener.Addr().String()) + types.PathSDKDomain)
	if err != nil {
		t.Fatalf("GET /sdk/domain error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /sdk/domain status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /sdk/domain response: %v", err)
	}

	var envelope types.APIEnvelope[types.DomainResponse]
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode /sdk/domain response: %v", err)
	}
	if !envelope.OK {
		t.Fatalf("GET /sdk/domain response = %+v, want ok=true", envelope)
	}
	if envelope.Data.ProtocolVersion != types.SDKVersion {
		t.Fatalf("DomainResponse.ProtocolVersion = %q, want %q", envelope.Data.ProtocolVersion, types.SDKVersion)
	}
	if envelope.Data.ReleaseVersion != types.ReleaseVersion {
		t.Fatalf("DomainResponse.ReleaseVersion = %q, want %q", envelope.Data.ReleaseVersion, types.ReleaseVersion)
	}
	if !envelope.Data.X402.Enabled {
		t.Fatal("DomainResponse.X402.Enabled = false, want true")
	}
	if envelope.Data.X402.Network != "sui:testnet" {
		t.Fatalf("DomainResponse.X402.Network = %q, want sui:testnet", envelope.Data.X402.Network)
	}
	if envelope.Data.X402.NetworkName != "Sui Testnet" {
		t.Fatalf("DomainResponse.X402.NetworkName = %q, want Sui Testnet", envelope.Data.X402.NetworkName)
	}
	if envelope.Data.X402.URL != "https://localhost:4017/api/x402" {
		t.Fatalf("DomainResponse.X402.URL = %q, want https://localhost:4017/api/x402", envelope.Data.X402.URL)
	}
	if envelope.Data.X402.SupportedURL != "https://localhost:4017/api/x402/supported" {
		t.Fatalf("DomainResponse.X402.SupportedURL = %q, want https://localhost:4017/api/x402/supported", envelope.Data.X402.SupportedURL)
	}
}

func TestRegisterLeaseIncludesSNIPortForPublicIngress(t *testing.T) {
	t.Parallel()

	port := tempLeasePort(t)
	server, err := NewServer(ServerConfig{
		PortalURL:    "https://portal.example.com:4017",
		IdentityPath: tempIdentityPath(t),
		SNIPort:      4443,
		MinPort:      port,
		MaxPort:      port,
		TCPEnabled:   true,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	record, resp, err := server.registry.Register(types.RegisterChallengeRequest{
		Identity: types.Identity{
			Name:    "demo-tcp",
			Address: server.identity.Address,
		},
		TCPEnabled: true,
	}, "203.0.113.10", "")
	if err != nil {
		t.Fatalf("registry.Register() error = %v", err)
	}
	t.Cleanup(func() {
		record.Close()
	})

	if resp.SNIPort != server.config().SNIPort {
		t.Fatalf("RegisterResponse.SNIPort = %d, want %d", resp.SNIPort, server.config().SNIPort)
	}
}

func TestServerStartUsesManualCertificateWithoutACMEProvider(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()
	writeManualRelayCertificate(t, keyDir, "portal.example.com")

	server, err := NewServer(ServerConfig{
		PortalURL:     "https://portal.example.com",
		IdentityPath:  tempIdentityPath(t),
		ACME:          acme.Config{KeyDir: keyDir},
		APIListenAddr: "127.0.0.1:0",
		SNIListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := server.Start(ctx, nil); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	client := newTestClient(t, cancel, server)

	healthResp, err := client.Get("https://" + utils.HostPortOrLoopback(server.apiListener.Addr().String()) + types.PathHealthz)
	if err != nil {
		t.Fatalf("GET /api/healthz error = %v", err)
	}
	defer healthResp.Body.Close()

	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/healthz status = %d, want %d", healthResp.StatusCode, http.StatusOK)
	}
}

func TestServerStartRejectsMismatchedACMEBaseDomain(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:     "https://portal.example.com",
		IdentityPath:  tempIdentityPath(t),
		ACME:          acme.Config{BaseDomain: "other.example.com", KeyDir: t.TempDir()},
		APIListenAddr: "127.0.0.1:0",
		SNIListenAddr: "127.0.0.1:0",
		MinPort:       40000,
		MaxPort:       40000,
		UDPEnabled:    true,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	err = server.Start(context.Background(), nil)
	if err == nil {
		t.Fatal("Start() error = nil, want mismatch error")
	}
	if !strings.Contains(err.Error(), "does not match portal root host") {
		t.Fatalf("Start() error = %v, want base domain mismatch", err)
	}
}

func TestRegisterLeaseDerivesFixedHostnameFromName(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:    "https://portal.example.com",
		IdentityPath: tempIdentityPath(t),
		MinPort:      40000,
		MaxPort:      40000,
		UDPEnabled:   true,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	record, _, err := server.registry.Register(types.RegisterChallengeRequest{
		Identity: types.Identity{
			Name:    "Demo-App",
			Address: server.identity.Address,
		},
	}, "203.0.113.10", "")
	if err != nil {
		t.Fatalf("registry.Register() error = %v", err)
	}

	wantHostname := "demo-app.portal.example.com"
	if record.Hostname != wantHostname {
		t.Fatalf("registry.Register() route hostname = %q, want %q", record.Hostname, wantHostname)
	}

	lease := server.registry.publicLease(record)
	if lease.Name != "demo-app" {
		t.Fatalf("publicLease().Name = %q, want %q", lease.Name, "demo-app")
	}
	if lease.Hostname != wantHostname {
		t.Fatalf("publicLease().Hostname = %q, want %q", lease.Hostname, wantHostname)
	}
}

func TestRegisterLeaseBuildsUDPEnabledRuntime(t *testing.T) {
	t.Parallel()

	port := tempLeasePort(t)
	server, err := NewServer(ServerConfig{
		PortalURL:    "https://portal.example.com",
		IdentityPath: tempIdentityPath(t),
		MinPort:      port,
		MaxPort:      port,
		UDPEnabled:   true,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	server.SetUDPPolicy(true, 0)

	record, resp, err := server.registry.Register(types.RegisterChallengeRequest{
		Identity: types.Identity{
			Name:    "demo-udp",
			Address: server.identity.Address,
		},
		UDPEnabled: true,
	}, "203.0.113.10", "")
	if err != nil {
		t.Fatalf("registry.Register() error = %v", err)
	}
	t.Cleanup(func() {
		record.Close()
	})

	if record.stream == nil {
		t.Fatal("stream = nil, want stream runtime")
	}
	if record.datagram == nil {
		t.Fatal("datagram = nil, want datagram runtime")
	}
	if got := record.datagram.UDPPort(); got != port {
		t.Fatalf("UDPPort() = %d, want %d", got, port)
	}
	if resp.SNIPort != server.config().SNIPort {
		t.Fatalf("RegisterResponse.SNIPort = %d, want %d", resp.SNIPort, server.config().SNIPort)
	}
	if resp.UDPAddr == "" {
		t.Fatal("RegisterResponse.UDPAddr = empty, want public udp address")
	}
}

func TestServerStartHidesDiscoveryRoutesWhenDisabled(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:     "https://localhost:4017",
		IdentityPath:  tempIdentityPath(t),
		ACME:          acme.Config{KeyDir: t.TempDir()},
		APIListenAddr: "127.0.0.1:0",
		SNIListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := server.Start(ctx, nil); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	client := newTestClient(t, cancel, server)

	resp, err := client.Get("https://" + utils.HostPortOrLoopback(server.apiListener.Addr().String()) + types.PathDiscovery)
	if err != nil {
		t.Fatalf("GET relay discovery error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET relay discovery status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	if server.config().DiscoveryEnabled {
		t.Fatal("cfg.DiscoveryEnabled = true, want false without configured discovery service")
	}
}
