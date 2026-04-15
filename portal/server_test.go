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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func tempIdentityPath(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func newTestClient(t *testing.T, cancel context.CancelFunc, server *Server) *http.Client {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
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

func TestNewServerInitializesRelaySetWhenDiscoveryEnabled(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:        "https://portal.example.com",
		IdentityPath:     tempIdentityPath(t),
		DiscoveryEnabled: true,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	if server.relaySet == nil {
		t.Fatal("relaySet = nil, want discovery relay set")
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
		t.Fatalf("GET /healthz error = %v", err)
	}
	defer healthResp.Body.Close()

	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want %d", healthResp.StatusCode, http.StatusOK)
	}

	var healthEnvelope types.APIEnvelope[map[string]string]
	if err := json.NewDecoder(healthResp.Body).Decode(&healthEnvelope); err != nil {
		t.Fatalf("decode /healthz response: %v", err)
	}
	if !healthEnvelope.OK || healthEnvelope.Data["status"] != "ok" {
		t.Fatalf("GET /healthz response = %+v, want ok status", healthEnvelope)
	}

	signResp, err := client.Get("https://" + utils.HostPortOrLoopback(server.apiListener.Addr().String()) + types.PathV1Sign)
	if err != nil {
		t.Fatalf("GET /v1/sign error = %v", err)
	}
	defer signResp.Body.Close()

	if signResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /v1/sign status = %d, want %d", signResp.StatusCode, http.StatusMethodNotAllowed)
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
}

func TestRegisterLeaseOmitsSNIPortWithoutUDP(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:    "https://portal.example.com:4017",
		IdentityPath: tempIdentityPath(t),
		SNIPort:      4443,
		MinPort:      40000,
		MaxPort:      40009,
		TCPEnabled:   true,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	resp, err := server.registerLease(types.RegisterChallengeRequest{
		Identity: types.Identity{
			Name:    "demo-tcp",
			Address: server.identity.Address,
		},
		TCPEnabled: true,
	}, "203.0.113.10", "")
	if err != nil {
		t.Fatalf("registerLease() error = %v", err)
	}
	t.Cleanup(func() {
		if record, err := server.registry.Find(resp.Identity); err == nil {
			record.Close()
		}
	})

	if resp.SNIPort != 0 {
		t.Fatalf("RegisterResponse.SNIPort = %d, want 0 without udp", resp.SNIPort)
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
		t.Fatalf("GET /healthz error = %v", err)
	}
	defer healthResp.Body.Close()

	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want %d", healthResp.StatusCode, http.StatusOK)
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

	resp, err := server.registerLease(types.RegisterChallengeRequest{
		Identity: types.Identity{
			Name:    "Demo-App",
			Address: server.identity.Address,
		},
	}, "203.0.113.10", "")
	if err != nil {
		t.Fatalf("registerLease() error = %v", err)
	}

	wantHostname := "demo-app.portal.example.com"
	if resp.Hostname != wantHostname {
		t.Fatalf("registerLease() hostname = %q, want %q", resp.Hostname, wantHostname)
	}

	record, err := server.registry.Find(resp.Identity)
	if err != nil {
		t.Fatalf("registry.Find() error = %v, want registered lease", err)
	}
	snapshot := server.registry.Snapshot(record)
	if snapshot.Name != "demo-app" {
		t.Fatalf("Snapshot().Name = %q, want %q", snapshot.Name, "demo-app")
	}
	if snapshot.Hostname != wantHostname {
		t.Fatalf("Snapshot().Hostname = %q, want %q", snapshot.Hostname, wantHostname)
	}
}

func TestRegisterLeaseBuildsUDPEnabledRuntime(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:    "https://portal.example.com",
		IdentityPath: tempIdentityPath(t),
		MinPort:      40000,
		MaxPort:      40009,
		UDPEnabled:   true,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	server.registry.policy.SetUDPPolicy(true, 0)

	resp, err := server.registerLease(types.RegisterChallengeRequest{
		Identity: types.Identity{
			Name:    "demo-udp",
			Address: server.identity.Address,
		},
		UDPEnabled: true,
	}, "203.0.113.10", "")
	if err != nil {
		t.Fatalf("registerLease() error = %v", err)
	}
	t.Cleanup(func() {
		if record, err := server.registry.Find(resp.Identity); err == nil {
			record.Close()
		}
	})

	record, err := server.registry.Find(resp.Identity)
	if err != nil {
		t.Fatalf("registry.Find() error = %v, want registered lease", err)
	}
	if record.stream == nil {
		t.Fatal("stream = nil, want stream runtime")
	}
	if record.datagram == nil {
		t.Fatal("datagram = nil, want datagram runtime")
	}
	if got := record.datagram.UDPPort(); got < 40000 || got > 40009 {
		t.Fatalf("UDPPort() = %d, want port within %d-%d", got, 40000, 40009)
	}
	if resp.SNIPort != server.cfg.SNIPort {
		t.Fatalf("RegisterResponse.SNIPort = %d, want %d", resp.SNIPort, server.cfg.SNIPort)
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
	if server.cfg.DiscoveryEnabled {
		t.Fatal("cfg.DiscoveryEnabled = true, want false without configured discovery service")
	}
}
