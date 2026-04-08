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
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func mustRelayDescriptor(t *testing.T, relayURL string) types.RelayDescriptor {
	t.Helper()

	now := time.Now().UTC()
	desc, err := discovery.NormalizeDescriptor(types.RelayDescriptor{
		Identity: types.Identity{
			Name: utils.PortalRootHost(relayURL),
		},
		RelayID:      relayURL,
		Sequence:     uint64(now.UnixMilli()),
		Version:      1,
		IssuedAt:     now,
		ExpiresAt:    now.Add(time.Hour),
		APIHTTPSAddr: relayURL,
	})
	if err != nil {
		t.Fatalf("NormalizeDescriptor() error = %v", err)
	}
	return desc
}

func tempIdentityPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "relay_identity.json")
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
		MaxRouting:       types.MinDiscoveryRoutingAttempts,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	if server.discoveryMgr == nil {
		t.Fatal("discoveryMgr = nil, want discovery manager")
	}
}

func TestNewServerRejectsOverlayMaxHopsOutOfRange(t *testing.T) {
	t.Parallel()

	_, err := NewServer(ServerConfig{
		PortalURL:      "https://portal.example.com",
		IdentityPath:   tempIdentityPath(t),
		OverlayEnabled: true,
		OverlayMaxHops: 11,
	})
	if err == nil || !strings.Contains(err.Error(), "overlay max hops") {
		t.Fatalf("NewServer() error = %v, want overlay max hops range error", err)
	}
}

func TestRelayDiscoveryReportsOverlaySupportWhenEnabled(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:        "https://localhost:4017",
		IdentityPath:     tempIdentityPath(t),
		ACME:             acme.Config{KeyDir: t.TempDir()},
		APIListenAddr:    "127.0.0.1:0",
		SNIListenAddr:    "127.0.0.1:0",
		DiscoveryEnabled: true,
		MaxRouting:       types.MinDiscoveryRoutingAttempts,
		OverlayEnabled:   true,
		OverlayMaxHops:   3,
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
		t.Fatalf("GET /discovery error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /discovery status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var discoveryResp types.DiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&discoveryResp); err != nil {
		t.Fatalf("decode /discovery response: %v", err)
	}
	if !discoveryResp.Self.SupportsOverlayPeer {
		t.Fatalf("SupportsOverlayPeer = false, want true")
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

	var healthPayload map[string]string
	if err := json.NewDecoder(healthResp.Body).Decode(&healthPayload); err != nil {
		t.Fatalf("decode /healthz response: %v", err)
	}
	if healthPayload["status"] != "ok" {
		t.Fatalf("GET /healthz response = %+v, want status=ok", healthPayload)
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

	var domainResp types.DomainResponse
	if err := json.Unmarshal(body, &domainResp); err != nil {
		t.Fatalf("decode /sdk/domain response: %v", err)
	}
	if domainResp.ProtocolVersion != types.ProtocolVersion {
		t.Fatalf("DomainResponse.ProtocolVersion = %q, want %q", domainResp.ProtocolVersion, types.ProtocolVersion)
	}
	if domainResp.ReleaseVersion != types.ReleaseVersion {
		t.Fatalf("DomainResponse.ReleaseVersion = %q, want %q", domainResp.ReleaseVersion, types.ReleaseVersion)
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

func TestServerStartDiscoveryIncludesIdentityAndOmitsSignerFields(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:        "https://localhost:4017",
		IdentityPath:     tempIdentityPath(t),
		ACME:             acme.Config{KeyDir: t.TempDir()},
		APIListenAddr:    "127.0.0.1:0",
		SNIListenAddr:    "127.0.0.1:0",
		DiscoveryEnabled: true,
		MaxRouting:       types.MinDiscoveryRoutingAttempts,
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
		t.Fatalf("GET /discovery error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /discovery status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /discovery response: %v", err)
	}
	bodyText := string(body)
	for _, key := range []string{"\"address\"", "\"name\"", "\"relay_id\"", "\"owner_address\"", "\"signer_public_key\""} {
		if !strings.Contains(bodyText, key) {
			t.Fatalf("/discovery body = %q, want %q present", bodyText, key)
		}
	}
	if strings.Contains(bodyText, "descriptor_signature") {
		t.Fatalf("/discovery body = %q, want descriptor_signature omitted", bodyText)
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

func TestServerSetBootstrapRelayURLsAllowsLoopbackButSkipsSelfRelay(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:        "https://relay-a.example.com",
		IdentityPath:     tempIdentityPath(t),
		Bootstraps:       []string{"https://bootstrap.example.com"},
		DiscoveryEnabled: true,
		MaxRouting:       types.MinDiscoveryRoutingAttempts,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	server.discoveryMgr.SetBootstrapRelayURLs([]string{
		"https://bootstrap.example.com",
		"https://localhost:4017",
		"https://relay-a.example.com",
		"https://relay-b.example.com",
	})
	advertisedDescriptors := server.discoveryMgr.ActiveRelayDescriptors()
	knownURLs := append([]string(nil), server.discoveryMgr.ActiveRelayURLs()...)
	sort.Strings(knownURLs)
	if !reflect.DeepEqual(knownURLs, []string{
		"https://bootstrap.example.com",
		"https://localhost:4017",
		"https://relay-b.example.com",
	}) {
		t.Fatalf("ActiveRelayURLs() = %v, want loopback kept and self filtered", knownURLs)
	}
	if len(advertisedDescriptors) != 0 {
		t.Fatalf("advertised count = %d, want 0 before direct confirmation", len(advertisedDescriptors))
	}
}

func TestServerDiscoverySkipsSelfRelayHint(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:        "https://portal.example.com",
		IdentityPath:     tempIdentityPath(t),
		Bootstraps:       []string{"https://bootstrap.example.com"},
		DiscoveryEnabled: true,
		MaxRouting:       types.MinDiscoveryRoutingAttempts,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	now := time.Now().UTC()
	bootstrapDesc := mustRelayDescriptor(t, "https://bootstrap.example.com")
	selfHint, err := discovery.NormalizeDescriptor(types.RelayDescriptor{
		Identity:     server.identity.Copy(),
		RelayID:      "https://self-mirror.example.com",
		Sequence:     uint64(now.UnixMilli()),
		Version:      1,
		IssuedAt:     now,
		ExpiresAt:    now.Add(time.Hour),
		APIHTTPSAddr: "https://self-mirror.example.com",
	})
	if err != nil {
		t.Fatalf("NormalizeDescriptor() self hint error = %v", err)
	}

	if err := server.discoveryMgr.ApplyRelayDiscoveryResponse(
		bootstrapDesc.Identity,
		bootstrapDesc.APIHTTPSAddr,
		types.DiscoveryResponse{ProtocolVersion: types.ProtocolVersion, Self: bootstrapDesc, Relays: []types.RelayDescriptor{selfHint}},
		now,
	); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
	}

	knownURLs := append([]string(nil), server.discoveryMgr.ActiveRelayURLs()...)
	sort.Strings(knownURLs)
	if !reflect.DeepEqual(knownURLs, []string{"https://bootstrap.example.com"}) {
		t.Fatalf("ActiveRelayURLs() = %v, want self hint excluded", knownURLs)
	}
}

func TestServerRecordVerifiedDiscoveryPeerRequiresDirectConfirmation(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:        "https://portal.example.com",
		IdentityPath:     tempIdentityPath(t),
		Bootstraps:       []string{"https://bootstrap.example.com"},
		DiscoveryEnabled: true,
		MaxRouting:       types.MinDiscoveryRoutingAttempts,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	bootstrapDesc := mustRelayDescriptor(t, "https://bootstrap.example.com")
	relayADesc := mustRelayDescriptor(t, "https://relay-a.example.com")

	applyDiscovery := func(targetIdentity types.Identity, targetURL string, resp types.DiscoveryResponse) error {
		now := time.Now().UTC()
		return server.discoveryMgr.ApplyRelayDiscoveryResponse(targetIdentity, targetURL, resp, now)
	}

	err = applyDiscovery(
		bootstrapDesc.Identity,
		bootstrapDesc.APIHTTPSAddr,
		types.DiscoveryResponse{ProtocolVersion: types.ProtocolVersion, Self: bootstrapDesc},
	)
	if err != nil {
		t.Fatalf("applyRelayDiscoveryResponse() bootstrap error = %v", err)
	}

	err = applyDiscovery(
		bootstrapDesc.Identity,
		bootstrapDesc.APIHTTPSAddr,
		types.DiscoveryResponse{ProtocolVersion: types.ProtocolVersion, Self: bootstrapDesc, Relays: []types.RelayDescriptor{relayADesc}},
	)
	if err != nil {
		t.Fatalf("applyRelayDiscoveryResponse() hinted error = %v", err)
	}
	knownURLs := append([]string(nil), server.discoveryMgr.ActiveRelayURLs()...)
	sort.Strings(knownURLs)
	if !reflect.DeepEqual(knownURLs, []string{"https://bootstrap.example.com"}) {
		t.Fatalf("ActiveRelayURLs() = %v, want [%q]", knownURLs, "https://bootstrap.example.com")
	}
	advertisedDescriptors := server.discoveryMgr.ActiveRelayDescriptors()
	advertisedURLs := make([]string, 0, len(advertisedDescriptors))
	for _, descriptor := range advertisedDescriptors {
		if strings.TrimSpace(descriptor.APIHTTPSAddr) == "" {
			continue
		}
		advertisedURLs = append(advertisedURLs, descriptor.APIHTTPSAddr)
	}
	sort.Strings(advertisedURLs)
	if !reflect.DeepEqual(advertisedURLs, []string{"https://bootstrap.example.com"}) {
		t.Fatalf("ActiveRelayDescriptors() = %v, want [%q]", advertisedURLs, "https://bootstrap.example.com")
	}

	err = applyDiscovery(
		relayADesc.Identity,
		relayADesc.APIHTTPSAddr,
		types.DiscoveryResponse{ProtocolVersion: types.ProtocolVersion, Self: relayADesc},
	)
	if err != nil {
		t.Fatalf("applyRelayDiscoveryResponse() confirm error = %v", err)
	}
	advertisedDescriptors = server.discoveryMgr.ActiveRelayDescriptors()
	advertisedURLs = advertisedURLs[:0]
	for _, descriptor := range advertisedDescriptors {
		if strings.TrimSpace(descriptor.APIHTTPSAddr) == "" {
			continue
		}
		advertisedURLs = append(advertisedURLs, descriptor.APIHTTPSAddr)
	}
	sort.Strings(advertisedURLs)
	if !reflect.DeepEqual(advertisedURLs, []string{"https://bootstrap.example.com", "https://relay-a.example.com"}) {
		t.Fatalf("ActiveRelayDescriptors() = %v, want [%q %q]", advertisedURLs, "https://bootstrap.example.com", "https://relay-a.example.com")
	}
}

func TestServerRecordVerifiedDiscoveryPeerExpiresAfterRepeatedDirectFailures(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:        "https://portal.example.com",
		IdentityPath:     tempIdentityPath(t),
		Bootstraps:       []string{"https://bootstrap.example.com"},
		DiscoveryEnabled: true,
		MaxRouting:       types.MinDiscoveryRoutingAttempts,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	bootstrapDesc := mustRelayDescriptor(t, "https://bootstrap.example.com")
	relayADesc := mustRelayDescriptor(t, "https://relay-a.example.com")
	now := time.Now().UTC()

	if err := server.discoveryMgr.ApplyRelayDiscoveryResponse(
		bootstrapDesc.Identity,
		bootstrapDesc.APIHTTPSAddr,
		types.DiscoveryResponse{ProtocolVersion: types.ProtocolVersion, Self: bootstrapDesc, Relays: []types.RelayDescriptor{relayADesc}},
		now,
	); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() bootstrap error = %v", err)
	}
	if err := server.discoveryMgr.ApplyRelayDiscoveryResponse(
		relayADesc.Identity,
		relayADesc.APIHTTPSAddr,
		types.DiscoveryResponse{ProtocolVersion: types.ProtocolVersion, Self: relayADesc},
		now.Add(time.Second),
	); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() direct confirm error = %v", err)
	}

	for attempt := 1; attempt <= 3; attempt++ {
		expired, _, consecutiveFailures := server.discoveryMgr.RecordDiscoveryFailure(
			relayADesc.Identity,
			relayADesc.APIHTTPSAddr,
			errors.New("direct discovery failed"),
		)
		if consecutiveFailures != attempt {
			t.Fatalf("RecordDiscoveryFailure() consecutive = %d, want %d", consecutiveFailures, attempt)
		}
		if attempt < 3 && expired {
			t.Fatalf("RecordDiscoveryFailure() expired early on attempt %d", attempt)
		}
		if attempt == 3 && !expired {
			t.Fatalf("RecordDiscoveryFailure() expired = false on attempt %d, want true", attempt)
		}
	}

	advertisedDescriptors := server.discoveryMgr.ActiveRelayDescriptors()
	advertisedURLs := make([]string, 0, len(advertisedDescriptors))
	for _, descriptor := range advertisedDescriptors {
		if strings.TrimSpace(descriptor.APIHTTPSAddr) == "" {
			continue
		}
		advertisedURLs = append(advertisedURLs, descriptor.APIHTTPSAddr)
	}
	sort.Strings(advertisedURLs)
	if !reflect.DeepEqual(advertisedURLs, []string{"https://bootstrap.example.com"}) {
		t.Fatalf("ActiveRelayDescriptors() = %v, want [%q] after relay expiry", advertisedURLs, "https://bootstrap.example.com")
	}
}

func TestServerBootstrapHintDoesNotResetDirectFailureBudget(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:        "https://portal.example.com",
		IdentityPath:     tempIdentityPath(t),
		Bootstraps:       []string{"https://bootstrap.example.com"},
		DiscoveryEnabled: true,
		MaxRouting:       types.MinDiscoveryRoutingAttempts,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	bootstrapDesc := mustRelayDescriptor(t, "https://bootstrap.example.com")
	relayADesc := mustRelayDescriptor(t, "https://relay-a.example.com")
	now := time.Now().UTC()

	if err := server.discoveryMgr.ApplyRelayDiscoveryResponse(
		bootstrapDesc.Identity,
		bootstrapDesc.APIHTTPSAddr,
		types.DiscoveryResponse{ProtocolVersion: types.ProtocolVersion, Self: bootstrapDesc, Relays: []types.RelayDescriptor{relayADesc}},
		now,
	); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() bootstrap error = %v", err)
	}
	if err := server.discoveryMgr.ApplyRelayDiscoveryResponse(
		relayADesc.Identity,
		relayADesc.APIHTTPSAddr,
		types.DiscoveryResponse{ProtocolVersion: types.ProtocolVersion, Self: relayADesc},
		now.Add(time.Second),
	); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() direct confirm error = %v", err)
	}

	for attempt := 1; attempt <= 2; attempt++ {
		expired, _, consecutiveFailures := server.discoveryMgr.RecordDiscoveryFailure(
			relayADesc.Identity,
			relayADesc.APIHTTPSAddr,
			errors.New("direct discovery failed"),
		)
		if expired {
			t.Fatalf("RecordDiscoveryFailure() expired early on attempt %d", attempt)
		}
		if consecutiveFailures != attempt {
			t.Fatalf("RecordDiscoveryFailure() consecutive = %d, want %d", consecutiveFailures, attempt)
		}

		if err := server.discoveryMgr.ApplyRelayDiscoveryResponse(
			bootstrapDesc.Identity,
			bootstrapDesc.APIHTTPSAddr,
			types.DiscoveryResponse{ProtocolVersion: types.ProtocolVersion, Self: bootstrapDesc, Relays: []types.RelayDescriptor{relayADesc}},
			now.Add(time.Duration(attempt+1)*time.Second),
		); err != nil {
			t.Fatalf("ApplyRelayDiscoveryResponse() hinted refresh error = %v", err)
		}

		advertisedDescriptors := server.discoveryMgr.ActiveRelayDescriptors()
		advertisedURLs := make([]string, 0, len(advertisedDescriptors))
		for _, descriptor := range advertisedDescriptors {
			if strings.TrimSpace(descriptor.APIHTTPSAddr) == "" {
				continue
			}
			advertisedURLs = append(advertisedURLs, descriptor.APIHTTPSAddr)
		}
		sort.Strings(advertisedURLs)
		if !reflect.DeepEqual(advertisedURLs, []string{"https://bootstrap.example.com", "https://relay-a.example.com"}) {
			t.Fatalf("ActiveRelayDescriptors() = %v, want relay to remain advertised before expiry", advertisedURLs)
		}
	}

	expired, _, consecutiveFailures := server.discoveryMgr.RecordDiscoveryFailure(
		relayADesc.Identity,
		relayADesc.APIHTTPSAddr,
		errors.New("direct discovery failed"),
	)
	if !expired {
		t.Fatal("RecordDiscoveryFailure() expired = false on final attempt, want true")
	}
	if consecutiveFailures != 3 {
		t.Fatalf("RecordDiscoveryFailure() consecutive = %d, want 3", consecutiveFailures)
	}
}

func TestServerExpiredDiscoveryPeerNeedsFreshDirectConfirmation(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:        "https://portal.example.com",
		IdentityPath:     tempIdentityPath(t),
		Bootstraps:       []string{"https://bootstrap.example.com"},
		DiscoveryEnabled: true,
		MaxRouting:       types.MinDiscoveryRoutingAttempts,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	bootstrapDesc := mustRelayDescriptor(t, "https://bootstrap.example.com")
	relayADesc := mustRelayDescriptor(t, "https://relay-a.example.com")
	now := time.Now().UTC()

	if err := server.discoveryMgr.ApplyRelayDiscoveryResponse(
		bootstrapDesc.Identity,
		bootstrapDesc.APIHTTPSAddr,
		types.DiscoveryResponse{ProtocolVersion: types.ProtocolVersion, Self: bootstrapDesc, Relays: []types.RelayDescriptor{relayADesc}},
		now,
	); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() bootstrap error = %v", err)
	}
	if err := server.discoveryMgr.ApplyRelayDiscoveryResponse(
		relayADesc.Identity,
		relayADesc.APIHTTPSAddr,
		types.DiscoveryResponse{ProtocolVersion: types.ProtocolVersion, Self: relayADesc},
		now.Add(time.Second),
	); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() direct confirm error = %v", err)
	}

	for attempt := 1; attempt <= 3; attempt++ {
		server.discoveryMgr.RecordDiscoveryFailure(
			relayADesc.Identity,
			relayADesc.APIHTTPSAddr,
			errors.New("direct discovery failed"),
		)
	}

	if err := server.discoveryMgr.ApplyRelayDiscoveryResponse(
		bootstrapDesc.Identity,
		bootstrapDesc.APIHTTPSAddr,
		types.DiscoveryResponse{ProtocolVersion: types.ProtocolVersion, Self: bootstrapDesc, Relays: []types.RelayDescriptor{relayADesc}},
		now.Add(5*time.Second),
	); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() fresh bootstrap error = %v", err)
	}

	advertisedDescriptors := server.discoveryMgr.ActiveRelayDescriptors()
	advertisedURLs := make([]string, 0, len(advertisedDescriptors))
	for _, descriptor := range advertisedDescriptors {
		if strings.TrimSpace(descriptor.APIHTTPSAddr) == "" {
			continue
		}
		advertisedURLs = append(advertisedURLs, descriptor.APIHTTPSAddr)
	}
	sort.Strings(advertisedURLs)
	if !reflect.DeepEqual(advertisedURLs, []string{"https://bootstrap.example.com"}) {
		t.Fatalf("ActiveRelayDescriptors() = %v, want relay to stay hidden until reconfirmed", advertisedURLs)
	}

	if err := server.discoveryMgr.ApplyRelayDiscoveryResponse(
		relayADesc.Identity,
		relayADesc.APIHTTPSAddr,
		types.DiscoveryResponse{ProtocolVersion: types.ProtocolVersion, Self: relayADesc},
		now.Add(6*time.Second),
	); err != nil {
		t.Fatalf("ApplyRelayDiscoveryResponse() reconfirm error = %v", err)
	}

	advertisedDescriptors = server.discoveryMgr.ActiveRelayDescriptors()
	advertisedURLs = advertisedURLs[:0]
	for _, descriptor := range advertisedDescriptors {
		if strings.TrimSpace(descriptor.APIHTTPSAddr) == "" {
			continue
		}
		advertisedURLs = append(advertisedURLs, descriptor.APIHTTPSAddr)
	}
	sort.Strings(advertisedURLs)
	if !reflect.DeepEqual(advertisedURLs, []string{"https://bootstrap.example.com", "https://relay-a.example.com"}) {
		t.Fatalf("ActiveRelayDescriptors() = %v, want relay restored after direct confirmation", advertisedURLs)
	}
}

func TestNewServerFiltersSelfBootstrapURLFromConfig(t *testing.T) {
	t.Parallel()

	server, err := NewServer(ServerConfig{
		PortalURL:        "https://portal.example.com",
		IdentityPath:     tempIdentityPath(t),
		Bootstraps:       []string{"https://bootstrap.example.com", "https://portal.example.com", "https://localhost:4017"},
		DiscoveryEnabled: true,
		MaxRouting:       types.MinDiscoveryRoutingAttempts,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if !reflect.DeepEqual(server.cfg.Bootstraps, []string{"https://bootstrap.example.com", "https://localhost:4017"}) {
		t.Fatalf("cfg.Bootstraps = %v, want self bootstrap filtered and loopback kept", server.cfg.Bootstraps)
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
