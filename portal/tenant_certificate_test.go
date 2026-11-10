package portal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestTenantCertificateOwnershipTracksLiveLease(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	owner := newTestLeaseIdentity(t, "tenant")
	record, _, err := registry.Register(types.RegisterChallengeRequest{Identity: owner}, netip.MustParseAddr("203.0.113.1"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	names, err := registry.tenantCertificateNames(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != record.CanonicalHostname {
		t.Fatalf("issued names = %v", names)
	}
	registry.mu.Lock()
	record.ExpiresAt = time.Now().Add(-time.Second)
	registry.mu.Unlock()
	if _, err := registry.tenantCertificateNames(record); err == nil {
		t.Fatal("expired lease can issue")
	}
	replacement, _, err := registry.Register(types.RegisterChallengeRequest{Identity: owner}, netip.MustParseAddr("203.0.113.1"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.tenantCertificateNames(record); err == nil {
		t.Fatal("replaced lease can issue")
	}
	if _, err := registry.tenantCertificateNames(replacement); err != nil {
		t.Fatal(err)
	}
	registry.setIdentityAccess(owner.ServiceKey(), types.LeaseDenied, 2)
	if _, err := registry.tenantCertificateNames(replacement); err == nil {
		t.Fatal("denied identity can issue")
	}
}

func TestTenantCertificateEndpointRequiresOptInAndAuthentication(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	manager, err := acme.NewManager(acme.Config{BaseDomain: "localhost", KeyDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{registry: registry, acmeManager: manager, cfg: utils.NewSnapshot(ServerConfig{})}
	request := func(token, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, types.PathV1TenantCertificate, strings.NewReader(body))
		req.Header.Set(types.HeaderAccessToken, token)
		response := httptest.NewRecorder()
		server.HandleTenantCertificate(response, req)
		return response
	}
	if got := request("", "{}").Code; got != http.StatusServiceUnavailable {
		t.Fatalf("disabled status=%d", got)
	}
	server.cfg.Swap(ServerConfig{TenantCertificates: true})
	if got := request("", "{}").Code; got != http.StatusForbidden {
		t.Fatalf("unauthenticated status=%d", got)
	}
	_, registration, err := registry.Register(types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "tenant")}, netip.MustParseAddr("203.0.113.1"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := request(registration.AccessToken, "{}").Code; got != http.StatusBadRequest {
		t.Fatalf("invalid CSR status=%d", got)
	}
}

func TestTenantCertificateRejectsReassignableAlias(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	manager, err := acme.NewManager(acme.Config{BaseDomain: "localhost", KeyDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{registry: registry, acmeManager: manager, cfg: utils.NewSnapshot(ServerConfig{TenantCertificates: true})}
	_, registration, err := registry.Register(types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "alias")}, netip.MustParseAddr("203.0.113.1"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{registration.Hostname}}, key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(types.TenantCertificateRequest{CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, types.PathV1TenantCertificate, strings.NewReader(string(body)))
	req.Header.Set(types.HeaderAccessToken, registration.AccessToken)
	response := httptest.NewRecorder()
	server.HandleTenantCertificate(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("alias CSR status=%d body=%s", response.Code, response.Body.String())
	}
}
