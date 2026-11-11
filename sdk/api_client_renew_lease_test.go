package sdk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestRenewLeaseChecksTheRelayCertificateHourly(t *testing.T) {
	fixture := newRenewLeaseHourlyFixture(t, "tenant.test.example")
	checkHourlyLeaseKeepsPinnedChain(t, fixture)
	checkHourlyLeaseRepinsAfterInterval(t, fixture)
	checkHourlyLeaseDefersRecheck(t, fixture)
}

type renewLeaseHourlyFixture struct {
	serving     *atomic.Pointer[tls.Certificate]
	listener    *listener
	tenantTLS   *keyless.Client
	firstPool   *x509.CertPool
	renewedPool *x509.CertPool
	renewed     tls.Certificate
	later       tls.Certificate
}

func newRenewLeaseHourlyFixture(t *testing.T, tenantHostname string) *renewLeaseHourlyFixture {
	t.Helper()
	first, firstPool := generateSelfSignedTenantCert(t, tenantHostname, 1)
	renewed, renewedPool := generateSelfSignedTenantCert(t, tenantHostname, 2)
	later, _ := generateSelfSignedTenantCert(t, tenantHostname, 3)
	serving := &atomic.Pointer[tls.Certificate]{}
	serving.Store(&first)
	expiresAt := time.Now().UTC().Add(time.Minute)
	relay, relayURL, parsedRelayURL := startLeaseRenewRelay(t, expiresAt, serving)
	t.Cleanup(relay.Close)
	tenantTLS, err := keyless.NewClient(t.Context(), keyless.ClientConfig{RelayURL: relayURL, Hostname: tenantHostname, AccessToken: "access-token"})
	if err != nil {
		t.Fatalf("keyless.NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = tenantTLS.Close() })
	if !tenantTLS.TenantCertPool().Equal(firstPool) {
		t.Fatal("the tenant did not pin the certificate the relay served")
	}
	listener := &listener{
		api: &apiClient{relayURL: parsedRelayURL, http: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}},
		lease: utils.NewSnapshot(listenerSnapshot{
			accessToken:    "access-token",
			expiresAt:      expiresAt,
			tenantTLS:      tenantTLS,
			chainCheckedAt: time.Now(),
		}),
	}
	return &renewLeaseHourlyFixture{serving: serving, listener: listener, tenantTLS: tenantTLS, firstPool: firstPool, renewedPool: renewedPool, renewed: renewed, later: later}
}

func renewHourlyLease(t *testing.T, fixture *renewLeaseHourlyFixture) {
	t.Helper()
	if err := fixture.listener.renewLease(context.Background()); err != nil {
		t.Fatalf("renewLease() error = %v", err)
	}
}

func checkHourlyLeaseKeepsPinnedChain(t *testing.T, fixture *renewLeaseHourlyFixture) {
	t.Helper()
	fixture.serving.Store(&fixture.renewed)
	renewHourlyLease(t, fixture)
	if !fixture.tenantTLS.TenantCertPool().Equal(fixture.firstPool) {
		t.Fatal("renewLease() checked the relay chain again within the hour after it was found current")
	}
}

func checkHourlyLeaseRepinsAfterInterval(t *testing.T, fixture *renewLeaseHourlyFixture) {
	t.Helper()
	fixture.listener.lease.Update(func(lease listenerSnapshot) listenerSnapshot {
		lease.chainCheckedAt = time.Now().Add(-defaultChainCheckInterval)
		return lease
	})
	renewHourlyLease(t, fixture)
	if !fixture.tenantTLS.TenantCertPool().Equal(fixture.renewedPool) {
		t.Fatal("renewLease() an hour after the last check left the tenant on the replaced relay certificate")
	}
}

func checkHourlyLeaseDefersRecheck(t *testing.T, fixture *renewLeaseHourlyFixture) {
	t.Helper()
	fixture.serving.Store(&fixture.later)
	renewHourlyLease(t, fixture)
	if !fixture.tenantTLS.TenantCertPool().Equal(fixture.renewedPool) {
		t.Fatal("renewLease() checked the relay chain again right after a scheduled check")
	}
}

func generateSelfSignedTenantCert(t *testing.T, tenantHostname string, serial int64) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		DNSNames:     []string{tenantHostname},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func startLeaseRenewRelay(t *testing.T, expiresAt time.Time, serving *atomic.Pointer[tls.Certificate]) (*httptest.Server, string, *url.URL) {
	t.Helper()
	var relayURL string
	relay := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.WriteAPIData(w, http.StatusOK, types.RenewResponse{
			AccessToken:     "renewed-token",
			ExpiresAt:       expiresAt,
			ReverseEndpoint: types.ReverseEndpoint{URL: relayURL + types.PathSDKConnect, Capability: "capability", ExpiresAt: expiresAt},
		})
	}))
	relay.Listener = tls.NewListener(relay.Listener, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return serving.Load(), nil },
		NextProtos:     []string{"http/1.1"},
	})
	relay.Start()
	relayURL = "https://" + relay.Listener.Addr().String()
	parsedRelayURL, err := url.Parse(relayURL)
	if err != nil {
		t.Fatal(err)
	}
	return relay, relayURL, parsedRelayURL
}

func TestRenewLeaseSaysItRepinsTheRelayChain(t *testing.T) {
	requests := make(chan types.RenewRequest, 1)
	expiresAt := time.Now().UTC().Add(time.Minute)
	server := startRenewLeaseRepinsChainServer(t, requests, expiresAt)
	defer server.Close()
	relayURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	listener := &listener{
		api:   &apiClient{relayURL: relayURL, http: server.Client()},
		lease: utils.NewSnapshot(listenerSnapshot{accessToken: "access-token", expiresAt: expiresAt}),
	}
	_ = listener.renewLease(context.Background())
	checkRenewLeaseRepinsChainRequest(t, <-requests)
}

func startRenewLeaseRepinsChainServer(t *testing.T, requests chan types.RenewRequest, expiresAt time.Time) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req types.RenewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode renew request: %v", err)
		}
		requests <- req
		utils.WriteAPIData(w, http.StatusOK, types.RenewResponse{
			AccessToken:     "renewed-token",
			ExpiresAt:       expiresAt,
			ReverseEndpoint: types.ReverseEndpoint{URL: "http://" + r.Host + types.PathSDKConnect, Capability: "capability", ExpiresAt: expiresAt},
		})
	}))
}

func checkRenewLeaseRepinsChainRequest(t *testing.T, req types.RenewRequest) {
	t.Helper()
	if !req.RepinsChain {
		t.Fatal("renew request does not say the SDK re-pins the relay chain")
	}
}
