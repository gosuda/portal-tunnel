package localtls

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestAutomaticCertificateState(t *testing.T) {
	const hostname = "tenant.test.example"
	dir := t.TempDir()
	client := &automaticSource{hostname: hostname, relayURL: "https://127.0.0.1:1", headers: func() http.Header { return http.Header{} }, certificateDir: dir}
	// Failed initial issuance keeps its generated key for the next attempt.
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := client.acquire(ctx); err == nil {
		t.Fatal("unreachable issuer succeeded")
	}
	pending, err := client.readBundle()
	if err != nil {
		t.Fatal(err)
	}
	if pending.CertificatePEM != "" || pending.KeyPEM == "" {
		t.Fatal("pending key not persisted")
	}
	if _, err := client.acquire(ctx); err == nil {
		t.Fatal("unreachable issuer succeeded")
	}
	retried, err := client.readBundle()
	if err != nil {
		t.Fatal(err)
	}
	if retried.KeyPEM != pending.KeyPEM {
		t.Fatal("retry replaced pending private key")
	}

	certFile, keyFile := filepath.Join(dir, "test.pem"), filepath.Join(dir, "test.key")
	cert := writeLocalPair(t, certFile, keyFile, hostname)
	key, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.saveBundle(certificateBundle{Hostname: hostname, KeyPEM: string(key), CertificatePEM: string(cert)}); err != nil {
		t.Fatal(err)
	}
	// A restart with persisted usable material has no dependency on the issuer.
	restarted, err := NewClient(t.Context(), ClientConfig{RelayURL: client.relayURL, Hostname: hostname, CertificateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.WaitReady(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restarted.pinned().chainPEM, cert) {
		t.Fatal("restart did not reuse certificate")
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(client.bundlePath(), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := NewClient(t.Context(), ClientConfig{RelayURL: client.relayURL, Hostname: hostname, CertificateDir: dir}); err == nil {
		got.Close()
		t.Fatal("corrupt persisted material accepted")
	}
}

func TestAutomaticCertificateReadiness(t *testing.T) {
	client, err := NewClient(t.Context(), ClientConfig{RelayURL: "https://127.0.0.1:1", Hostname: "tenant.test.example", CertificateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if client.pinned() != nil {
		t.Fatal("local TLS became ready without a certificate")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := client.WaitReady(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("readiness = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.WaitReady(t.Context()); err == nil {
		t.Fatal("closed unready client became ready")
	}
}

func TestIssuancePolicyDoesNotInvalidateUsableCertificate(t *testing.T) {
	const hostname = "tenant.test.example"
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tenant.pem"), filepath.Join(dir, "tenant.key")
	certPEM := writeLocalPair(t, certFile, keyFile, hostname)
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := newLocalPin(certPEM, keyPEM, hostname)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{pin: pin}
	denied := &types.APIRequestError{StatusCode: http.StatusForbidden, Code: types.APIErrorCodeTenantIssuanceNotApproved}
	client.setIssuanceError(&certificateRetryError{error: denied})
	if !client.Ready() || !errors.Is(client.IssuanceError(), &types.APIRequestError{Code: denied.Code}) {
		t.Fatalf("usable certificate or policy diagnosis lost: %v", client.IssuanceError())
	}
	client.setIssuanceError(&types.APIRequestError{StatusCode: http.StatusServiceUnavailable, Code: types.APIErrorCodeFeatureUnavailable})
	if !client.Ready() || client.IssuanceError() != nil {
		t.Fatalf("transient CA failure became a policy denial: %v", client.IssuanceError())
	}
}

func TestCertificateIssuanceLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certificate.lock")
	first, err := lockCertificate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := lockCertificate(path); !errors.Is(err, errAutomaticCertificateBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("concurrent issuer lock = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	// Persistent lock file is not stale ownership after its descriptor closes.
	next, err := lockCertificate(path)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}

func TestExpiredAutomaticCertificateDoesNotBootstrap(t *testing.T) {
	const hostname = "tenant.test.example"
	dir := t.TempDir()
	key, der, _ := mustSelfSignedCert(t, hostname, nil)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cert.NotBefore = time.Now().Add(-2 * time.Hour)
	cert.NotAfter = time.Now().Add(-time.Hour)
	der, err = x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	owner := &automaticSource{hostname: hostname, certificateDir: dir}
	if err := owner.saveBundle(certificateBundle{
		Hostname:       hostname,
		KeyPEM:         string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(t.Context(), ClientConfig{RelayURL: "https://127.0.0.1:1", Hostname: hostname, CertificateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.pinned() != nil {
		t.Fatal("expired persisted certificate restored relay signing")
	}
}

// Lease checks cannot initiate issuance after a failure or cancel a slow worker
// attempt. A gate models CA work outliving the lease caller's deadline.
func TestAutomaticWorkerOwnsIssuanceAfterFailure(t *testing.T) {
	issuer := newTestIssuer(t)
	relayCert := issuer.issueFor(t, 2, "127.0.0.1")
	var requests atomic.Int64
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != types.PathV1TenantCertificate {
			t.Errorf("unexpected relay endpoint: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if requests.Add(1) == 1 {
			http.Error(w, "temporary issuance failure", http.StatusServiceUnavailable)
			return
		}
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		var request types.TenantCertificateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		block, _ := pem.Decode([]byte(request.CSRPEM))
		if block == nil {
			t.Error("missing CSR")
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Error(err)
			return
		}
		template := *issuer.issue(t, 3).leaf
		template.IPAddresses = nil
		der, err := x509.CreateCertificate(rand.Reader, &template, issuer.cert, csr.PublicKey, issuer.key)
		if err != nil {
			t.Error(err)
			return
		}
		chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.cert.Raw})...)
		_ = json.NewEncoder(w).Encode(types.APIEnvelope[types.TenantCertificateResponse]{OK: true, Data: types.TenantCertificateResponse{CertificatePEM: string(chain)}})
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{relayCert.tls}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	client := &Client{hostname: tenantHostname, ready: make(chan struct{})}
	client.automatic = &automaticSource{hostname: tenantHostname, relayURL: server.URL, headers: client.headers, certificateDir: t.TempDir()}
	if _, err := client.automatic.acquire(t.Context()); err == nil {
		t.Fatal("initial issuance succeeded")
	}
	pending, err := client.automatic.readBundle()
	if err != nil {
		t.Fatal(err)
	}
	// During worker backoff, a lease check must not take over issuance.
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, _ = client.RefreshChain(ctx)
	if requests.Load() != 1 {
		t.Fatal("lease check issued after failure")
	}
	client.automatic.start(client)
	defer client.Close()
	defer close(release)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not start")
	}
	ctx, cancel = context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, _ = client.RefreshChain(ctx)
	<-ctx.Done()
	// Releasing only after the short deadline proves it cannot cancel issuance.
	select {
	case release <- struct{}{}:
	case <-time.After(5 * time.Second):
		t.Fatal("lease deadline canceled worker issuance")
	}
	readyCtx, readyCancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer readyCancel()
	if err := client.WaitReady(readyCtx); err != nil {
		t.Fatal(err)
	}
	if client.pinned() == nil || requests.Load() != 2 {
		t.Fatal("worker did not exclusively activate local material")
	}
	installed, err := client.automatic.readBundle()
	if err != nil {
		t.Fatal(err)
	}
	if installed.KeyPEM != pending.KeyPEM {
		t.Fatal("worker replaced persisted key")
	}
}

func TestAutomaticRetryAfterIsBounded(t *testing.T) {
	for _, test := range []struct {
		value string
		want  time.Duration
	}{
		{"120", 2 * time.Minute}, {"18446744073709551615", time.Hour},
		{time.Now().Add(24 * time.Hour).UTC().Format(http.TimeFormat), time.Hour},
		{"-1", 0}, {"invalid", 0}, {"Wed, 01 Jan 2020 00:00:00 GMT", 0},
	} {
		t.Run(test.value, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", test.value)
				http.Error(w, "retry later", http.StatusTooManyRequests)
			}))
			defer server.Close()
			source := &automaticSource{hostname: tenantHostname, relayURL: server.URL, headers: func() http.Header { return http.Header{} }, certificateDir: t.TempDir()}
			_, err := source.acquire(t.Context())
			var retry *certificateRetryError
			if !errors.As(err, &retry) || retry.delay != test.want {
				t.Fatalf("Retry-After %q: %v, want %v", test.value, err, test.want)
			}
		})
	}
}
