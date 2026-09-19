package keyless

import (
	"bytes"
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
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ksigner "github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestClientAccessTokenUpdateChangesSignerHeaders(t *testing.T) {
	t.Parallel()
	client := &Client{}
	client.SetAccessToken(" first ")
	if got := client.headers().Get(types.HeaderAccessToken); got != "first" {
		t.Fatalf("initial access token header = %q, want first", got)
	}
	client.SetAccessToken("second")
	if got := client.headers().Get(types.HeaderAccessToken); got != "second" {
		t.Fatalf("updated access token header = %q, want second", got)
	}
}

func TestClientClosePreservesFirstError(t *testing.T) {
	t.Parallel()
	closer := &failingCloseResource{}
	client := &Client{signer: closer}

	first := client.Close()
	second := client.Close()
	if first == nil || second == nil {
		t.Fatalf("Close() must keep reporting the first close error; got first=%v second=%v", first, second)
	}
	if !errors.Is(second, first) {
		t.Fatalf("second Close() = %v, want first close error %v", second, first)
	}
	if closer.calls != 1 {
		t.Fatalf("underlying resource closed %d times, want exactly 1", closer.calls)
	}
}

func TestNewSignerRequiresTranscriptValidator(t *testing.T) {
	t.Parallel()

	if _, err := NewSigner(nil, nil); err == nil {
		t.Fatal("NewSigner(nil validator) = nil error, want policy guard")
	} else if err.Error() != "portal transcript validator is required" {
		t.Fatalf("NewSigner(nil validator) error = %q, want transcript validator requirement", err)
	}
}

func TestVerifyCertificateHostname(t *testing.T) {
	t.Parallel()
	_, _, certPEM := mustSelfSignedCert(t, "covered.test.example", nil)

	if err := verifyCertificateHostname(certPEM, "covered.test.example"); err != nil {
		t.Fatalf("VerifyCertificateHostname(covered) error = %v", err)
	}
	if err := verifyCertificateHostname(certPEM, "other.test.example"); err == nil {
		t.Fatal("VerifyCertificateHostname(other) = nil, want hostname mismatch error")
	}
}

// TestClientTerminateConnLoopback is the end-to-end proof of the rebuilt
// tenant client: a loopback relay stand-in serves the transcript-bound
// /v1/sign wire (POST JSON in the signrpc shape) behind HTTPS, the client
// pins that endpoint's certificate chain, and TerminateConn completes a real
// TLS 1.3 handshake against a stock crypto/tls counterpart. The relay-minted
// binding and the access token must reach the sign endpoint untouched, and
// the terminated connection must carry application data both ways.
func TestClientTerminateConnLoopback(t *testing.T) {
	const (
		hostname        = "tunnel.test.example"
		initialToken    = "token-initial"
		handshakeBudget = 15 * time.Second
	)

	key, certDER, certPEM := mustSelfSignedCert(t, hostname, []net.IP{net.ParseIP("127.0.0.1")})

	service := &ksigner.Service{
		Store: func() ksigner.KeyStore {
			store := ksigner.NewStaticKeyStore()
			if err := store.Put(relayKeyID, key); err != nil {
				t.Fatalf("seed static key store: %v", err)
			}
			return store
		}(),
		// Test-only: this stand-in's validator accepts every structurally
		// valid request; the binding's presence and value are asserted below.
		TranscriptValidator: ksigner.TranscriptValidatorFunc(func(context.Context, *signrpc.TranscriptSignRequest) error {
			return nil
		}),
	}

	type signObservation struct {
		binding     []byte
		accessToken string
	}
	observations := make(chan signObservation, 4)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != signrpc.SignPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req signrpc.TranscriptSignRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10)).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(signrpc.ErrorResponse{Error: err.Error()})
			return
		}
		resp, err := service.SignTranscript(r.Context(), &req)
		if err != nil {
			status := http.StatusInternalServerError
			switch {
			case errors.Is(err, ksigner.ErrInvalidArgument):
				status = http.StatusBadRequest
			case errors.Is(err, ksigner.ErrPermissionDenied):
				status = http.StatusForbidden
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(signrpc.ErrorResponse{Error: err.Error()})
			return
		}
		observations <- signObservation{
			binding:     bytes.Clone(req.Binding),
			accessToken: r.Header.Get(types.HeaderAccessToken),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client, err := NewClient(ClientConfig{
		RelayURL:    srv.URL,
		Hostname:    hostname,
		AccessToken: initialToken,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Errorf("client.Close() error = %v", closeErr)
		}
	})
	if !client.ExportsKeyingMaterial() {
		t.Fatal("ExportsKeyingMaterial() = false, want true for the t13server terminator")
	}

	ctx, cancel := context.WithTimeout(context.Background(), handshakeBudget)
	defer cancel()

	binding := make([]byte, 16)
	if _, err := rand.Read(binding); err != nil {
		t.Fatalf("generate binding: %v", err)
	}

	relayEnd, tenantEnd := net.Pipe()
	t.Cleanup(func() { _ = relayEnd.Close() })
	probeTLS := tls.Client(relayEnd, &tls.Config{
		ServerName: hostname,
		RootCAs:    mustCertPool(t, certPEM),
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	})
	t.Cleanup(func() { _ = probeTLS.Close() })

	probeHandshake := make(chan error, 1)
	go func() {
		probeHandshake <- probeTLS.HandshakeContext(ctx)
	}()

	terminated, err := client.TerminateConn(ctx, tenantEnd, binding)
	if err != nil {
		t.Fatalf("TerminateConn() error = %v", err)
	}
	t.Cleanup(func() { _ = terminated.Close() })
	if err := <-probeHandshake; err != nil {
		t.Fatalf("client-side tls handshake error = %v", err)
	}
	if got := terminated.(interface{ ConnectionState() tls.ConnectionState }).ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("negotiated ALPN = %q, want http/1.1", got)
	}

	select {
	case obs := <-observations:
		if !bytes.Equal(obs.binding, binding) {
			t.Fatalf("sign request binding = %X, want %X", obs.binding, binding)
		}
		if obs.accessToken != initialToken {
			t.Fatalf("sign request access token header = %q, want %q", obs.accessToken, initialToken)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sign endpoint saw no transcript sign request")
	}

	echoDone := make(chan error, 1)
	go func() {
		if _, err := probeTLS.Write([]byte("ping")); err != nil {
			echoDone <- fmt.Errorf("probe write: %w", err)
			return
		}
		pong := make([]byte, len("ping-pong"))
		if _, err := io.ReadFull(probeTLS, pong); err != nil {
			echoDone <- fmt.Errorf("probe read echo: %w", err)
			return
		}
		if string(pong) != "ping-pong" {
			echoDone <- fmt.Errorf("probe echo = %q, want ping-pong", pong)
			return
		}
		echoDone <- nil
	}()
	ping := make([]byte, len("ping"))
	if _, err := io.ReadFull(terminated, ping); err != nil {
		t.Fatalf("terminated conn read = %v", err)
	}
	if string(ping) != "ping" {
		t.Fatalf("terminated conn read = %q, want ping", ping)
	}
	if _, err := terminated.Write([]byte("ping-pong")); err != nil {
		t.Fatalf("terminated conn write = %v", err)
	}
	if err := <-echoDone; err != nil {
		t.Fatalf("application data round trip failed: %v", err)
	}
}

// mustSelfSignedCert generates one ECDSA P-256 self-signed server certificate
// covering hostname (plus any extra IPs) and returns the private key, DER,
// and PEM forms.
func mustSelfSignedCert(t *testing.T, hostname string, ips []net.IP) (*ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: hostname},
		DNSNames:              []string{hostname},
		IPAddresses:           ips,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if certPEM == nil {
		t.Fatal("encode certificate pem")
	}
	return key, der, certPEM
}

func mustCertPool(t *testing.T, certPEM []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("append certificate to pool")
	}
	return pool
}

type failingCloseResource struct {
	calls int
}

func (c *failingCloseResource) Close() error {
	c.calls++
	return errors.New("signer close failed")
}

// TestClientTerminateConnExportsKeyingMaterial is the MITM self-probe
// integration regression: the terminated t13server conn satisfies the
// direct exporter capability the SDK's responder side asserts, and both
// endpoints of the same probe session — the stock crypto/tls probe client
// and the t13server responder conn — derive byte-identical keying material
// for the same label. Exporter derivation itself is owned and tested by
// keyless_tls; this pins the Portal-facing capability boundary.
func TestClientTerminateConnExportsKeyingMaterial(t *testing.T) {
	const (
		hostname        = "probe.test.example"
		probeExporter   = "Portal-MITM-Probe-v1"
		handshakeBudget = 15 * time.Second
	)

	key, certDER, certPEM := mustSelfSignedCert(t, hostname, []net.IP{net.ParseIP("127.0.0.1")})
	service := &ksigner.Service{
		Store: func() ksigner.KeyStore {
			store := ksigner.NewStaticKeyStore()
			if err := store.Put(relayKeyID, key); err != nil {
				t.Fatalf("seed static key store: %v", err)
			}
			return store
		}(),
		// Test-only: this stand-in's validator accepts every structurally
		// valid request; the binding validator contract is covered by the
		// loopback termination test.
		TranscriptValidator: ksigner.TranscriptValidatorFunc(func(context.Context, *signrpc.TranscriptSignRequest) error {
			return nil
		}),
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != signrpc.SignPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req signrpc.TranscriptSignRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10)).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp, err := service.SignTranscript(r.Context(), &req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client, err := NewClient(ClientConfig{RelayURL: srv.URL, Hostname: hostname})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if !client.ExportsKeyingMaterial() {
		t.Fatal("ExportsKeyingMaterial() = false, want true for the t13server terminator")
	}

	ctx, cancel := context.WithTimeout(context.Background(), handshakeBudget)
	defer cancel()
	binding := make([]byte, 16)
	if _, err := rand.Read(binding); err != nil {
		t.Fatalf("generate binding: %v", err)
	}

	relayEnd, tenantEnd := net.Pipe()
	t.Cleanup(func() { _ = relayEnd.Close() })
	probeTLS := tls.Client(relayEnd, &tls.Config{
		ServerName: hostname,
		RootCAs:    mustCertPool(t, certPEM),
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	})
	t.Cleanup(func() { _ = probeTLS.Close() })

	probeHandshake := make(chan error, 1)
	go func() {
		probeHandshake <- probeTLS.HandshakeContext(ctx)
	}()

	terminated, err := client.TerminateConn(ctx, tenantEnd, binding)
	if err != nil {
		t.Fatalf("TerminateConn() error = %v", err)
	}
	t.Cleanup(func() { _ = terminated.Close() })
	if err := <-probeHandshake; err != nil {
		t.Fatalf("probe handshake error = %v", err)
	}

	exporter, ok := terminated.(interface {
		ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
	})
	if !ok {
		t.Fatal("terminated conn does not satisfy the direct exporter capability")
	}
	probeState := probeTLS.ConnectionState()
	probeExport, err := (&probeState).ExportKeyingMaterial(probeExporter, nil, 32)
	if err != nil {
		t.Fatalf("probe ExportKeyingMaterial() error = %v", err)
	}
	serverExport, err := exporter.ExportKeyingMaterial(probeExporter, nil, 32)
	if err != nil {
		t.Fatalf("terminated conn ExportKeyingMaterial() error = %v", err)
	}
	if !bytes.Equal(probeExport, serverExport) {
		t.Fatal("exporter values of the same probe session differ between the stock client and the t13server terminator")
	}
}
