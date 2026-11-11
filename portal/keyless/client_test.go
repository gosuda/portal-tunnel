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

var errSignerCloseFailed = errors.New("signer close failed")

func TestNewClientHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for name, config := range map[string]ClientConfig{
		"relay": {},
	} {
		t.Run(name, func(t *testing.T) {
			config.RelayURL = "https://127.0.0.1:1"
			config.Hostname = "tenant.example"
			client, err := NewClient(ctx, config)
			if client != nil {
				_ = client.Close()
				t.Fatal("NewClient returned a client after cancellation")
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("NewClient() error = %v, want context.Canceled", err)
			}
		})
	}
}

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
	client := &Client{pin: &pinnedChain{signer: closer}}

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

func TestNewSignerRequiresBindingRegistry(t *testing.T) {
	t.Parallel()

	if _, err := NewSigner(nil, nil); err == nil {
		t.Fatal("NewSigner(nil bindings) = nil error, want policy guard")
	} else if err.Error() != "portal binding registry is required" {
		t.Fatalf("NewSigner(nil bindings) error = %q, want binding registry requirement", err)
	}
	if _, err := NewSigner(NewBindingRegistry(time.Minute), nil); err == nil {
		t.Fatal("NewSigner(nil key lookup) = nil error, want a signer that cannot sign refused")
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

func TestClientTerminateConnLoopback(t *testing.T) {
	const (
		hostname        = "tunnel.test.example"
		initialToken    = "token-initial"
		handshakeBudget = 15 * time.Second
	)
	key, certDER, certPEM := mustSelfSignedCert(t, hostname, []net.IP{net.ParseIP("127.0.0.1")})
	service, observations := newTranscriptSignService(t, key)
	srv := httptest.NewUnstartedServer(transcriptSignHandler(service, observations))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	client := newTerminateLoopbackClient(t, srv.URL, hostname, initialToken)
	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Errorf("client.Close() error = %v", closeErr)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), handshakeBudget)
	defer cancel()
	binding := make([]byte, 16)
	if _, err := rand.Read(binding); err != nil {
		t.Fatalf("generate binding: %v", err)
	}
	relayEnd, tenantEnd := net.Pipe()
	t.Cleanup(func() { _ = relayEnd.Close() })
	probeTLS, probeHandshake := startTLSProbeHandshake(t, ctx, relayEnd, hostname, certPEM)
	terminated, err := client.TerminateConn(ctx, tenantEnd, binding)
	if err != nil {
		t.Fatalf("TerminateConn() error = %v", err)
	}
	t.Cleanup(func() { _ = terminated.Close() })
	checkTerminatedHandshake(t, probeHandshake, terminated)
	awaitSignObservation(t, observations, binding, initialToken)
	checkTerminatedEcho(t, probeTLS, terminated)
}

type signObservation struct {
	binding     []byte
	accessToken string
}

func newTranscriptSignService(t *testing.T, key *ecdsa.PrivateKey) (*ksigner.Service, chan signObservation) {
	t.Helper()
	service := &ksigner.Service{
		Store: func() ksigner.KeyStore {
			store := ksigner.NewStaticKeyStore()
			if err := store.Put(types.KeylessRelayKeyID, key); err != nil {
				t.Fatalf("seed static key store: %v", err)
			}
			return store
		}(),
		TranscriptValidator: ksigner.TranscriptValidatorFunc(func(context.Context, *signrpc.TranscriptSignRequest) error {
			return nil
		}),
	}
	return service, make(chan signObservation, 4)
}

func transcriptSignHandler(service *ksigner.Service, observations chan<- signObservation) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}

func newTerminateLoopbackClient(t *testing.T, relayURL, hostname, accessToken string) *Client {
	t.Helper()
	client, err := NewClient(t.Context(), ClientConfig{
		RelayURL:    relayURL,
		Hostname:    hostname,
		AccessToken: accessToken,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	return client
}

func startTLSProbeHandshake(t *testing.T, ctx context.Context, relayEnd net.Conn, hostname string, certPEM []byte) (*tls.Conn, <-chan error) {
	t.Helper()
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
	return probeTLS, probeHandshake
}

func checkTerminatedHandshake(t *testing.T, probeHandshake <-chan error, terminated net.Conn) {
	t.Helper()
	if err := <-probeHandshake; err != nil {
		t.Fatalf("client-side tls handshake error = %v", err)
	}
	if got := terminated.(interface{ ConnectionState() tls.ConnectionState }).ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("negotiated ALPN = %q, want http/1.1", got)
	}
}

func awaitSignObservation(t *testing.T, observations <-chan signObservation, binding []byte, accessToken string) {
	t.Helper()
	select {
	case obs := <-observations:
		if !bytes.Equal(obs.binding, binding) {
			t.Fatalf("sign request binding = %X, want %X", obs.binding, binding)
		}
		if obs.accessToken != accessToken {
			t.Fatalf("sign request access token header = %q, want %q", obs.accessToken, accessToken)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sign endpoint saw no transcript sign request")
	}
}

func writeProbeEchoRoundTrip(probeTLS *tls.Conn) error {
	if _, err := probeTLS.Write([]byte("ping")); err != nil {
		return fmt.Errorf("probe write: %w", err)
	}
	pong := make([]byte, len("ping-pong"))
	if _, err := io.ReadFull(probeTLS, pong); err != nil {
		return fmt.Errorf("probe read echo: %w", err)
	}
	if string(pong) != "ping-pong" {
		return fmt.Errorf("probe echo = %q, want ping-pong", pong)
	}
	return nil
}

func replyCheckTerminatedEchoPingPong(t *testing.T, terminated net.Conn) {
	t.Helper()
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
}

func checkTerminatedEcho(t *testing.T, probeTLS *tls.Conn, terminated net.Conn) {
	t.Helper()
	echoDone := make(chan error, 1)
	go func() {
		echoDone <- writeProbeEchoRoundTrip(probeTLS)
	}()
	replyCheckTerminatedEchoPingPong(t, terminated)
	if err := <-echoDone; err != nil {
		t.Fatalf("application data round trip failed: %v", err)
	}
}

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
	return errSignerCloseFailed
}

func replyTranscriptSignRequest(w http.ResponseWriter, r *http.Request, service *ksigner.Service) {
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
}

func startTranscriptSignServer(t *testing.T, key *ecdsa.PrivateKey, certDER []byte, service *ksigner.Service) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != signrpc.SignPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		replyTranscriptSignRequest(w, r, service)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestClientTerminateConnExportsKeyingMaterial(t *testing.T) {
	const (
		hostname        = "probe.test.example"
		probeExporter   = "Portal-MITM-Probe-v1"
		handshakeBudget = 15 * time.Second
	)

	key, certDER, certPEM := mustSelfSignedCert(t, hostname, []net.IP{net.ParseIP("127.0.0.1")})
	service, _ := newTranscriptSignService(t, key)
	srv := startTranscriptSignServer(t, key, certDER, service)

	client := newTerminateLoopbackClient(t, srv.URL, hostname, "")
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), handshakeBudget)
	defer cancel()
	binding := make([]byte, 16)
	if _, err := rand.Read(binding); err != nil {
		t.Fatalf("generate binding: %v", err)
	}
	relayEnd, tenantEnd := net.Pipe()
	t.Cleanup(func() { _ = relayEnd.Close() })
	probeTLS, probeHandshake := startTLSProbeHandshake(t, ctx, relayEnd, hostname, certPEM)
	terminated, err := client.TerminateConn(ctx, tenantEnd, binding)
	if err != nil {
		t.Fatalf("TerminateConn() error = %v", err)
	}
	t.Cleanup(func() { _ = terminated.Close() })
	if err := <-probeHandshake; err != nil {
		t.Fatalf("probe handshake error = %v", err)
	}
	checkExporterMatchesProbe(t, terminated, probeTLS, probeExporter)
}

func checkExporterMatchesProbe(t *testing.T, terminated net.Conn, probeTLS *tls.Conn, label string) {
	t.Helper()
	exporter, ok := terminated.(interface {
		ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
	})
	if !ok {
		t.Fatal("terminated conn does not satisfy the direct exporter capability")
	}
	probeState := probeTLS.ConnectionState()
	probeExport, err := (&probeState).ExportKeyingMaterial(label, nil, 32)
	if err != nil {
		t.Fatalf("probe ExportKeyingMaterial() error = %v", err)
	}
	serverExport, err := exporter.ExportKeyingMaterial(label, nil, 32)
	if err != nil {
		t.Fatalf("terminated conn ExportKeyingMaterial() error = %v", err)
	}
	if !bytes.Equal(probeExport, serverExport) {
		t.Fatal("exporter values of the same probe session differ between the stock client and the t13server terminator")
	}
}

type captureWrites struct {
	net.Conn
	capture  bool
	captured []byte
}

func (c *captureWrites) Write(p []byte) (int, error) {
	if c.capture {
		c.captured = append(c.captured, p...)
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func TestTerminatedConnKeepsARecordAcrossAReadDeadline(t *testing.T) {
	t.Parallel()
	fixture, cancel := setupTerminatedRead(t)
	defer cancel()
	fixture.checkPartialReadTimesOut(t)
	fixture.checkReadRecoversAfterDeadline(t)
}

type readResult struct {
	data string
	err  error
}

func readTerminatedAsync(terminated net.Conn, n int) <-chan readResult {
	done := make(chan readResult, 1)
	go func() {
		buf := make([]byte, n)
		n, err := io.ReadFull(terminated, buf)
		done <- readResult{data: string(buf[:n]), err: err}
	}()
	return done
}

func awaitReadResult(t *testing.T, ctx context.Context, done <-chan readResult) readResult {
	t.Helper()
	select {
	case res := <-done:
		return res
	case <-ctx.Done():
		t.Fatal("tenant read did not return")
		return readResult{}
	}
}

type terminatedReadFixture struct {
	ctx        context.Context
	relayEnd   net.Conn
	terminated net.Conn
	request    string
	split      int
	record     []byte
}

func setupTerminatedRead(t *testing.T) (*terminatedReadFixture, context.CancelFunc) {
	t.Helper()
	issuer := newTestIssuer(t)
	relay := newRelayStandIn(t, issuer.issue(t, 2))
	client := relay.newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	binding := relay.bindings.Issue("lease", nil)
	relayEnd, tenantEnd := net.Pipe()
	t.Cleanup(func() { _ = relayEnd.Close() })
	wire := &captureWrites{Conn: relay.bindings.FixHelloOnWrite(relayEnd, binding)}
	visitor := tls.Client(wire, &tls.Config{ServerName: tenantHostname, RootCAs: issuer.pool, MinVersion: tls.VersionTLS13})
	t.Cleanup(func() { _ = visitor.Close() })
	visitorDone := make(chan error, 1)
	go func() { visitorDone <- visitor.HandshakeContext(ctx) }()
	terminated, err := client.TerminateConn(ctx, tenantEnd, binding[:])
	if err != nil {
		t.Fatalf("TerminateConn() error = %v", err)
	}
	t.Cleanup(func() { _ = terminated.Close() })
	if err := <-visitorDone; err != nil {
		t.Fatalf("visitor handshake: %v", err)
	}
	const request = "GET / HTTP/1.1\r\nHost: " + tenantHostname + "\r\n\r\n"
	wire.capture = true
	if _, err := visitor.Write([]byte(request)); err != nil {
		t.Fatalf("visitor write: %v", err)
	}
	return &terminatedReadFixture{
		ctx:        ctx,
		relayEnd:   relayEnd,
		terminated: terminated,
		request:    request,
		split:      10,
		record:     wire.captured,
	}, cancel
}

func (f *terminatedReadFixture) checkPartialReadTimesOut(t *testing.T) {
	t.Helper()
	first := readTerminatedAsync(f.terminated, len(f.request))
	if _, err := f.relayEnd.Write(f.record[:f.split]); err != nil {
		t.Fatalf("deliver the first part: %v", err)
	}
	if err := f.terminated.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	var netErr net.Error
	if res := awaitReadResult(t, f.ctx, first); !errors.As(res.err, &netErr) || !netErr.Timeout() {
		t.Fatalf("read past the deadline = (%q, %v), want a timeout", res.data, res.err)
	}
}

func (f *terminatedReadFixture) checkReadRecoversAfterDeadline(t *testing.T) {
	t.Helper()
	if err := f.terminated.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear read deadline: %v", err)
	}
	second := readTerminatedAsync(f.terminated, len(f.request))
	go func() { _, _ = f.relayEnd.Write(f.record[f.split:]) }()
	if res := awaitReadResult(t, f.ctx, second); res.err != nil || res.data != f.request {
		t.Fatalf("read after the deadline = (%q, %v), want %q", res.data, res.err, f.request)
	}
}
