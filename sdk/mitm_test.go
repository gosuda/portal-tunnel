package sdk

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"syscall"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// TestMITMProbeCompletionClassifiesExporter covers the probe completion
// decision at the manager boundary, with no TLS peer: a completion matching
// the armed exporter passes, a differing one reports the exporter mismatch,
// a reservation that was never armed counts as a mismatch, and an unknown
// nonce is dropped without touching live reservations.
func TestMITMProbeCompletionClassifiesExporter(t *testing.T) {
	listener := &listener{}
	listener.mitmManager = newMITMManager(context.Background(), listener, false)

	// Matching exporter value: the probe passes with an empty reason.
	expected := bytes.Repeat([]byte{0xAB}, 32)
	resultCh, cleanup := listener.mitmManager.reserveProbe("probe-match")
	defer cleanup()
	listener.mitmManager.attachExpected("probe-match", expected)
	listener.mitmManager.completeProbe("probe-match", expected)
	select {
	case reason := <-resultCh:
		if reason != "" {
			t.Fatalf("probe reason = %q, want empty", reason)
		}
	default:
		t.Fatal("matching probe completion produced no result")
	}

	// Differing exporter value: exporter mismatch.
	resultCh, cleanup = listener.mitmManager.reserveProbe("probe-mismatch")
	defer cleanup()
	listener.mitmManager.attachExpected("probe-mismatch", bytes.Repeat([]byte{0xAB}, 32))
	listener.mitmManager.completeProbe("probe-mismatch", bytes.Repeat([]byte{0xCD}, 32))
	select {
	case reason := <-resultCh:
		if reason != types.MITMProbeReasonExporterMismatch {
			t.Fatalf("probe reason = %q, want %q", reason, types.MITMProbeReasonExporterMismatch)
		}
	default:
		t.Fatal("mismatched probe completion produced no result")
	}

	// A reservation that was never armed holds no exporter value and must
	// count as a mismatch, never as a pass.
	resultCh, cleanup = listener.mitmManager.reserveProbe("probe-unarmed")
	defer cleanup()
	listener.mitmManager.completeProbe("probe-unarmed", bytes.Repeat([]byte{0xAB}, 32))
	select {
	case reason := <-resultCh:
		if reason != types.MITMProbeReasonExporterMismatch {
			t.Fatalf("unarmed probe reason = %q, want %q", reason, types.MITMProbeReasonExporterMismatch)
		}
	default:
		t.Fatal("unarmed probe completion produced no result")
	}

	// An unknown nonce is dropped: completing it must neither block nor
	// consume the result of a live reservation.
	armed := bytes.Repeat([]byte{0xAB}, 32)
	resultCh, cleanup = listener.mitmManager.reserveProbe("probe-live")
	defer cleanup()
	listener.mitmManager.attachExpected("probe-live", armed)
	listener.mitmManager.completeProbe("nonce-unknown", armed)
	listener.mitmManager.completeProbe("probe-live", armed)
	select {
	case reason := <-resultCh:
		if reason != "" {
			t.Fatalf("live probe reason = %q, want empty after an unknown nonce was dropped", reason)
		}
	default:
		t.Fatal("live probe completion produced no result")
	}
}

// TestWrapBufferedConnRedeliversPeekedBytes proves tenant stream integrity
// while a probe is pending: the nonce frame the probe peek consumed from the
// wire is re-delivered to the passthrough conn ahead of the remaining bytes.
func TestWrapBufferedConnRedeliversPeekedBytes(t *testing.T) {
	const frameSize = 16
	payload := append(bytes.Repeat([]byte{0x00}, frameSize), bytes.Repeat([]byte{0xAB}, 8)...)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		writeErr <- err
	}()

	reader := bufio.NewReaderSize(server, frameSize)
	peeked, err := reader.Peek(frameSize)
	if err != nil {
		t.Fatalf("Peek() error = %v", err)
	}
	passthrough := wrapBufferedConn(server, reader)
	t.Cleanup(func() { _ = passthrough.Close() })

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(passthrough, got); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("passthrough payload = % x, want % x", got, payload)
	}
	if !bytes.Equal(peeked, payload[:frameSize]) {
		t.Fatalf("peeked frame = % x, want the probe nonce frame % x", peeked, payload[:frameSize])
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("client Write() error = %v", err)
	}
}

// TestMITMProbeConnAtHandshakeCompletionIsHandled pins the #397 ordering
// invariant at its real owner: maybeHandleConn runs the moment the reverse
// TLS handshake completes, so a nonce reserved before the handshake is
// served as a probe there — never handed to tenant traffic — while the same
// connection shape without a pending reservation falls through as ordinary
// tenant traffic.
func TestMITMProbeConnAtHandshakeCompletionIsHandled(t *testing.T) {
	t.Run("reserved before handshake is handled as a probe", func(t *testing.T) {
		listener := &listener{}
		listener.mitmManager = newMITMManager(context.Background(), listener, false)

		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatalf("rand.Read() error = %v", err)
		}
		nonceHex := hex.EncodeToString(nonce)

		// Production order from probeTLSPassthrough: the nonce is reserved
		// once the TCP connection exists but before the TLS handshake, so
		// the reservation is pending before the reverse handshake can
		// complete.
		resultCh, cleanupProbe := listener.mitmManager.reserveProbe(nonceHex)
		defer cleanupProbe()

		clientConn, serverConn := newMITMProbeTLSPair(t)
		defer closeMITMProbeTLSConn(clientConn)
		defer closeMITMProbeTLSConn(serverConn)

		// Arm the reservation before the handler can observe the
		// connection: in production the exporter value exists the moment
		// the reverse handshake completes, never later than Accept.
		clientState := clientConn.ConnectionState()
		expected, err := (&clientState).ExportKeyingMaterial(mitmProbeExporterLabel, nil, 32)
		if err != nil {
			t.Fatalf("client ExportKeyingMaterial() error = %v", err)
		}
		listener.mitmManager.attachExpected(nonceHex, expected)

		// Park the probe frame in the pipe rendezvous before the handler
		// starts: net.Pipe is synchronous, so the writer goroutine blocks
		// until the handler's TLS readLoop consumes the record (returns
		// nil) or cleanup closes the conn (ErrClosedPipe — tolerated in
		// the drain below). This keeps the 100ms peek deadline safe under
		// any scheduler delay. The handler may still legally bail out as
		// a passthrough, so the write must never block the test goroutine.
		frame := bytes.Clone(nonce)
		frame = append(frame, bytes.Repeat([]byte{0xAB}, 128)...)
		writeErrCh := make(chan error, 1)
		go func() {
			_, err := clientConn.Write(frame)
			writeErrCh <- err
		}()

		type handleResult struct {
			conn    net.Conn
			handled bool
			err     error
		}
		handleResultCh := make(chan handleResult, 1)
		go func() {
			// Accept fires the moment the reverse handshake completes; the
			// reservation must already be pending at that point.
			nextConn, handled, err := listener.mitmManager.maybeHandleConn(serverConn)
			handleResultCh <- handleResult{conn: nextConn, handled: handled, err: err}
		}()

		select {
		case reason := <-resultCh:
			if reason != "" {
				t.Fatalf("probe reason = %q, want empty", reason)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for probe result: was the reservation pending at handshake completion?")
		}

		select {
		case result := <-handleResultCh:
			if result.err != nil {
				t.Fatalf("maybeHandleConn() error = %v", result.err)
			}
			if !result.handled {
				t.Fatal("maybeHandleConn() handled = false, want true: probe bypassed into normal traffic")
			}
			if result.conn != nil {
				t.Fatal("maybeHandleConn() returned passthrough conn for probe")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for probe handler")
		}

		// A completed probe closes the conn mid-frame, so a closed-pipe
		// or nil write result is the expected terminal state here.
		select {
		case writeErr := <-writeErrCh:
			if writeErr != nil && !errors.Is(writeErr, io.ErrClosedPipe) && !errors.Is(writeErr, net.ErrClosed) && !errors.Is(writeErr, syscall.EPIPE) {
				t.Fatalf("clientConn.Write() error = %v", writeErr)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for client probe write")
		}
	})

	t.Run("unreserved connection passes through as tenant traffic", func(t *testing.T) {
		listener := &listener{}
		listener.mitmManager = newMITMManager(context.Background(), listener, false)

		clientConn, serverConn := newMITMProbeTLSPair(t)
		defer closeMITMProbeTLSConn(clientConn)
		defer closeMITMProbeTLSConn(serverConn)

		type handleResult struct {
			conn    net.Conn
			handled bool
			err     error
		}
		handleResultCh := make(chan handleResult, 1)
		go func() {
			nextConn, handled, err := listener.mitmManager.maybeHandleConn(serverConn)
			handleResultCh <- handleResult{conn: nextConn, handled: handled, err: err}
		}()

		var result handleResult
		select {
		case result = <-handleResultCh:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for passthrough result")
		}
		if result.err != nil {
			t.Fatalf("maybeHandleConn() error = %v", result.err)
		}
		if result.handled {
			t.Fatal("maybeHandleConn() handled = true, want false: unreserved conn was intercepted")
		}
		if result.conn == nil {
			t.Fatal("maybeHandleConn() returned nil passthrough conn")
		}

		payload := []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
		writeErrCh := make(chan error, 1)
		go func() {
			_, err := clientConn.Write(payload)
			writeErrCh <- err
		}()
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(result.conn, got); err != nil {
			t.Fatalf("ReadFull() error = %v", err)
		}
		select {
		case err := <-writeErrCh:
			if err != nil {
				t.Fatalf("clientConn.Write() error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for client write")
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("passthrough payload = %q, want %q", got, payload)
		}
	})
}

// TestMITMProbePassthroughForNonExporterConn pins the C7 capability gate: a
// connection that cannot export keying material — e.g. one terminated by a
// tenant transport without EKM — never enters the probe machinery, even when
// its leading bytes match a reserved nonce, and the peeked bytes are handed
// on to tenant traffic intact.
func TestMITMProbePassthroughForNonExporterConn(t *testing.T) {
	listener := &listener{}
	listener.mitmManager = newMITMManager(context.Background(), listener, false)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	resultCh, cleanupProbe := listener.mitmManager.reserveProbe(hex.EncodeToString(nonce))
	defer cleanupProbe()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	type handleResult struct {
		conn    net.Conn
		handled bool
		err     error
	}
	handleResultCh := make(chan handleResult, 1)
	go func() {
		nextConn, handled, err := listener.mitmManager.maybeHandleConn(serverConn)
		handleResultCh <- handleResult{conn: nextConn, handled: handled, err: err}
	}()

	payload := append(bytes.Clone(nonce), bytes.Repeat([]byte{0xCD}, 32)...)
	writeErrCh := make(chan error, 1)
	go func() {
		_, err := clientConn.Write(payload)
		writeErrCh <- err
	}()

	var result handleResult
	select {
	case result = <-handleResultCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for passthrough result")
	}
	if result.err != nil {
		t.Fatalf("maybeHandleConn() error = %v", result.err)
	}
	if result.handled {
		t.Fatal("maybeHandleConn() handled = true, want false: non-exporter conn was intercepted as a probe")
	}
	if result.conn == nil {
		t.Fatal("maybeHandleConn() returned nil passthrough conn")
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(result.conn, got); err != nil {
		t.Fatalf("ReadFull() on passthrough conn error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("passthrough payload = % x, want the full probe-shaped frame % x", got, payload)
	}
	select {
	case err := <-writeErrCh:
		if err != nil {
			t.Fatalf("clientConn.Write() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client write")
	}

	select {
	case reason := <-resultCh:
		t.Fatalf("probe completed with reason %q for a non-exporter conn", reason)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestMITMProbeDetectionBansListener(t *testing.T) {
	doneCh := make(chan struct{})
	entryURL, err := url.Parse("https://entry.example")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	listener := &listener{
		api: &apiClient{relayURL: entryURL},
		cancel: func() {
			select {
			case <-doneCh:
			default:
				close(doneCh)
			}
		},
		doneCh: doneCh,
	}
	listener.mitmManager = newMITMManager(context.Background(), listener, true)

	listener.mitmManager.logResult(mitmProbeReport{
		RelayURL: entryURL.String(),
		Detected: true,
		Reason:   types.MITMProbeReasonExporterMismatch,
	}, nil)

	select {
	case <-listener.doneCh:
	default:
		t.Fatal("listener.doneCh is open, want closed")
	}
}

func TestMITMProbeDetectionWarnsWithoutBanningListener(t *testing.T) {
	doneCh := make(chan struct{})
	relayURL, err := url.Parse("https://relay.example")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	listener := &listener{
		api:    &apiClient{relayURL: relayURL},
		doneCh: doneCh,
	}
	listener.mitmManager = newMITMManager(context.Background(), listener, false)

	listener.mitmManager.logResult(mitmProbeReport{
		RelayURL: relayURL.String(),
		Detected: true,
		Reason:   types.MITMProbeReasonExporterMismatch,
	}, nil)

	select {
	case <-listener.doneCh:
		t.Fatal("listener.doneCh is closed, want open")
	default:
	}
}

func TestMITMProbeDialAddressUsesRelayHostForLocalRelay(t *testing.T) {
	relayURL, err := url.Parse("https://localhost:4017")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	listener := &listener{
		api: &apiClient{relayURL: relayURL},
	}
	listener.mitmManager = newMITMManager(context.Background(), listener, false)

	got, err := listener.mitmManager.probeDialAddress("https://bravo-gecko-disco.localhost:4017")
	if err != nil {
		t.Fatalf("probeDialAddress() error = %v", err)
	}
	if got != "localhost:4017" {
		t.Fatalf("probeDialAddress() = %q, want %q", got, "localhost:4017")
	}
}

func TestMITMProbeDialAddressUsesPublicURLForRemoteRelay(t *testing.T) {
	relayURL, err := url.Parse("https://relay.example")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	listener := &listener{
		api: &apiClient{relayURL: relayURL},
	}
	listener.mitmManager = newMITMManager(context.Background(), listener, false)

	got, err := listener.mitmManager.probeDialAddress("https://bravo-gecko-disco.example")
	if err != nil {
		t.Fatalf("probeDialAddress() error = %v", err)
	}
	if got != "bravo-gecko-disco.example:443" {
		t.Fatalf("probeDialAddress() = %q, want %q", got, "bravo-gecko-disco.example:443")
	}
}

// newMITMProbeTLSPair returns a client/server TLS pair over a loopback TCP
// socket pair with the handshake already completed on both sides. Real TCP
// matches production probe transport and its kernel buffering makes frame
// delivery independent of goroutine scheduling; net.Pipe's unbuffered
// rendezvous made the responder's bounded peek racy under load.
func newMITMProbeTLSPair(t *testing.T) (*tls.Conn, *tls.Conn) {
	t.Helper()

	cert := newMITMProbeCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	clientRaw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial() error = %v", err)
	}
	serverRaw, err := listener.Accept()
	if err != nil {
		_ = clientRaw.Close()
		t.Fatalf("Accept() error = %v", err)
	}

	clientConn := tls.Client(clientRaw, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
	})
	serverConn := tls.Server(serverRaw, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	})

	errCh := make(chan error, 2)
	go func() { errCh <- serverConn.HandshakeContext(context.Background()) }()
	go func() { errCh <- clientConn.HandshakeContext(context.Background()) }()
	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatalf("TLS handshake error = %v", err)
		}
	}

	return clientConn, serverConn
}

// closeMITMProbeTLSConn breaks pending I/O before Close so deferred cleanup
// cannot block on a peer that already exited.
func closeMITMProbeTLSConn(conn *tls.Conn) {
	if conn == nil {
		return
	}
	_ = conn.SetDeadline(time.Now())
	_ = conn.Close()
}

func newMITMProbeCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "portal-mitm-probe",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair() error = %v", err)
	}
	return cert
}
