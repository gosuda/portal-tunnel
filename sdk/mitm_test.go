package sdk

import (
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
	"io"
	"math/big"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestMITMProbeConnMatchesExporter(t *testing.T) {
	clientConn, serverConn := newMITMProbeTLSPair(t)
	defer closeMITMProbeTLSConn(clientConn)
	defer closeMITMProbeTLSConn(serverConn)

	listener := &listener{}
	listener.mitmManager = newMITMManager(context.Background(), listener, false)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	nonceHex := hex.EncodeToString(nonce)
	clientState := clientConn.ConnectionState()
	expected, err := (&clientState).ExportKeyingMaterial(mitmProbeExporterLabel, nil, 32)
	if err != nil {
		t.Fatalf("client ExportKeyingMaterial() error = %v", err)
	}
	resultCh, cleanupProbe := listener.mitmManager.reserveProbe(nonceHex)
	defer cleanupProbe()
	listener.mitmManager.attachExpected(nonceHex, expected)

	handleDone := make(chan struct{})
	go func() {
		defer close(handleDone)
		nextConn, handled, err := listener.mitmManager.maybeHandleConn(serverConn)
		if err != nil {
			t.Errorf("maybeHandleConn() error = %v", err)
			return
		}
		if nextConn != nil {
			t.Error("maybeHandleConn() returned passthrough conn for probe")
		}
		if !handled {
			t.Error("maybeHandleConn() handled = false, want true")
		}
	}()

	frame := bytes.Clone(nonce)
	frame = append(frame, bytes.Repeat([]byte{0xAB}, 128)...)
	if _, err := clientConn.Write(frame); err != nil {
		t.Fatalf("clientConn.Write() error = %v", err)
	}
	_ = clientConn.Close()

	select {
	case reason := <-resultCh:
		if reason != "" {
			t.Fatalf("probe reason = %q, want empty", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for probe result")
	}

	select {
	case <-handleDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for probe handler")
	}
}

func TestMITMProbeConnDetectsExporterMismatch(t *testing.T) {
	clientConn, serverConn := newMITMProbeTLSPair(t)
	defer closeMITMProbeTLSConn(clientConn)
	defer closeMITMProbeTLSConn(serverConn)

	listener := &listener{}
	listener.mitmManager = newMITMManager(context.Background(), listener, false)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	nonceHex := hex.EncodeToString(nonce)
	resultCh, cleanupProbe := listener.mitmManager.reserveProbe(nonceHex)
	defer cleanupProbe()
	listener.mitmManager.attachExpected(nonceHex, make([]byte, 32))

	handleDone := make(chan struct{})
	go func() {
		defer close(handleDone)
		nextConn, handled, err := listener.mitmManager.maybeHandleConn(serverConn)
		if err != nil {
			t.Errorf("maybeHandleConn() error = %v", err)
			return
		}
		if nextConn != nil {
			t.Error("maybeHandleConn() returned passthrough conn for probe")
		}
		if !handled {
			t.Error("maybeHandleConn() handled = false, want true")
		}
	}()

	frame := bytes.Clone(nonce)
	frame = append(frame, bytes.Repeat([]byte{0xCD}, 128)...)
	if _, err := clientConn.Write(frame); err != nil {
		t.Fatalf("clientConn.Write() error = %v", err)
	}
	_ = clientConn.Close()

	select {
	case reason := <-resultCh:
		if reason != types.MITMProbeReasonExporterMismatch {
			t.Fatalf("probe reason = %q, want %q", reason, types.MITMProbeReasonExporterMismatch)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for probe result")
	}

	select {
	case <-handleDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for probe handler")
	}
}

func TestMITMProbeConnAtHandshakeCompletionIsHandled(t *testing.T) {
	listener := &listener{}
	listener.mitmManager = newMITMManager(context.Background(), listener, false)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	nonceHex := hex.EncodeToString(nonce)

	// Production order from probeTLSPassthrough: the nonce is reserved
	// once the TCP connection exists but before the TLS handshake, so the
	// reservation is in place before the reverse handshake can complete.
	resultCh, cleanupProbe := listener.mitmManager.reserveProbe(nonceHex)
	defer cleanupProbe()

	cert := newMITMProbeCertificate(t)
	clientRaw, serverRaw := net.Pipe()
	clientConn := tls.Client(clientRaw, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
	})
	signaling := &readSignalingConn{Conn: serverRaw, readStarted: make(chan struct{})}
	serverConn := tls.Server(signaling, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	})
	defer closeMITMProbeTLSConn(clientConn)
	defer closeMITMProbeTLSConn(serverConn)

	type handleResult struct {
		conn    net.Conn
		handled bool
		err     error
	}
	handleResultCh := make(chan handleResult, 1)
	go func() {
		if err := serverConn.HandshakeContext(context.Background()); err != nil {
			handleResultCh <- handleResult{err: err}
			return
		}
		// Accept fires the moment the reverse handshake completes. Arming the
		// wrapper makes its next read — maybeHandleConn's peek — signal, so
		// the probe side provably attaches the expected exporter only after
		// the handler has entered its peek.
		signaling.arm()
		nextConn, handled, err := listener.mitmManager.maybeHandleConn(serverConn)
		handleResultCh <- handleResult{conn: nextConn, handled: handled, err: err}
	}()

	if err := clientConn.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client handshake error: %v", err)
	}
	select {
	case <-signaling.readStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for maybeHandleConn to start reading; was the probe reservation removed?")
	}

	clientState := clientConn.ConnectionState()
	expected, err := (&clientState).ExportKeyingMaterial(mitmProbeExporterLabel, nil, 32)
	if err != nil {
		t.Fatalf("client ExportKeyingMaterial() error = %v", err)
	}
	listener.mitmManager.attachExpected(nonceHex, expected)

	frame := bytes.Clone(nonce)
	frame = append(frame, bytes.Repeat([]byte{0xAB}, 128)...)
	if _, err := clientConn.Write(frame); err != nil {
		t.Fatalf("clientConn.Write() error = %v", err)
	}
	_ = clientConn.Close()

	select {
	case reason := <-resultCh:
		if reason != "" {
			t.Fatalf("probe reason = %q, want empty", reason)
		}
	case <-time.After(2 * time.Second):
		select {
		case result := <-handleResultCh:
			t.Fatalf("timed out waiting for probe result; handler resolved first: handled=%v passthrough=%v err=%v", result.handled, result.conn != nil, result.err)
		default:
		}
		t.Fatal("timed out waiting for probe result")
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
}

// readSignalingConn closes readStarted on the first Read after arm is
// called. Reads before arming — the TLS handshake itself — do not signal.
// Handshake reads and armed reads both happen on the goroutine that owns the
// conn, so the flag needs no lock; the Once makes repeated armed reads a
// single signal instead of a double close.
type readSignalingConn struct {
	net.Conn
	readStarted chan struct{}
	signalOnce  sync.Once
	armed       bool
}

func (c *readSignalingConn) arm() { c.armed = true }

func (c *readSignalingConn) Read(p []byte) (int, error) {
	if c.armed {
		c.signalOnce.Do(func() { close(c.readStarted) })
	}
	return c.Conn.Read(p)
}

func TestMITMProbeConnPassesThroughNormalTraffic(t *testing.T) {
	clientConn, serverConn := newMITMProbeTLSPair(t)
	defer closeMITMProbeTLSConn(clientConn)
	defer closeMITMProbeTLSConn(serverConn)

	listener := &listener{}
	listener.mitmManager = newMITMManager(context.Background(), listener, false)

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

	payload := []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
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
		t.Fatal("maybeHandleConn() handled = true, want false")
	}
	if result.conn == nil {
		t.Fatal("maybeHandleConn() returned nil passthrough conn")
	}

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
}

func TestMITMProbeDetectionBansListener(t *testing.T) {
	doneCh := make(chan struct{})
	entryURL, err := url.Parse("https://entry.example")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	exitURL, err := url.Parse("https://exit.example")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	listener := &listener{
		relayURL: entryURL,
		route:    discovery.Route{RelayURL: entryURL.String(), Explicit: false},
		relaySet: mustRelaySet(t, entryURL.String(), exitURL.String()),
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

	routes := listener.relaySet.SelectRelays(discovery.RouteState{})
	for _, route := range routes {
		if route.RelayURL == entryURL.String() {
			t.Fatal("ingress relay remains active after mitm detection")
		}
		if route.RelayURL != exitURL.String() {
			t.Fatalf("unexpected active relay after mitm detection: %q", route.RelayURL)
		}
	}
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
		relayURL: relayURL,
		relaySet: mustRelaySet(t, relayURL.String()),
		doneCh:   doneCh,
	}
	listener.mitmManager = newMITMManager(context.Background(), listener, false)

	listener.mitmManager.logResult(mitmProbeReport{
		RelayURL: relayURL.String(),
		Detected: true,
		Reason:   types.MITMProbeReasonExporterMismatch,
	}, nil)

	routes := listener.relaySet.SelectRelays(discovery.RouteState{})
	activeRelayURLs := make([]string, 0, len(routes))
	for _, route := range routes {
		activeRelayURLs = append(activeRelayURLs, route.RelayURL)
	}
	if len(activeRelayURLs) != 1 || activeRelayURLs[0] != relayURL.String() {
		t.Fatalf("ActiveRelayURLs() = %v, want [%q]", activeRelayURLs, relayURL.String())
	}
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
		relayURL: relayURL,
		route:    discovery.Route{RelayURL: relayURL.String(), Explicit: true},
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
		relayURL: relayURL,
		route:    discovery.Route{RelayURL: relayURL.String(), Explicit: true},
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

func newMITMProbeTLSPair(t *testing.T) (*tls.Conn, *tls.Conn) {
	t.Helper()

	cert := newMITMProbeCertificate(t)
	clientRaw, serverRaw := net.Pipe()
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
