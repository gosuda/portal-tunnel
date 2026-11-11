package sdk

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/url"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

type probeExporterVerdictFixture struct {
	listener *listener
}

func newProbeExporterVerdictFixture() *probeExporterVerdictFixture {
	listener := &listener{}
	listener.mitmManager = newMITMManager(listener, false)
	return &probeExporterVerdictFixture{listener: listener}
}

func checkProbeExporterVerdictMatch(t *testing.T, fx *probeExporterVerdictFixture) {
	t.Helper()
	nonce := mitmProbeNonce{1}
	resultCh := fx.listener.mitmManager.reserveProbe(nonce)
	defer fx.listener.mitmManager.releaseProbe(nonce)
	fx.listener.mitmManager.attachExpected(nonce, bytes.Repeat([]byte{0xAB}, 32))
	fx.listener.mitmManager.completeProbe(nonce, bytes.Repeat([]byte{0xAB}, 32))
	select {
	case reason := <-resultCh:
		if reason != "" {
			t.Fatalf("probe reason = %q, want empty", reason)
		}
	default:
		t.Fatal("matching probe completion produced no result")
	}
}

func checkProbeExporterVerdictMismatch(t *testing.T, fx *probeExporterVerdictFixture) {
	t.Helper()
	nonce := mitmProbeNonce{2}
	resultCh := fx.listener.mitmManager.reserveProbe(nonce)
	defer fx.listener.mitmManager.releaseProbe(nonce)
	fx.listener.mitmManager.attachExpected(nonce, bytes.Repeat([]byte{0xAB}, 32))
	fx.listener.mitmManager.completeProbe(nonce, bytes.Repeat([]byte{0xCD}, 32))
	select {
	case reason := <-resultCh:
		if reason != types.MITMProbeReasonExporterMismatch {
			t.Fatalf("probe reason = %q, want %q", reason, types.MITMProbeReasonExporterMismatch)
		}
	default:
		t.Fatal("mismatched probe completion produced no result")
	}
}

func checkProbeExporterVerdictUnarmed(t *testing.T, fx *probeExporterVerdictFixture) {
	t.Helper()
	nonce := mitmProbeNonce{3}
	resultCh := fx.listener.mitmManager.reserveProbe(nonce)
	defer fx.listener.mitmManager.releaseProbe(nonce)
	fx.listener.mitmManager.completeProbe(nonce, bytes.Repeat([]byte{0xAB}, 32))
	select {
	case reason := <-resultCh:
		if reason != types.MITMProbeReasonExporterMismatch {
			t.Fatalf("unarmed probe reason = %q, want %q", reason, types.MITMProbeReasonExporterMismatch)
		}
	default:
		t.Fatal("unarmed probe completion produced no result")
	}
}

func checkProbeIgnoresUnknownNonce(t *testing.T, fx *probeExporterVerdictFixture) {
	t.Helper()
	armed := bytes.Repeat([]byte{0xAB}, 32)
	nonce := mitmProbeNonce{4}
	resultCh := fx.listener.mitmManager.reserveProbe(nonce)
	defer fx.listener.mitmManager.releaseProbe(nonce)
	fx.listener.mitmManager.attachExpected(nonce, armed)
	fx.listener.mitmManager.completeProbe(mitmProbeNonce{5}, armed)
	fx.listener.mitmManager.completeProbe(nonce, armed)
	select {
	case reason := <-resultCh:
		if reason != "" {
			t.Fatalf("live probe reason = %q, want empty after an unknown nonce was dropped", reason)
		}
	default:
		t.Fatal("live probe completion produced no result")
	}
}

func TestMITMProbeCompletionClassifiesExporter(t *testing.T) {
	fx := newProbeExporterVerdictFixture()
	checkProbeExporterVerdictMatch(t, fx)
	checkProbeExporterVerdictMismatch(t, fx)
	checkProbeExporterVerdictUnarmed(t, fx)
	checkProbeIgnoresUnknownNonce(t, fx)
}

type bufferedConnPeekFixture struct {
	passthrough net.Conn
	payload     []byte
	peeked      []byte
	frameSize   int
	writeErr    chan error
}

func peekBufferedConnFrame(t *testing.T, reader *bufio.Reader, frameSize int) []byte {
	t.Helper()
	peeked, err := reader.Peek(frameSize)
	if err != nil {
		t.Fatalf("Peek() error = %v", err)
	}
	return peeked
}

func checkBufferedConnPassthrough(t *testing.T, fx *bufferedConnPeekFixture) {
	t.Helper()
	got := make([]byte, len(fx.payload))
	if _, err := io.ReadFull(fx.passthrough, got); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if !bytes.Equal(got, fx.payload) {
		t.Fatalf("passthrough payload = % x, want % x", got, fx.payload)
	}
	if !bytes.Equal(fx.peeked, fx.payload[:fx.frameSize]) {
		t.Fatalf("peeked frame = % x, want the probe nonce frame % x", fx.peeked, fx.payload[:fx.frameSize])
	}
	if err := <-fx.writeErr; err != nil {
		t.Fatalf("client Write() error = %v", err)
	}
}

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
	peeked := peekBufferedConnFrame(t, reader, frameSize)
	passthrough := wrapBufferedConn(server, reader)
	t.Cleanup(func() { _ = passthrough.Close() })

	checkBufferedConnPassthrough(t, &bufferedConnPeekFixture{
		passthrough: passthrough,
		payload:     payload,
		peeked:      peeked,
		frameSize:   frameSize,
		writeErr:    writeErr,
	})
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
	listener.mitmManager = newMITMManager(listener, true)

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
	listener.mitmManager = newMITMManager(listener, false)
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

type probeLoopCancelFixture struct {
	cancel       context.CancelFunc
	reverseReady chan struct{}
	done         chan struct{}
}

func newProbeLoopCancelFixture(t *testing.T) *probeLoopCancelFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	l := &listener{}
	l.readySessions.Store(1)
	manager := newMITMManager(l, false)
	reverseReady := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		manager.run(ctx, reverseReady)
	}()
	return &probeLoopCancelFixture{
		cancel:       cancel,
		reverseReady: reverseReady,
		done:         done,
	}
}

func (fx *probeLoopCancelFixture) signalProbeLoopCancelReady() {
	fx.reverseReady <- struct{}{}
}

func (fx *probeLoopCancelFixture) checkProbeLoopCancelRetained(t *testing.T) {
	t.Helper()
	synctest.Wait()
	synctest.Sleep(3 * defaultMITMProbeInterval)
	synctest.Wait()
	select {
	case <-fx.done:
		t.Fatal("probe loop exited before lease cancellation")
	default:
	}
}

func (fx *probeLoopCancelFixture) cancelProbeLoopAndCheckStopped(t *testing.T) {
	t.Helper()
	fx.cancel()
	synctest.Wait()
	select {
	case <-fx.done:
	default:
		t.Fatal("canceled lease retained its probe loop")
	}
}

func TestMITMProbeLoopLeaseCancellation(t *testing.T) {
	for _, ready := range []bool{false, true} {
		name := "before-reverse-ready"
		if ready {
			name = "after-failed-attempts"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				fx := newProbeLoopCancelFixture(t)
				defer fx.cancel()
				if ready {
					fx.signalProbeLoopCancelReady()
				}
				fx.checkProbeLoopCancelRetained(t)
				fx.cancelProbeLoopAndCheckStopped(t)
			})
		})
	}
}

func TestMITMProbeDialAddress(t *testing.T) {
	testCases := []struct {
		name     string
		relayURL string
		input    string
		want     string
	}{
		{name: "local relay uses relay host", relayURL: "https://localhost:4017", input: "https://bravo-gecko-disco.localhost:4017", want: "localhost:4017"},
		{name: "remote relay uses public URL", relayURL: "https://relay.example", input: "https://bravo-gecko-disco.example", want: "bravo-gecko-disco.example:443"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			relayURL, err := url.Parse(tc.relayURL)
			if err != nil {
				t.Fatalf("url.Parse() error = %v", err)
			}

			listener := &listener{
				api: &apiClient{relayURL: relayURL},
			}
			listener.mitmManager = newMITMManager(listener, false)

			got, err := listener.mitmManager.probeDialAddress(tc.input)
			if err != nil {
				t.Fatalf("probeDialAddress() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("probeDialAddress() = %q, want %q", got, tc.want)
			}
		})
	}
}

type stalledAdmissionFixture struct {
	listener *listener
	exporter []byte
}

func newStalledClientFixture(t *testing.T) *stalledAdmissionFixture {
	t.Helper()
	l := newChannelBindingListener(t, "9", "")
	l.accepted = make(chan net.Conn, 4)
	l.admitting = make(chan struct{}, 4)
	l.doneCh = make(chan struct{})
	l.api = &apiClient{relayURL: &url.URL{Scheme: "https", Host: "relay.example"}}
	return &stalledAdmissionFixture{
		listener: l,
		exporter: bytes.Repeat([]byte{0x42}, 32),
	}
}

func (fx *stalledAdmissionFixture) admitStalledClient(t *testing.T, first []byte) net.Conn {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	if len(first) > 0 {
		go func() { _, _ = clientRaw.Write(first) }()
	}
	fx.listener.admitting <- struct{}{}
	go fx.listener.admit(t.Context(), &testExporterConn{Conn: serverRaw, exported: fx.exporter})
	return clientRaw
}

func (fx *stalledAdmissionFixture) checkStalledClientAccept(t *testing.T, stalled, ordinary net.Conn) {
	t.Helper()
	start := time.Now()
	conn, err := fx.listener.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed >= mitmProbePeekTimeout {
		t.Fatalf("Accept() took %v behind a client that stalled; want it unaffected", elapsed)
	}
	first := make([]byte, len("GET /"))
	if _, err := io.ReadFull(conn, first); err != nil || string(first) != "GET /" {
		t.Fatalf("Accept() returned a connection that read %q, %v; want the ordinary client's request", first, err)
	}
	_ = conn.Close()
	_ = ordinary.Close()
	_ = stalled.Close()
}

func verifyStalledClientCase(t *testing.T, prefix []byte) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		fx := newStalledClientFixture(t)
		stalled := fx.admitStalledClient(t, prefix)
		synctest.Wait()
		ordinary := fx.admitStalledClient(t, []byte("GET / HTTP/1.1\r\n\r\n"))
		fx.checkStalledClientAccept(t, stalled, ordinary)
	})
}

func TestAcceptIsNotHeldUpByClientsThatStallDuringAdmission(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix []byte
	}{
		{"stalled channel binding request", []byte(types.TLSChannelBindingRequestMagic)},
		{"silent client", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifyStalledClientCase(t, tc.prefix)
		})
	}
}
