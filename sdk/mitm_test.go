package sdk

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/url"
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
