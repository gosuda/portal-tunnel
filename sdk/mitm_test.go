package sdk

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
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
	matchNonce := mitmProbeNonce{1}
	resultCh := listener.mitmManager.reserveProbe(matchNonce)
	defer listener.mitmManager.releaseProbe(matchNonce)
	listener.mitmManager.attachExpected(matchNonce, expected)
	listener.mitmManager.completeProbe(matchNonce, expected)
	select {
	case reason := <-resultCh:
		if reason != "" {
			t.Fatalf("probe reason = %q, want empty", reason)
		}
	default:
		t.Fatal("matching probe completion produced no result")
	}

	// Differing exporter value: exporter mismatch.
	mismatchNonce := mitmProbeNonce{2}
	resultCh = listener.mitmManager.reserveProbe(mismatchNonce)
	defer listener.mitmManager.releaseProbe(mismatchNonce)
	listener.mitmManager.attachExpected(mismatchNonce, bytes.Repeat([]byte{0xAB}, 32))
	listener.mitmManager.completeProbe(mismatchNonce, bytes.Repeat([]byte{0xCD}, 32))
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
	unarmedNonce := mitmProbeNonce{3}
	resultCh = listener.mitmManager.reserveProbe(unarmedNonce)
	defer listener.mitmManager.releaseProbe(unarmedNonce)
	listener.mitmManager.completeProbe(unarmedNonce, bytes.Repeat([]byte{0xAB}, 32))
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
	liveNonce := mitmProbeNonce{4}
	resultCh = listener.mitmManager.reserveProbe(liveNonce)
	defer listener.mitmManager.releaseProbe(liveNonce)
	listener.mitmManager.attachExpected(liveNonce, armed)
	listener.mitmManager.completeProbe(mitmProbeNonce{5}, armed)
	listener.mitmManager.completeProbe(liveNonce, armed)
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

// TestListenerBanMITMRequiresKeyingMaterialExporter pins the explicit
// startup failure for probe protection a relay cannot deliver: with
// ban-mitm requested, a tenant TLS stack without keying material export
// fails registration terminally instead of silently skipping the probe,
// while an exporting stack or an unset ban-mitm proceeds.
func TestListenerBanMITMRequiresKeyingMaterialExporter(t *testing.T) {
	relayURL, err := url.Parse("https://relay.example")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	for name, test := range map[string]struct {
		banMITM         bool
		exporterCapable bool
		wantErr         bool
	}{
		"ban mitm without exporter": {banMITM: true, exporterCapable: false, wantErr: true},
		"ban mitm with exporter":    {banMITM: true, exporterCapable: true},
		"no ban mitm":               {exporterCapable: false},
	} {
		t.Run(name, func(t *testing.T) {
			listener := &listener{
				api:      &apiClient{relayURL: relayURL},
				banMITM:  test.banMITM,
				identity: types.Identity{Name: "probe-guard"},
			}
			listener.mitmManager = newMITMManager(context.Background(), listener, test.banMITM)

			err := listener.ensureMITMProbeSupport(test.exporterCapable)
			if (err != nil) != test.wantErr {
				t.Fatalf("ensureMITMProbeSupport() error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr {
				return
			}
			if !errors.Is(err, errRelayIncompatible) {
				t.Fatalf("ensureMITMProbeSupport() error = %v, want errRelayIncompatible", err)
			}
			if !listener.closeForTerminalRelayError(err) {
				t.Fatal("ban-mitm capability error was not treated as terminal")
			}
			for _, fragment := range []string{"--ban-mitm", "does not export keying material", "remove the ban-mitm option"} {
				if !strings.Contains(err.Error(), fragment) {
					t.Fatalf("error %q missing fragment %q", err, fragment)
				}
			}
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
			listener.mitmManager = newMITMManager(context.Background(), listener, false)

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
