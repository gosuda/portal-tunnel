package sdk

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// TestMITMProbeCompletionClassifiesExporter covers the probe completion
// decision at the manager boundary, with no TLS peer: a completion matching
// the armed exporter passes, a differing one reports the exporter mismatch,
// a reservation that was never armed counts as a mismatch, and an unknown
// nonce is dropped without touching live reservations.
func TestMITMProbeCompletionClassifiesExporter(t *testing.T) {
	listener := &listener{}
	listener.mitmManager = newMITMManager(listener, false)

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
			listener.mitmManager = newMITMManager(listener, test.banMITM)

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

// Lease cancellation must join the loop both before reverse readiness and
// while waiting between failed attempts. Virtual time avoids network fixtures,
// production injection seams, and wall-clock waits for the retry interval.
func TestMITMProbeLoopLeaseCancellation(t *testing.T) {
	for _, ready := range []bool{false, true} {
		name := "before-reverse-ready"
		if ready {
			name = "after-failed-attempts"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				l := &listener{}
				l.readySessions.Store(1)
				manager := newMITMManager(l, false)
				manager.setResponderCapable(true)
				reverseReady := make(chan struct{}, 1)
				done := make(chan struct{})
				go func() {
					defer close(done)
					manager.run(ctx, reverseReady)
				}()
				if ready {
					// No API is configured, so each attempted probe fails
					// locally. The background worker must remain scheduled.
					reverseReady <- struct{}{}
				}
				synctest.Wait()
				synctest.Sleep(3 * defaultMITMProbeInterval)
				synctest.Wait()
				select {
				case <-done:
					t.Fatal("probe loop exited before lease cancellation")
				default:
				}
				cancel()
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("canceled lease retained its probe loop")
				}
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

type testExporterConn struct {
	net.Conn
	exported []byte
}

func (c *testExporterConn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	out := make([]byte, length)
	copy(out, c.exported)
	return out, nil
}

// fragmentingConn delivers each Write in two parts with a pause between them.
type fragmentingConn struct {
	*testExporterConn
	splitAt int
	pause   time.Duration
}

func (c *fragmentingConn) Write(p []byte) (int, error) {
	if c.splitAt <= 0 || c.splitAt >= len(p) {
		return c.testExporterConn.Write(p)
	}
	n, err := c.testExporterConn.Write(p[:c.splitAt])
	if err != nil {
		return n, err
	}
	synctest.Sleep(c.pause)
	m, err := c.testExporterConn.Write(p[c.splitAt:])
	return n + m, err
}

// newChannelBindingListener returns a listener able to answer channel binding
// requests for the canonical hostname of the identity derived from seed.
func newChannelBindingListener(t *testing.T, seed, hostname string) *listener {
	t.Helper()
	tunnelIdentity, err := identity.ResolveSecp256k1Identity(strings.Repeat(seed, 64))
	if err != nil {
		t.Fatal(err)
	}
	hostname = cmp.Or(hostname, canonicalTestHostname(t, tunnelIdentity.Address))
	l := &listener{
		identity: tunnelIdentity,
		lease:    utils.NewSnapshot(listenerSnapshot{hostname: hostname, accessToken: "test-access-token"}, listenerSnapshot.snapshot),
	}
	l.mitmManager = newMITMManager(l, true)
	l.mitmManager.setResponderCapable(true)
	return l
}

func canonicalTestHostname(t *testing.T, address string) string {
	t.Helper()
	hostname, err := utils.CanonicalLeaseHostname("myapp", address, "relay.example")
	if err != nil {
		t.Fatal(err)
	}
	return hostname
}

func TestTLSChannelBindingPassesOnHonestRelayAndPreservesAppTraffic(t *testing.T) {
	l := newChannelBindingListener(t, "1", "")
	canonicalHost := canonicalTestHostname(t, l.identity.Address)

	sharedExporter := bytes.Repeat([]byte{0x42}, 32)
	clientRaw, serverRaw := net.Pipe()
	clientConn := &testExporterConn{Conn: clientRaw, exported: sharedExporter}
	serverConn := &testExporterConn{Conn: serverRaw, exported: sharedExporter}

	serverDone := make(chan error, 1)
	go func() {
		nextConn, handled, err := l.mitmManager.maybeHandleConn(serverConn)
		if err != nil {
			serverDone <- err
			return
		}
		if handled {
			serverDone <- errors.New("channel binding conn was consumed instead of passed to application")
			return
		}
		defer nextConn.Close()
		var buf [4]byte
		if _, err := io.ReadFull(nextConn, buf[:]); err != nil {
			serverDone <- err
			return
		}
		if string(buf[:]) != "ping" {
			serverDone <- errors.New("unexpected application payload")
			return
		}
		_, err = nextConn.Write([]byte("pong"))
		serverDone <- err
	}()

	if err := VerifyTLSChannelBinding(context.Background(), clientConn, canonicalHost); err != nil {
		t.Fatalf("VerifyTLSChannelBinding() error = %v", err)
	}
	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatalf("client application write failed: %v", err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(clientConn, reply[:]); err != nil {
		t.Fatalf("client application read failed: %v", err)
	}
	if string(reply[:]) != "pong" {
		t.Fatalf("application reply = %q; want pong", string(reply[:]))
	}
	_ = clientConn.Close()
	if err := <-serverDone; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestTLSChannelBindingAbortsOnSelectiveRelayMITM(t *testing.T) {
	l := newChannelBindingListener(t, "2", "")
	canonicalHost := canonicalTestHostname(t, l.identity.Address)

	// Selective MITM: client-to-relay session has exporter Ec (0xAA), while
	// relay-to-tunnel session has a different exporter Et (0xBB).
	clientRaw, serverRaw := net.Pipe()
	clientConn := &testExporterConn{Conn: clientRaw, exported: bytes.Repeat([]byte{0xAA}, 32)}
	serverConn := &testExporterConn{Conn: serverRaw, exported: bytes.Repeat([]byte{0xBB}, 32)}

	go func() {
		nextConn, _, _ := l.mitmManager.maybeHandleConn(serverConn)
		if nextConn != nil {
			_ = nextConn.Close()
		}
	}()

	err := VerifyTLSChannelBinding(context.Background(), clientConn, canonicalHost)
	if err == nil || !strings.Contains(err.Error(), "exporter mismatch") {
		t.Fatalf("VerifyTLSChannelBinding() = %v; want exporter mismatch error", err)
	}
	// The client connection was aborted before any application data.
	if _, writeErr := clientConn.Write([]byte("secret")); writeErr == nil {
		t.Fatal("client connection remained writable after MITM abort")
	}
}

// A request may arrive split across TLS records, and the part after the
// recognized magic may arrive after the short sniff window. Both must still bind.
func TestTLSChannelBindingToleratesSplitRequest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		splitAt int
		pause   time.Duration
	}{
		{"magic split across records", 2, mitmProbePeekTimeout / 2},
		{"request body after the sniff window", len(types.TLSChannelBindingRequestMagic), 3 * mitmProbePeekTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l := newChannelBindingListener(t, "3", "")
				canonicalHost := canonicalTestHostname(t, l.identity.Address)
				exporter := bytes.Repeat([]byte{0x42}, 32)
				clientRaw, serverRaw := net.Pipe()
				client := &fragmentingConn{
					testExporterConn: &testExporterConn{Conn: clientRaw, exported: exporter},
					splitAt:          tc.splitAt,
					pause:            tc.pause,
				}
				server := &testExporterConn{Conn: serverRaw, exported: exporter}

				serverDone := make(chan error, 1)
				go func() {
					nextConn, handled, err := l.mitmManager.maybeHandleConn(server)
					if err == nil && handled {
						err = errors.New("channel binding conn was consumed instead of passed to application")
					}
					if err == nil {
						_ = nextConn.Close()
					}
					serverDone <- err
				}()

				if err := VerifyTLSChannelBinding(t.Context(), client, canonicalHost); err != nil {
					t.Fatalf("VerifyTLSChannelBinding() error = %v", err)
				}
				_ = client.Close()
				if err := <-serverDone; err != nil {
					t.Fatalf("server error = %v", err)
				}
			})
		})
	}
}

// A suppressed, garbled, or wrongly signed answer must abort the client with an
// error that says why, before any application data is sent.
func TestTLSChannelBindingFailsClosed(t *testing.T) {
	exporter := bytes.Repeat([]byte{0x42}, 32)
	for _, tc := range []struct {
		name    string
		respond func(t *testing.T, server net.Conn)
		wantErr string
	}{
		{
			name:    "suppressed answer",
			respond: func(t *testing.T, server net.Conn) { _ = server.Close() },
			wantErr: "read channel binding answer",
		},
		{
			name: "garbled signature",
			respond: func(t *testing.T, server net.Conn) {
				answer := append([]byte(types.TLSChannelBindingAnswerTag), exporter...)
				_, _ = server.Write(append(answer, make([]byte, types.TLSChannelBindingSignatureSize)...))
			},
			wantErr: "recover channel binding signer",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l := newChannelBindingListener(t, "4", "")
				canonicalHost := canonicalTestHostname(t, l.identity.Address)
				clientRaw, serverRaw := net.Pipe()
				client := &testExporterConn{Conn: clientRaw, exported: exporter}
				go func() {
					var request [types.TLSChannelBindingRequestSize]byte
					_, _ = io.ReadFull(serverRaw, request[:])
					tc.respond(t, serverRaw)
				}()

				err := VerifyTLSChannelBinding(t.Context(), client, canonicalHost)
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("VerifyTLSChannelBinding() = %v; want error containing %q", err, tc.wantErr)
				}
				if _, writeErr := client.Write([]byte("secret")); writeErr == nil {
					t.Fatal("client connection remained writable after the aborted exchange")
				}
			})
		})
	}

	t.Run("signed by another identity", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			owner := newChannelBindingListener(t, "5", "")
			canonicalHost := canonicalTestHostname(t, owner.identity.Address)
			// A relay-side responder holds its own key, not the tunnel's, but
			// answers for the tunnel's canonical hostname.
			impostor := newChannelBindingListener(t, "6", canonicalHost)
			clientRaw, serverRaw := net.Pipe()
			client := &testExporterConn{Conn: clientRaw, exported: exporter}
			server := &testExporterConn{Conn: serverRaw, exported: exporter}
			go func() {
				nextConn, _, _ := impostor.mitmManager.maybeHandleConn(server)
				if nextConn != nil {
					_ = nextConn.Close()
				}
			}()

			err := VerifyTLSChannelBinding(t.Context(), client, canonicalHost)
			if err == nil || !strings.Contains(err.Error(), "does not match canonical hostname identity") {
				t.Fatalf("VerifyTLSChannelBinding() = %v; want signer identity mismatch", err)
			}
		})
	})

	// Both sessions share one exporter, so only the client's fresh nonce can
	// tell the recorded answer from the one the client is waiting for.
	t.Run("replayed answer from an earlier exchange", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			l := newChannelBindingListener(t, "8", "")
			canonicalHost := canonicalTestHostname(t, l.identity.Address)
			recorded := recordChannelBindingAnswer(t, l, exporter)

			clientRaw, serverRaw := net.Pipe()
			client := &testExporterConn{Conn: clientRaw, exported: exporter}
			go func() {
				var request [types.TLSChannelBindingRequestSize]byte
				_, _ = io.ReadFull(serverRaw, request[:])
				_, _ = serverRaw.Write(recorded)
			}()

			err := VerifyTLSChannelBinding(t.Context(), client, canonicalHost)
			if err == nil || !strings.Contains(err.Error(), "does not match canonical hostname identity") {
				t.Fatalf("VerifyTLSChannelBinding() = %v; want signer identity mismatch", err)
			}
		})
	})
}

// A tunnel that does not offer binding, such as an older SDK or a cache
// exposure, hands the request to its application. The application's reply is
// no claim about the connection, so the client fails closed with an error that
// says the tunnel did not answer, never with an exporter mismatch that would
// accuse the relay.
func TestTLSChannelBindingReportsATunnelThatDoesNotAnswer(t *testing.T) {
	// What net/http writes for a request line it cannot parse.
	const httpBadRequest = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
	for _, tc := range []struct {
		name  string
		reply func(request []byte) []byte
	}{
		{"HTTP server rejecting the request", func([]byte) []byte { return []byte(httpBadRequest) }},
		{"application echoing the request", func(request []byte) []byte { return request }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				hostname := canonicalTestHostname(t, "0x1234567890abcdef1234567890abcdef12345678")
				clientRaw, serverRaw := net.Pipe()
				client := &testExporterConn{Conn: clientRaw, exported: bytes.Repeat([]byte{0x42}, 32)}
				go func() {
					request := make([]byte, types.TLSChannelBindingRequestSize)
					if _, err := io.ReadFull(serverRaw, request); err == nil {
						_, _ = serverRaw.Write(tc.reply(request))
					}
				}()

				err := VerifyTLSChannelBinding(t.Context(), client, hostname)
				if err == nil || !strings.Contains(err.Error(), "tunnel did not answer channel binding") || strings.Contains(err.Error(), "mismatch") {
					t.Fatalf("VerifyTLSChannelBinding() = %v; want a tunnel that did not answer, not a mismatch", err)
				}
				if _, writeErr := client.Write([]byte("secret")); writeErr == nil {
					t.Fatal("client connection remained writable after the unanswered exchange")
				}
				_ = serverRaw.Close()
			})
		})
	}
}

// recordChannelBindingAnswer plays the honest tunnel for one earlier client
// request and returns the answer frame a relay could have recorded from it.
func recordChannelBindingAnswer(t *testing.T, l *listener, exporter []byte) []byte {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	go func() {
		nextConn, _, _ := l.mitmManager.maybeHandleConn(&testExporterConn{Conn: serverRaw, exported: exporter})
		if nextConn != nil {
			_ = nextConn.Close()
		}
	}()
	request := append([]byte(types.TLSChannelBindingRequestMagic), bytes.Repeat([]byte{9}, types.TLSChannelBindingNonceSize)...)
	if _, err := clientRaw.Write(request); err != nil {
		t.Fatalf("write earlier request: %v", err)
	}
	answer := make([]byte, types.TLSChannelBindingAnswerSize)
	if _, err := io.ReadFull(clientRaw, answer); err != nil {
		t.Fatalf("read earlier answer: %v", err)
	}
	_ = clientRaw.Close()
	return answer
}

// A client that sends the start of a binding request and withholds the nonce
// holds an admitting slot without any credential, so the tunnel gives up on it
// after a short budget of its own, not the client's round-trip budget, while a
// request fragmented within that budget still binds (see
// TestTLSChannelBindingToleratesSplitRequest).
func TestAdmissionOfAWithheldBindingNonceEndsQuickly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := newChannelBindingListener(t, "a", "")
		l.accepted = make(chan net.Conn, 1)
		l.admitting = make(chan struct{}, 1)
		l.api = &apiClient{relayURL: &url.URL{Scheme: "https", Host: "relay.example"}}

		clientRaw, serverRaw := net.Pipe()
		go func() { _, _ = clientRaw.Write([]byte(types.TLSChannelBindingRequestMagic)) }()
		l.admitting <- struct{}{}
		go l.admit(t.Context(), &testExporterConn{Conn: serverRaw, exported: bytes.Repeat([]byte{0x42}, 32)})

		// The slot is held while the nonce is still due, and free well before the
		// client's own ten second budget would have run out.
		const slotCeiling = 2 * time.Second
		synctest.Sleep(channelBindingRequestTimeout / 2)
		select {
		case l.admitting <- struct{}{}:
			t.Fatal("the slot was free before the nonce was due")
		default:
		}
		synctest.Sleep(slotCeiling - channelBindingRequestTimeout/2)
		select {
		case l.admitting <- struct{}{}:
		default:
			t.Fatalf("a client withholding the nonce still holds its admitting slot after %v", slotCeiling)
		}
		_ = clientRaw.Close()
	})
}

// A client that sends a whole binding request and never reads the answer must
// not hold its admitting slot either.
func TestAdmissionOfAClientThatNeverReadsTheAnswerEndsQuickly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := newChannelBindingListener(t, "b", "")
		l.accepted = make(chan net.Conn, 1)
		l.admitting = make(chan struct{}, 1)
		l.api = &apiClient{relayURL: &url.URL{Scheme: "https", Host: "relay.example"}}

		clientRaw, serverRaw := net.Pipe()
		request := append([]byte(types.TLSChannelBindingRequestMagic), bytes.Repeat([]byte{7}, types.TLSChannelBindingNonceSize)...)
		go func() { _, _ = clientRaw.Write(request) }()
		l.admitting <- struct{}{}
		go l.admit(t.Context(), &testExporterConn{Conn: serverRaw, exported: bytes.Repeat([]byte{0x42}, 32)})

		const slotCeiling = 2 * time.Second
		synctest.Sleep(channelBindingRequestTimeout / 2)
		select {
		case l.admitting <- struct{}{}:
			t.Fatal("the slot was free while the answer was still being written")
		default:
		}
		synctest.Sleep(slotCeiling - channelBindingRequestTimeout/2)
		select {
		case l.admitting <- struct{}{}:
		default:
			t.Fatalf("a client that never reads the answer still holds its admitting slot after %v", slotCeiling)
		}
		_ = clientRaw.Close()
	})
}

// Accept is serial, so a client that is slow to speak must delay only itself.
// One that sends the start of a channel binding request and stops, and one that
// stays silent, are admitted off the accept path while an ordinary client is
// accepted at once.
func TestAcceptIsNotHeldUpByClientsThatStallDuringAdmission(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix []byte
	}{
		{"stalled channel binding request", []byte(types.TLSChannelBindingRequestMagic)},
		{"silent client", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l := newChannelBindingListener(t, "9", "")
				l.accepted = make(chan net.Conn, 4)
				l.admitting = make(chan struct{}, 4)
				l.doneCh = make(chan struct{})
				l.api = &apiClient{relayURL: &url.URL{Scheme: "https", Host: "relay.example"}}
				exporter := bytes.Repeat([]byte{0x42}, 32)

				// admit starts one client the way a reverse session does: it takes
				// an admitting slot and hands the connection to l.admit.
				admit := func(first []byte) net.Conn {
					clientRaw, serverRaw := net.Pipe()
					if len(first) > 0 {
						go func() { _, _ = clientRaw.Write(first) }()
					}
					l.admitting <- struct{}{}
					go l.admit(t.Context(), &testExporterConn{Conn: serverRaw, exported: exporter})
					return clientRaw
				}
				stalled := admit(tc.prefix)
				// The stalled client is now queued, or still being admitted, ahead
				// of the ordinary one.
				synctest.Wait()
				ordinary := admit([]byte("GET / HTTP/1.1\r\n\r\n"))

				start := time.Now()
				conn, err := l.Accept()
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
			})
		})
	}
}

// Channel binding shares the self-probe's capability boundary: a listener whose
// tenant TLS cannot export keying material, or a cache exposure where relay TLS
// termination is allowed, treats the request as ordinary application bytes.
func TestTLSChannelBindingIsNotServedOutsideResponderBoundary(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(l *listener)
	}{
		{"tenant tls cannot export keying material", func(l *listener) { l.mitmManager.setResponderCapable(false) }},
		{"cache exposure", func(l *listener) { l.cache = &cache.Source{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l := newChannelBindingListener(t, "7", "")
				tc.setup(l)
				request := append([]byte(types.TLSChannelBindingRequestMagic), bytes.Repeat([]byte{7}, types.TLSChannelBindingNonceSize)...)
				clientRaw, serverRaw := net.Pipe()
				go func() { _, _ = clientRaw.Write(request) }()

				nextConn, handled, err := l.mitmManager.maybeHandleConn(&testExporterConn{Conn: serverRaw, exported: bytes.Repeat([]byte{0x42}, 32)})
				if err != nil || handled {
					t.Fatalf("maybeHandleConn() = (handled %v, err %v); want the connection passed to the application", handled, err)
				}
				got := make([]byte, len(request))
				if _, err := io.ReadFull(nextConn, got); err != nil {
					t.Fatalf("read application bytes: %v", err)
				}
				if !bytes.Equal(got, request) {
					t.Fatalf("application received %x; want the untouched request %x", got, request)
				}
				_ = nextConn.Close()
			})
		})
	}
}
