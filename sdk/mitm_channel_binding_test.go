package sdk

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/namespace"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type testExporterConn struct {
	net.Conn
	exported []byte
}

func (c *testExporterConn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	out := make([]byte, length)
	copy(out, c.exported)
	return out, nil
}

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

func newChannelBindingListener(t *testing.T, seed, hostname string) *listener {
	t.Helper()
	tunnelIdentity, err := identity.ResolveSecp256k1Identity(strings.Repeat(seed, 64))
	if err != nil {
		t.Fatal(err)
	}
	hostname = cmp.Or(hostname, canonicalTestHostname(t, tunnelIdentity.Address))
	l := &listener{
		identity: tunnelIdentity,
		lease:    utils.NewSnapshot(listenerSnapshot{hostname: hostname, accessToken: "test-access-token"}),
	}
	l.mitmManager = newMITMManager(l, true)
	return l
}

func canonicalTestHostname(t *testing.T, address string) string {
	t.Helper()
	hostname, err := namespace.LegacyHostname("myapp", address, "relay.example")
	if err != nil {
		t.Fatal(err)
	}
	return hostname
}

type honestRelayBindingFixture struct {
	listener      *listener
	canonicalHost string
	clientConn    *testExporterConn
	serverDone    chan error
}

func startHonestRelayServer(t *testing.T, l *listener, serverConn *testExporterConn) chan error {
	t.Helper()
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
	return serverDone
}

func newHonestRelayFixture(t *testing.T, exporter []byte) *honestRelayBindingFixture {
	t.Helper()
	l := newChannelBindingListener(t, "1", "")
	canonicalHost := canonicalTestHostname(t, l.identity.Address)
	clientRaw, serverRaw := net.Pipe()
	clientConn := &testExporterConn{Conn: clientRaw, exported: exporter}
	serverDone := startHonestRelayServer(t, l, &testExporterConn{Conn: serverRaw, exported: exporter})
	return &honestRelayBindingFixture{
		listener:      l,
		canonicalHost: canonicalHost,
		clientConn:    clientConn,
		serverDone:    serverDone,
	}
}

func (fx *honestRelayBindingFixture) verifyHonestRelayBinding(t *testing.T) {
	t.Helper()
	if err := VerifyTLSChannelBinding(context.Background(), fx.clientConn, fx.canonicalHost); err != nil {
		t.Fatalf("VerifyTLSChannelBinding() error = %v", err)
	}
}

func (fx *honestRelayBindingFixture) exchangeHonestRelayAppTraffic(t *testing.T) {
	t.Helper()
	if _, err := fx.clientConn.Write([]byte("ping")); err != nil {
		t.Fatalf("client application write failed: %v", err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(fx.clientConn, reply[:]); err != nil {
		t.Fatalf("client application read failed: %v", err)
	}
	if string(reply[:]) != "pong" {
		t.Fatalf("application reply = %q; want pong", string(reply[:]))
	}
	_ = fx.clientConn.Close()
	if err := <-fx.serverDone; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestTLSChannelBindingPassesOnHonestRelayAndPreservesAppTraffic(t *testing.T) {
	exporter := bytes.Repeat([]byte{0x42}, 32)
	fx := newHonestRelayFixture(t, exporter)
	fx.verifyHonestRelayBinding(t)
	fx.exchangeHonestRelayAppTraffic(t)
}

func TestTLSChannelBindingAbortsOnSelectiveRelayMITM(t *testing.T) {
	l := newChannelBindingListener(t, "2", "")
	canonicalHost := canonicalTestHostname(t, l.identity.Address)

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

	if _, writeErr := clientConn.Write([]byte("secret")); writeErr == nil {
		t.Fatal("client connection remained writable after MITM abort")
	}
}

type splitRequestBindingFixture struct {
	listener      *listener
	canonicalHost string
	client        *fragmentingConn
	serverDone    chan error
}

func startSplitRequestServer(t *testing.T, l *listener, server *testExporterConn) chan error {
	t.Helper()
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
	return serverDone
}

func newSplitRequestFixture(t *testing.T, splitAt int, pause time.Duration) *splitRequestBindingFixture {
	t.Helper()
	l := newChannelBindingListener(t, "3", "")
	canonicalHost := canonicalTestHostname(t, l.identity.Address)
	exporter := bytes.Repeat([]byte{0x42}, 32)
	clientRaw, serverRaw := net.Pipe()
	client := &fragmentingConn{
		testExporterConn: &testExporterConn{Conn: clientRaw, exported: exporter},
		splitAt:          splitAt,
		pause:            pause,
	}
	serverDone := startSplitRequestServer(t, l, &testExporterConn{Conn: serverRaw, exported: exporter})
	return &splitRequestBindingFixture{
		listener:      l,
		canonicalHost: canonicalHost,
		client:        client,
		serverDone:    serverDone,
	}
}

func checkSplitRequestExchange(t *testing.T, fx *splitRequestBindingFixture) {
	t.Helper()
	if err := VerifyTLSChannelBinding(t.Context(), fx.client, fx.canonicalHost); err != nil {
		t.Fatalf("VerifyTLSChannelBinding() error = %v", err)
	}
	_ = fx.client.Close()
	if err := <-fx.serverDone; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func verifySplitRequestCase(t *testing.T, splitAt int, pause time.Duration) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		fx := newSplitRequestFixture(t, splitAt, pause)
		checkSplitRequestExchange(t, fx)
	})
}

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
			verifySplitRequestCase(t, tc.splitAt, tc.pause)
		})
	}
}

func verifyFailsClosedCase(t *testing.T, exporter []byte, respond func(t *testing.T, server net.Conn), wantErr string) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		l := newChannelBindingListener(t, "4", "")
		canonicalHost := canonicalTestHostname(t, l.identity.Address)
		clientRaw, serverRaw := net.Pipe()
		client := &testExporterConn{Conn: clientRaw, exported: exporter}
		go func() {
			var request [types.TLSChannelBindingRequestSize]byte
			_, _ = io.ReadFull(serverRaw, request[:])
			respond(t, serverRaw)
		}()

		if err := VerifyTLSChannelBinding(t.Context(), client, canonicalHost); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("VerifyTLSChannelBinding() = %v; want error containing %q", err, wantErr)
		}
		if _, writeErr := client.Write([]byte("secret")); writeErr == nil {
			t.Fatal("client connection remained writable after the aborted exchange")
		}
	})
}

func verifyFailsClosedForeignSigner(t *testing.T, exporter []byte) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		owner := newChannelBindingListener(t, "5", "")
		canonicalHost := canonicalTestHostname(t, owner.identity.Address)

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

		if err := VerifyTLSChannelBinding(t.Context(), client, canonicalHost); err == nil || !strings.Contains(err.Error(), "does not match canonical hostname identity") {
			t.Fatalf("VerifyTLSChannelBinding() = %v; want signer identity mismatch", err)
		}
	})
}

func verifyFailsClosedReplayedAnswer(t *testing.T, exporter []byte) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		l := newChannelBindingListener(t, "8", "")
		canonicalHost := canonicalTestHostname(t, l.identity.Address)
		recorded := recordChannelBindingAnswer(t, l, bytes.Repeat([]byte{0x11}, 32))

		clientRaw, serverRaw := net.Pipe()
		client := &testExporterConn{Conn: clientRaw, exported: exporter}
		go func() {
			var request [types.TLSChannelBindingRequestSize]byte
			_, _ = io.ReadFull(serverRaw, request[:])
			_, _ = serverRaw.Write(recorded)
		}()

		if err := VerifyTLSChannelBinding(t.Context(), client, canonicalHost); err == nil || !strings.Contains(err.Error(), "exporter mismatch") || strings.Contains(err.Error(), "signer") {
			t.Fatalf("VerifyTLSChannelBinding() = %v; want an exporter mismatch, not a signature error", err)
		}
	})
}

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
			verifyFailsClosedCase(t, exporter, tc.respond, tc.wantErr)
		})
	}

	t.Run("signed by another identity", func(t *testing.T) {
		verifyFailsClosedForeignSigner(t, exporter)
	})

	t.Run("replayed answer from an earlier session", func(t *testing.T) {
		verifyFailsClosedReplayedAnswer(t, exporter)
	})
}

func verifyUnansweredTunnelCase(t *testing.T, reply func(request []byte) []byte) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		hostname := canonicalTestHostname(t, "0x1234567890abcdef1234567890abcdef12345678")
		clientRaw, serverRaw := net.Pipe()
		client := &testExporterConn{Conn: clientRaw, exported: bytes.Repeat([]byte{0x42}, 32)}
		go func() {
			request := make([]byte, types.TLSChannelBindingRequestSize)
			if _, err := io.ReadFull(serverRaw, request); err == nil {
				_, _ = serverRaw.Write(reply(request))
			}
		}()

		if err := VerifyTLSChannelBinding(t.Context(), client, hostname); err == nil || !strings.Contains(err.Error(), "tunnel did not answer channel binding") || strings.Contains(err.Error(), "mismatch") {
			t.Fatalf("VerifyTLSChannelBinding() = %v; want a tunnel that did not answer, not a mismatch", err)
		}
		if _, writeErr := client.Write([]byte("secret")); writeErr == nil {
			t.Fatal("client connection remained writable after the unanswered exchange")
		}
		_ = serverRaw.Close()
	})
}

func TestTLSChannelBindingReportsATunnelThatDoesNotAnswer(t *testing.T) {
	const httpBadRequest = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
	for _, tc := range []struct {
		name  string
		reply func(request []byte) []byte
	}{
		{"HTTP server rejecting the request", func([]byte) []byte { return []byte(httpBadRequest) }},
		{"application echoing the request", func(request []byte) []byte { return request }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifyUnansweredTunnelCase(t, tc.reply)
		})
	}
}

func TestTLSChannelBindingReturnsWhenContextIsCanceled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hostname := canonicalTestHostname(t, "0x1234567890abcdef1234567890abcdef12345678")
		clientRaw, serverRaw := net.Pipe()
		client := &testExporterConn{Conn: clientRaw, exported: bytes.Repeat([]byte{0x42}, 32)}

		go func() { _, _ = io.Copy(io.Discard, serverRaw) }()
		const cancelAfter = 50 * time.Millisecond
		ctx, cancel := context.WithCancel(t.Context())
		time.AfterFunc(cancelAfter, cancel)

		start := time.Now()
		err := VerifyTLSChannelBinding(ctx, client, hostname)
		if elapsed := time.Since(start); elapsed > cancelAfter {
			t.Fatalf("VerifyTLSChannelBinding() returned %v after the context was canceled", elapsed-cancelAfter)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("VerifyTLSChannelBinding() = %v; want context.Canceled", err)
		}
		if _, writeErr := client.Write([]byte("secret")); writeErr == nil {
			t.Fatal("client connection remained writable after the canceled exchange")
		}
	})
}

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

func TestAdmissionOfAWithheldBindingNonceEndsQuickly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := newChannelBindingListener(t, "a", "")
		clientRaw, serverRaw := net.Pipe()
		defer clientRaw.Close()
		go func() {
			_, _, _ = l.mitmManager.maybeHandleConn(&testExporterConn{Conn: serverRaw, exported: bytes.Repeat([]byte{0x42}, 32)})
		}()
		go func() { _, _ = clientRaw.Write([]byte(types.TLSChannelBindingRequestMagic)) }()

		const budget = 2 * time.Second
		_ = clientRaw.SetReadDeadline(time.Now().Add(budget))
		if _, err := clientRaw.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("client read = %v; want the tunnel to close a withheld request within %v", err, budget)
		}
	})
}

func TestAdmissionOfAClientThatNeverReadsTheAnswerEndsQuickly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := newChannelBindingListener(t, "b", "")
		clientRaw, serverRaw := net.Pipe()
		defer clientRaw.Close()
		go func() {
			_, _, _ = l.mitmManager.maybeHandleConn(&testExporterConn{Conn: serverRaw, exported: bytes.Repeat([]byte{0x42}, 32)})
		}()
		request := append([]byte(types.TLSChannelBindingRequestMagic), bytes.Repeat([]byte{7}, types.TLSChannelBindingNonceSize)...)
		go func() { _, _ = clientRaw.Write(request) }()

		const budget = 2 * time.Second
		synctest.Sleep(budget)
		if n, err := clientRaw.Read(make([]byte, types.TLSChannelBindingAnswerSize)); !errors.Is(err, io.EOF) {
			t.Fatalf("client read after %v = %d bytes, %v; want the tunnel to have closed the connection", budget, n, err)
		}
	})
}

func openOutsideResponderServer(t *testing.T, request []byte) net.Conn {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	go func() { _, _ = clientRaw.Write(request) }()
	return serverRaw
}

func checkOutsideResponderPassthrough(t *testing.T, l *listener, request []byte, serverConn net.Conn) {
	t.Helper()
	nextConn, handled, err := l.mitmManager.maybeHandleConn(serverConn)
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
}

func TestTLSChannelBindingIsNotServedOutsideResponderBoundary(t *testing.T) {
	for _, tc := range []struct {
		name     string
		exporter bool
		cache    bool
	}{
		{name: "connection without exporter"},
		{name: "cache exposure", exporter: true, cache: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l := newChannelBindingListener(t, "7", "")
				if tc.cache {
					l.cache = &cache.Source{}
				}
				request := append([]byte(types.TLSChannelBindingRequestMagic), bytes.Repeat([]byte{7}, types.TLSChannelBindingNonceSize)...)
				serverRaw := openOutsideResponderServer(t, request)
				serverConn := serverRaw
				if tc.exporter {
					serverConn = &testExporterConn{Conn: serverRaw, exported: bytes.Repeat([]byte{0x42}, 32)}
				}
				checkOutsideResponderPassthrough(t, l, request, serverConn)
			})
		})
	}
}

func TestCanonicalBindingCoversSiblingNonceAndExporter(t *testing.T) {
	id, err := identity.Generate("blog")
	if err != nil {
		t.Fatal(err)
	}
	host, err := namespace.LocalTLSHostname("blog", id.Address, "relay.example")
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := namespace.LocalTLSHostname("api", id.Address, "relay.example")
	if err != nil {
		t.Fatal(err)
	}
	nonce, exporter := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	sig, err := signChannelBindingPayload(host, nonce, exporter, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyChannelBindingSigner(host, nonce, exporter, id.Address, sig); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, host      string
		nonce, exporter []byte
	}{
		{"sibling service", sibling, nonce, exporter},
		{"different nonce", host, bytes.Repeat([]byte{3}, 32), exporter},
		{"different TLS session", host, nonce, bytes.Repeat([]byte{4}, 32)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := verifyChannelBindingSigner(test.host, test.nonce, test.exporter, id.Address, sig); err == nil {
				t.Fatal("substituted binding accepted")
			}
		})
	}
}
