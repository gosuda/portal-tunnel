package e2e_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// A raw TCP lease allocates one dedicated relay port and pipes plain bytes
// through the backhaul to the local service. The transport refactor moved
// this path between owners, so the data path itself is pinned here: port
// allocation on the relay, byte round trips in both directions, and a fresh
// connection after the first one closes.
func TestRawTCPPortRelay(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			testRawTCPPortRelay(t, host)
		})
	}
}

func testRawTCPPortRelay(t *testing.T, host string) {
	t.Helper()
	target, stopEcho := startTCPEcho(t, host)
	defer stopEcho()
	publicAddr, _, _ := startRawTCPTestTunnel(t, host, target)
	for round := range 2 {
		conn, err := net.DialTimeout("tcp", publicAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("round %d: dial relay TCP port: %v", round, err)
		}
		for i := range 3 {
			payload := []byte("rawtcp-" + strconv.Itoa(round) + "-" + strconv.Itoa(i))
			if _, err := conn.Write(payload); err != nil {
				_ = conn.Close()
				t.Fatalf("round %d: write %q: %v", round, payload, err)
			}
			echo := make([]byte, len(payload))
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(conn, echo); err != nil {
				_ = conn.Close()
				t.Fatalf("round %d: read echo: %v", round, err)
			}
			if string(echo) != string(payload) {
				_ = conn.Close()
				t.Fatalf("round %d: echo = %q, want %q", round, echo, payload)
			}
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("round %d: close conn: %v", round, err)
		}
	}
}

func startRawTCPTestTunnel(t *testing.T, host, target string) (string, *tunnel.Runtime, func()) {
	t.Helper()
	rawPort := harnessPort(t, host)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stateDir := t.TempDir()
	port := harnessPort(t, host)
	sniAddr := net.JoinHostPort(host, strconv.Itoa(port))
	relayURL := "https://" + sniAddr
	relay, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     relayURL,
		StateDir:      stateDir,
		SNIListenAddr: sniAddr,
		SNIPort:       port,
		MinPort:       rawPort,
		MaxPort:       rawPort,
	})
	if err != nil {
		cancel()
		t.Fatalf("create relay: %v", err)
	}
	if err := relay.SetTransportPolicy(false, 0, true, 0); err != nil {
		cancel()
		t.Fatalf("enable raw TCP transport: %v", err)
	}
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		cancel()
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = relay.Shutdown(shutdownCtx)
		_ = relay.Wait()
	})

	runtime, err := tunnel.Start(ctx, tunnel.Spec{
		Identity:  tunnel.IdentitySpec{Name: "rawtcp"},
		Relays:    tunnel.RelaySpec{URLs: []string{relayURL}},
		Transport: tunnel.TransportSpec{Target: target, TCP: true},
	})
	if err != nil {
		t.Fatalf("start raw TCP tunnel: %v", err)
	}
	proxyCtx, proxyCancel := context.WithCancel(ctx)
	proxyDone := make(chan error, 1)
	go func() { proxyDone <- runtime.Run(proxyCtx) }()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			proxyCancel()
			_ = runtime.Close()
			select {
			case err := <-proxyDone:
				if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
					t.Errorf("proxy raw TCP: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("raw TCP proxy did not stop")
			}
		})
	}
	t.Cleanup(stop)

	wctx, wcancel := context.WithTimeout(ctx, 60*time.Second)
	t.Cleanup(wcancel)
	ready, err := runtime.Exposure.WaitReady(wctx)
	if err != nil {
		t.Fatalf("wait for raw TCP lease: %v; relay statuses: %+v", err, runtime.Exposure.Relays())
	}
	var tcpAddr string
	for _, relay := range ready {
		if relay.TCPAddr != "" {
			tcpAddr = relay.TCPAddr
		}
	}
	if tcpAddr == "" {
		t.Fatalf("relay status %+v carries no TCP address", ready)
	}
	// Raw TCP routing is per allocated port, so tests dial the loopback
	// address behind the advertised host.
	_, leasePort, err := net.SplitHostPort(tcpAddr)
	if err != nil {
		t.Fatalf("split TCP address %q: %v", tcpAddr, err)
	}
	return net.JoinHostPort(host, leasePort), runtime, stop
}

// startTCPEcho runs a byte echo listener on loopback and returns its address.
func startTCPEcho(t *testing.T, host string) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		if host == "::1" {
			t.Skipf("IPv6 loopback is unavailable: %v", err)
		}
		t.Fatalf("listen echo target: %v", err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String(), func() { _ = listener.Close() }
}

func TestTCPProxyRequestHalfClose(t *testing.T) {
	origin, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	publicAddr, _, _ := startRawTCPTestTunnel(t, "127.0.0.1", origin.Addr().String())
	originDone := make(chan error, 1)
	go func() {
		conn, err := origin.AcceptTCP()
		if err != nil {
			originDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		request, err := io.ReadAll(conn)
		if err == nil {
			_, err = conn.Write(append([]byte("after-eof:"), request...))
		}
		originDone <- err
	}()
	client, err := net.DialTCP("tcp", nil, mustTCPAddr(t, publicAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "after-eof:request" {
		t.Fatalf("response = %q", response)
	}
	if err := <-originDone; err != nil {
		t.Fatal(err)
	}
}

func TestTCPProxyResponseHalfClosePreservesRequestUpload(t *testing.T) {
	origin, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	publicAddr, _, _ := startRawTCPTestTunnel(t, "127.0.0.1", origin.Addr().String())
	client, err := net.DialTCP("tcp", nil, mustTCPAddr(t, publicAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	_ = origin.SetDeadline(time.Now().Add(10 * time.Second))
	conn, err := origin.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("response-first")); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response-first" {
		t.Fatalf("response = %q", response)
	}
	// Receiving response EOF must not end the opposite direction. Only
	// now send the request, so a premature full close cannot pass by luck.
	if _, err := client.Write([]byte("request-after-response-eof")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(request) != "request-after-response-eof" {
		t.Fatalf("request = %q, want complete upload after response EOF", request)
	}
}

// Shutdown and public reset must propagate EOF to the origin. A public reset
// may reach the SDK as clean reverse EOF.
func TestTCPProxyOriginEOFOnShutdownOrPublicReset(t *testing.T) {
	for _, mode := range []string{"cancel", "exposure-close", "reset"} {
		t.Run(mode, func(t *testing.T) {
			for range 2 {
				origin, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = origin.Close() })
				publicAddr, runtime, stop := startRawTCPTestTunnel(t, "127.0.0.1", origin.Addr().String())
				client, err := net.DialTCP("tcp", nil, mustTCPAddr(t, publicAddr))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close() })
				if _, err := client.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
				_ = origin.SetDeadline(time.Now().Add(5 * time.Second))
				conn, err := origin.AcceptTCP()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = conn.Close() })
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var payload [1]byte
				if _, err := io.ReadFull(conn, payload[:]); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "cancel":
					stop()
				case "exposure-close":
					if err := runtime.Exposure.Close(); err != nil {
						t.Fatal(err)
					}
				case "reset":
					if err := client.SetLinger(0); err != nil {
						t.Fatal(err)
					}
					_ = client.Close()
				}
				if _, err := conn.Read(payload[:]); !errors.Is(err, io.EOF) {
					t.Fatalf("origin did not observe EOF after %s: %v", mode, err)
				}
				stop()
			}
		})
	}
}

func mustTCPAddr(t *testing.T, address string) *net.TCPAddr {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

type tcpLeaseHarness struct {
	t       *testing.T
	server  *portal.Server
	client  *http.Client
	base    *url.URL
	lease   types.RegisterResponse
	raw     string
	carrier string
	mux     *yamux.Session
}

func newTCPLeaseHarness(t *testing.T, carrier string) *tcpLeaseHarness {
	t.Helper()
	rawPort, port := harnessPort(t, "127.0.0.1"), harnessPort(t, "127.0.0.1")
	base, _ := url.Parse("https://127.0.0.1:" + strconv.Itoa(port))
	server, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     base.String(),
		StateDir:      t.TempDir(),
		SNIListenAddr: base.Host,
		SNIPort:       port,
		MinPort:       rawPort,
		MaxPort:       rawPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.SetTransportPolicy(false, 0, true, 0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	if err := server.Start(ctx, relayHandler(server, nil)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = server.Shutdown(shutdownCtx)
		_ = server.Wait()
	})
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	t.Cleanup(tr.CloseIdleConnections)
	h := &tcpLeaseHarness{
		t:       t,
		server:  server,
		client:  &http.Client{Transport: tr, Timeout: 10 * time.Second},
		base:    base,
		raw:     net.JoinHostPort("127.0.0.1", strconv.Itoa(rawPort)),
		carrier: carrier,
	}
	id, err := identity.Generate("lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	var challenge types.RegisterChallengeResponse
	if err := utils.HTTPDoAPIPath(ctx, h.client, base, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{Identity: id, TCPEnabled: true, TTL: 60}, nil, &challenge); err != nil {
		t.Fatal(err)
	}
	sig, err := identity.NewLocalAuthority(id).SignEthereumPersonalMessage(challenge.SIWEMessage)
	if err != nil {
		t.Fatal(err)
	}
	if err := utils.HTTPDoAPIPath(ctx, h.client, base, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{ChallengeID: challenge.ChallengeID, SIWEMessage: challenge.SIWEMessage, SIWESignature: sig}, nil, &h.lease); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *tcpLeaseHarness) openReverse() net.Conn {
	h.t.Helper()
	endpoint, err := url.Parse(h.lease.ReverseEndpoint.URL)
	if err != nil {
		h.t.Fatal(err)
	}
	if h.carrier == "native" {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", endpoint.Host, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			h.t.Fatal(err)
		}
		h.t.Cleanup(func() { _ = conn.Close() })
		req := &http.Request{Method: http.MethodGet, URL: endpoint, Host: endpoint.Host, Header: make(http.Header)}
		req.Header.Set(types.HeaderReverseCapability, h.lease.ReverseEndpoint.Capability)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "raw")
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := req.Write(conn); err != nil {
			h.t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			h.t.Fatal(err)
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			h.t.Fatalf("reverse upgrade status %d", resp.StatusCode)
		}
		_ = resp.Body.Close()
		_ = conn.SetDeadline(time.Time{})
		return conn
	}
	if h.mux == nil {
		endpoint.Scheme = "wss"
		socket, resp, err := websocket.Dial(h.t.Context(), endpoint.String(), &websocket.DialOptions{HTTPClient: h.client, Subprotocols: []string{types.ReverseSubprotocol, h.lease.ReverseEndpoint.Capability}})
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			h.t.Fatal(err)
		}
		config := yamux.DefaultConfig()
		config.LogOutput = io.Discard
		h.mux, err = yamux.Client(websocket.NetConn(context.Background(), socket, websocket.MessageBinary), config)
		if err != nil {
			h.t.Fatal(err)
		}
		h.t.Cleanup(func() { _ = h.mux.Close() })
	}
	stream, err := h.mux.OpenStream()
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = stream.Close() })
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	capability := []byte(h.lease.ReverseEndpoint.Capability)
	packet := make([]byte, 2+len(capability))
	binary.BigEndian.PutUint16(packet, uint16(len(capability)))
	copy(packet[2:], capability)
	if _, err := stream.Write(packet); err != nil {
		h.t.Fatal(err)
	}
	var status [1]byte
	if _, err := io.ReadFull(stream, status[:]); err != nil || status[0] != 0 {
		h.t.Fatalf("reverse capability status=%d err=%v", status[0], err)
	}
	_ = stream.SetDeadline(time.Time{})
	return stream
}

func (h *tcpLeaseHarness) connect() (*net.TCPConn, net.Conn) {
	h.t.Helper()
	reverse := h.openReverse()
	addr, err := net.ResolveTCPAddr("tcp", h.raw)
	if err != nil {
		h.t.Fatal(err)
	}
	public, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = public.Close() })
	if _, err := transport.ReadStart(h.t.Context(), reverse, 5*time.Second); err != nil {
		h.t.Fatal(err)
	}
	return public, reverse
}

func tcpLeaseRoundTrip(t *testing.T, public, reverse net.Conn) {
	t.Helper()
	_ = public.SetDeadline(time.Now().Add(5 * time.Second))
	_ = reverse.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := public.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	var request [7]byte
	if _, err := io.ReadFull(reverse, request[:]); err != nil || string(request[:]) != "request" {
		t.Fatalf("request %q: %v", request, err)
	}
	if _, err := reverse.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	var reply [5]byte
	if _, err := io.ReadFull(public, reply[:]); err != nil || string(reply[:]) != "reply" {
		t.Fatalf("reply %q: %v", reply, err)
	}
	_ = public.SetDeadline(time.Time{})
	_ = reverse.SetDeadline(time.Time{})
}

func TestTCPLeaseBridgeLifecycle(t *testing.T) {
	for _, carrier := range []string{"native", "websocket"} {
		for _, event := range []string{"unregister", "expiry", "deny", "shutdown"} {
			t.Run(carrier+"/"+event, func(t *testing.T) {
				h := newTCPLeaseHarness(t, carrier)
				public, reverse := h.connect()
				tcpLeaseRoundTrip(t, public, reverse)
				// Renewal extends the same lease and must leave its active bridge alive.
				var renewed types.RenewResponse
				if err := utils.HTTPDoAPIPath(t.Context(), h.client, h.base, http.MethodPost, types.PathSDKRenew, types.RenewRequest{AccessToken: h.lease.AccessToken, TTL: 60}, nil, &renewed); err != nil {
					t.Fatal(err)
				}
				h.lease.AccessToken = renewed.AccessToken
				tcpLeaseRoundTrip(t, public, reverse)
				revocationWait := 7 * time.Second
				switch event {
				case "unregister":
					if err := utils.HTTPDoAPIPath(t.Context(), h.client, h.base, http.MethodPost, types.PathSDKUnregister, types.UnregisterRequest{AccessToken: h.lease.AccessToken}, nil, nil); err != nil {
						t.Fatal(err)
					}
				case "expiry":
					// Expiry is enforced by the five-second registry janitor.
					revocationWait = 15 * time.Second
					if err := utils.HTTPDoAPIPath(t.Context(), h.client, h.base, http.MethodPost, types.PathSDKRenew, types.RenewRequest{AccessToken: h.lease.AccessToken, TTL: 1}, nil, &renewed); err != nil {
						t.Fatal(err)
					}
				case "deny":
					if !h.server.SetServiceIdentityAccess(h.lease.Identity.ServiceKey(), types.LeaseDenied, 1) {
						t.Fatal("deny rejected")
					}
				case "shutdown":
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					if err := h.server.Shutdown(ctx); err != nil {
						t.Fatal(err)
					}
				}
				for _, conn := range []net.Conn{public, reverse} {
					_ = conn.SetReadDeadline(time.Now().Add(revocationWait))
					var one [1]byte
					if _, err := conn.Read(one[:]); err == nil {
						t.Fatal("revoked bridge still delivered data")
					} else {
						var netErr net.Error
						if errors.As(err, &netErr) && netErr.Timeout() {
							t.Fatalf("%s retained active %s bridge: %v", event, carrier, err)
						}
					}
				}
				if event == "deny" {
					if !h.server.SetServiceIdentityAccess(h.lease.Identity.ServiceKey(), types.LeaseRoutable, 2) {
						t.Fatal("allow rejected")
					}
					fresh, backhaul := h.connect()
					tcpLeaseRoundTrip(t, fresh, backhaul)
				}
			})
		}
	}
}

func TestTCPLeaseBridgeResponseAfterHalfClose(t *testing.T) {
	for _, carrier := range []string{"native", "websocket"} {
		t.Run(carrier, func(t *testing.T) {
			h := newTCPLeaseHarness(t, carrier)
			public, reverse := h.connect()
			if _, err := public.Write([]byte("complete request")); err != nil {
				t.Fatal(err)
			}
			if err := public.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			_ = reverse.SetReadDeadline(time.Now().Add(5 * time.Second))
			request, err := io.ReadAll(reverse)
			if err != nil || string(request) != "complete request" {
				t.Fatalf("EOF request=%q err=%v", request, err)
			}
			if _, err := reverse.Write([]byte("after EOF")); err != nil {
				t.Fatal(err)
			}
			_ = public.SetReadDeadline(time.Now().Add(5 * time.Second))
			var reply [9]byte
			if _, err := io.ReadFull(public, reply[:]); err != nil || string(reply[:]) != "after EOF" {
				t.Fatalf("post-EOF reply=%q err=%v", reply, err)
			}
		})
	}
}

func TestTCPLeaseBoundsReverseWaitersAndRecovers(t *testing.T) {
	h := newTCPLeaseHarness(t, "native")
	var connections []net.Conn
	for range 160 {
		conn, err := net.DialTimeout("tcp", h.raw, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
		t.Cleanup(func() { _ = conn.Close() })
	}
	var workers sync.WaitGroup
	retained := make(chan bool, len(connections))
	for _, conn := range connections {
		workers.Go(func() {
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			var buf [1]byte
			_, err := conn.Read(buf[:])
			var netErr net.Error
			retained <- errors.As(err, &netErr) && netErr.Timeout()
		})
	}
	workers.Wait()
	close(retained)
	pending := 0
	for live := range retained {
		if live {
			pending++
		}
	}
	if pending != 128 {
		t.Fatalf("pending reverse waiters=%d, want bounded 128", pending)
	}
	h.server.SetServiceIdentityAccess(h.lease.Identity.ServiceKey(), types.LeaseDenied, 1)
	for _, conn := range connections {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var buf [1]byte
		_, err := conn.Read(buf[:])
		var netErr net.Error
		if err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
			t.Fatalf("denied waiter retained: %v", err)
		}
	}
	h.server.SetServiceIdentityAccess(h.lease.Identity.ServiceKey(), types.LeaseRoutable, 2)
	public, reverse := h.connect()
	tcpLeaseRoundTrip(t, public, reverse)
}
