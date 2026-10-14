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

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

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
	server, err := portal.NewServer(portal.ServerConfig{PortalURL: base.String(), StateDir: t.TempDir(), SNIListenAddr: base.Host, SNIPort: port, MinPort: rawPort, MaxPort: rawPort})
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
	h := &tcpLeaseHarness{t: t, server: server, client: &http.Client{Transport: tr, Timeout: 10 * time.Second}, base: base, raw: net.JoinHostPort("127.0.0.1", strconv.Itoa(rawPort)), carrier: carrier}
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
			h.t.Fatalf("reverse upgrade status%d", resp.StatusCode)
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
	cap := []byte(h.lease.ReverseEndpoint.Capability)
	packet := make([]byte, 2+len(cap))
	binary.BigEndian.PutUint16(packet, uint16(len(cap)))
	copy(packet[2:], cap)
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
					if !h.server.SetServiceIdentityRoutable(h.lease.Identity.ServiceKey(), false, 1) {
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
					if !h.server.SetServiceIdentityRoutable(h.lease.Identity.ServiceKey(), true, 2) {
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
		t.Fatalf("pending reverse waiters=%d, want bounded128", pending)
	}
	h.server.SetServiceIdentityRoutable(h.lease.Identity.ServiceKey(), false, 1)
	for _, conn := range connections {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var buf [1]byte
		_, err := conn.Read(buf[:])
		var netErr net.Error
		if err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
			t.Fatalf("denied waiter retained: %v", err)
		}
	}
	h.server.SetServiceIdentityRoutable(h.lease.Identity.ServiceKey(), true, 2)
	public, reverse := h.connect()
	tcpLeaseRoundTrip(t, public, reverse)
}
