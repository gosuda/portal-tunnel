package e2e_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/portal"
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
