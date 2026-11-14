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

func TestRawTCPPortRelay(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			testRawTCPPortRelay(t, host)
		})
	}
}

func assertRawTCPMessageEcho(t *testing.T, conn net.Conn, round, i int) {
	t.Helper()
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

func assertRawTCPEchoRoundTrip(t *testing.T, publicAddr string, round int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", publicAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("round %d: dial relay TCP port: %v", round, err)
	}
	for i := range 3 {
		assertRawTCPMessageEcho(t, conn, round, i)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("round %d: close conn: %v", round, err)
	}
}

func testRawTCPPortRelay(t *testing.T, host string) {
	t.Helper()
	target, stopEcho := startTCPEcho(t, host)
	defer stopEcho()
	publicAddr, _, _ := startRawTCPTestTunnel(t, host, target)
	for round := range 2 {
		assertRawTCPEchoRoundTrip(t, publicAddr, round)
	}
}

func trackRawTCPRelayShutdown(t *testing.T, relay *portal.Server) {
	t.Helper()
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = relay.Shutdown(shutdownCtx)
		_ = relay.Wait()
	})
}

func bootRawTCPServer(t *testing.T, ctx context.Context, host string) string {
	t.Helper()
	rawPort := harnessPort(t, host)
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
		t.Fatalf("create relay: %v", err)
	}
	if err := relay.SetTransportPolicy(false, 0, true, 0); err != nil {
		t.Fatalf("enable raw TCP transport: %v", err)
	}
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		t.Fatalf("start relay: %v", err)
	}
	trackRawTCPRelayShutdown(t, relay)
	return relayURL
}

func proxyRawTCPTunnel(t *testing.T, ctx context.Context, runtime *tunnel.Runtime) func() {
	t.Helper()
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
	return stop
}

func awaitRawTCPPublicAddr(ctx context.Context, t *testing.T, runtime *tunnel.Runtime) string {
	t.Helper()
	ready, err := runtime.Exposure.WaitReady(ctx)
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
	_, leasePort, err := net.SplitHostPort(tcpAddr)
	if err != nil {
		t.Fatalf("split TCP address %q: %v", tcpAddr, err)
	}
	return leasePort
}

func startRawTCPTestTunnel(t *testing.T, host, target string) (string, *tunnel.Runtime, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	relayURL := bootRawTCPServer(t, ctx, host)

	runtime, err := tunnel.Start(ctx, tunnel.Spec{
		Identity:  tunnel.IdentitySpec{Name: "rawtcp"},
		Relays:    tunnel.RelaySpec{URLs: []string{relayURL}},
		Transport: tunnel.TransportSpec{Target: target, TCP: true},
	})
	if err != nil {
		t.Fatalf("start raw TCP tunnel: %v", err)
	}
	stop := proxyRawTCPTunnel(t, ctx, runtime)

	wctx, wcancel := context.WithTimeout(ctx, 60*time.Second)
	t.Cleanup(wcancel)
	return net.JoinHostPort(host, awaitRawTCPPublicAddr(wctx, t, runtime)), runtime, stop
}
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

func mustTCPAddr(t *testing.T, address string) *net.TCPAddr {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}
