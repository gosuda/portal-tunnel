package e2e_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
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
	// One dedicated raw port outside the ephemeral range: the lease binds it
	// for the whole test, and the system's dynamic port range would collide
	// with ephemeral client sockets.
	target, stopEcho := startTCPEcho(t, host)
	defer stopEcho()
	rawPort := harnessPort(t, host)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
	t.Cleanup(func() {
		proxyCancel()
		_ = runtime.Close()
		select {
		case err := <-proxyDone:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("proxy raw TCP: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("raw TCP proxy did not stop")
		}
	})

	wctx, wcancel := context.WithTimeout(ctx, 60*time.Second)
	defer wcancel()
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
	for round := range 2 {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, leasePort), 5*time.Second)
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
