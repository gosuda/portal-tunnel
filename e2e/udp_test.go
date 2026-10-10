package e2e_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/portal"
)

func TestUDPPortRelay(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			testUDPPortRelay(t, host, host, host)
		})
	}
}

// Exercise real UDP ingress, authenticated QUIC backhaul, the local UDP
// origin, and the response path. The advertised relay name can differ from
// its bind address so DNS fallback uses the same end-to-end contract.
func testUDPPortRelay(t *testing.T, relayHost, relayName, originHost string) {
	t.Helper()
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(originHost)})
	if err != nil {
		if originHost == "::1" {
			t.Skipf("IPv6 loopback is unavailable: %v", err)
		}
		t.Fatalf("listen UDP origin: %v", err)
	}
	originDone := make(chan struct{})
	go func() {
		defer close(originDone)
		var payload [2048]byte
		for {
			n, peer, err := origin.ReadFromUDP(payload[:])
			if err != nil {
				return
			}
			if _, err := origin.WriteToUDP(payload[:n], peer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = origin.Close()
		<-originDone
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	udpPort := harnessPort(t, relayHost)
	port := harnessPort(t, relayHost)
	relayURL := "https://" + net.JoinHostPort(relayName, strconv.Itoa(port))
	relay, err := portal.NewServer(portal.ServerConfig{
		PortalURL:     relayURL,
		StateDir:      t.TempDir(),
		SNIListenAddr: net.JoinHostPort(relayHost, strconv.Itoa(port)),
		SNIPort:       port,
		MinPort:       udpPort,
		MaxPort:       udpPort,
	})
	if err != nil {
		t.Fatalf("create UDP relay: %v", err)
	}
	if err := relay.SetTransportPolicy(true, 0, false, 0); err != nil {
		t.Fatalf("enable UDP transport: %v", err)
	}
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		t.Fatalf("start UDP relay: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := relay.Shutdown(shutdownCtx); err != nil {
			t.Errorf("shutdown UDP relay: %v", err)
		}
		if err := relay.Wait(); err != nil {
			t.Errorf("wait for UDP relay: %v", err)
		}
	})

	runtime, err := tunnel.Start(ctx, tunnel.Spec{
		Identity: tunnel.IdentitySpec{Name: "udp"},
		Relays:   tunnel.RelaySpec{URLs: []string{relayURL}},
		Transport: tunnel.TransportSpec{
			Target: origin.LocalAddr().String(),
			UDP:    &tunnel.UDPConfig{},
		},
	})
	if err != nil {
		t.Fatalf("start UDP tunnel: %v", err)
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
				t.Errorf("proxy UDP: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("UDP proxy did not stop")
		}
	})

	readyCtx, readyCancel := context.WithTimeout(ctx, 30*time.Second)
	defer readyCancel()
	ready, err := runtime.Exposure.WaitDatagramReady(readyCtx)
	if err != nil || len(ready) == 0 {
		t.Fatalf("wait for UDP backhaul: %v; relay statuses: %+v", err, runtime.Exposure.Relays())
	}
	_, portText, err := net.SplitHostPort(ready[0].UDPAddr)
	if err != nil {
		t.Fatalf("split public UDP address %q: %v", ready[0].UDPAddr, err)
	}
	publicPort, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse public UDP port %q: %v", portText, err)
	}
	for client := range 2 {
		conn, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(relayHost)}, &net.UDPAddr{IP: net.ParseIP(relayHost), Port: publicPort})
		if err != nil {
			t.Fatalf("dial UDP ingress: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		for message := range 3 {
			payload := []byte("udp-" + strconv.Itoa(client) + "-" + strconv.Itoa(message))
			if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("send UDP payload: %v", err)
			}
			var reply [2048]byte
			n, err := conn.Read(reply[:])
			if err != nil {
				t.Fatalf("read UDP reply: %v", err)
			}
			if string(reply[:n]) != string(payload) {
				t.Fatalf("UDP reply = %q, want %q", reply[:n], payload)
			}
		}
	}
}
