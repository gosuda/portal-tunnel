package e2e_test

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestUDPOversizedPacketsDropWhole(t *testing.T) {
	origin, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	port, _, _ := startUDPTestTunnel(t, "127.0.0.1", "127.0.0.1", origin.LocalAddr().String())
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	for _, size := range []int{types.MaxUDPPayloadSize + 1, 4096} {
		if _, err := client.Write(bytes.Repeat([]byte("x"), size)); err != nil {
			t.Fatalf("send oversized packet (%d): %v", size, err)
		}
	}
	valid := bytes.Repeat([]byte("v"), types.MaxUDPPayloadSize)
	if _, err := client.Write(valid); err != nil {
		t.Fatal(err)
	}
	_ = origin.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 65535)
	n, peer, err := origin.ReadFromUDP(buf)
	if err != nil || !bytes.Equal(buf[:n], valid) {
		t.Fatalf("origin received oversized prefix or lost valid packet: size=%d err=%v", n, err)
	}
	// Enforce the same whole-packet limit on local-origin responses.
	if _, err := origin.WriteToUDP(bytes.Repeat([]byte("x"), 4096), peer); err != nil {
		t.Fatal(err)
	}
	if _, err := origin.WriteToUDP(valid, peer); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err = client.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], valid) {
		t.Fatalf("client received oversized prefix or lost valid reply: size=%d err=%v", n, err)
	}
}

func TestUDPRelayRestartIsolatesSenderSockets(t *testing.T) {
	origin, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	port, restart, _ := startUDPTestTunnel(t, "127.0.0.1", "127.0.0.1", origin.LocalAddr().String())
	dial := func() *net.UDPConn {
		t.Helper()
		client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		return client
	}
	oldSender := dial()
	if _, err := oldSender.Write([]byte("old sender")); err != nil {
		t.Fatal(err)
	}
	var buf [2048]byte
	_ = origin.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, oldPeer, err := origin.ReadFromUDP(buf[:])
	if err != nil || string(buf[:n]) != "old sender" {
		t.Fatalf("old sender did not reach origin: %q, %v", buf[:n], err)
	}
	restart()
	newSender := dial()
	// The surviving SDK re-registers asynchronously. Retry only new ingress
	// until its origin socket is observable, using the same public UDP port.
	var newPeer *net.UDPAddr
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := newSender.Write([]byte("new sender")); err != nil && !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatal(err)
		}
		_ = origin.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, newPeer, err = origin.ReadFromUDP(buf[:])
		if err == nil {
			break
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatal(err)
		}
	}
	if err != nil || string(buf[:n]) != "new sender" {
		t.Fatalf("new sender did not reach origin after restart: %q, %v", buf[:n], err)
	}
	if _, err := origin.WriteToUDP([]byte("delayed old reply"), oldPeer); err != nil {
		t.Fatal(err)
	}
	if _, err := origin.WriteToUDP([]byte("new reply"), newPeer); err != nil {
		t.Fatal(err)
	}
	_ = newSender.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err = newSender.Read(buf[:])
	if err != nil || string(buf[:n]) != "new reply" {
		t.Fatalf("new sender received stale reply or no reply: %q, %v", buf[:n], err)
	}
	_ = newSender.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, err := newSender.Read(buf[:]); err == nil {
		t.Fatalf("unexpected delayed reply crossed lease boundary: %q", buf[:n])
	} else {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatal(err)
		}
	}
}

func TestUDPProxyCloseReleasesOriginSocket(t *testing.T) {
	for attempt := range 3 {
		t.Run(strconv.Itoa(attempt), func(t *testing.T) {
			origin, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = origin.Close() })
			port, _, stop := startUDPTestTunnel(t, "127.0.0.1", "127.0.0.1", origin.LocalAddr().String())
			client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if _, err := client.Write([]byte("live socket")); err != nil {
				t.Fatal(err)
			}
			_ = origin.SetReadDeadline(time.Now().Add(10 * time.Second))
			var payload [64]byte
			n, peer, err := origin.ReadFromUDP(payload[:])
			if err != nil || string(payload[:n]) != "live socket" {
				t.Fatalf("origin did not observe live proxy socket: %q, %v", payload[:n], err)
			}
			stop()
			// Proxy completion must release its connected origin socket, not
			// merely stop accepting new frames while its reader remains alive.
			rebound, err := net.ListenUDP("udp4", peer)
			if err != nil {
				t.Fatalf("proxy close retained origin socket %s: %v", peer, err)
			}
			_ = rebound.Close()
		})
	}
}
