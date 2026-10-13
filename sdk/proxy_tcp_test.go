package sdk

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestTCPProxyCapacityAndJoinedShutdown(t *testing.T) {
	target, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	ingress, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	exposure := &Exposure{done: ctx.Done(), cancel: cancel, accepted: make(chan net.Conn)}
	defer exposure.Close()
	done := make(chan error, 1)
	go func() { done <- proxyRelayConnections(ctx, exposure, target.Addr().String()) }()
	clients := make([]*net.TCPConn, 0, types.DefaultSDKMaxTCPConnections)
	origins := make([]*net.TCPConn, 0, types.DefaultSDKMaxTCPConnections)
	for range types.DefaultSDKMaxTCPConnections {
		client, err := net.DialTCP("tcp", nil, ingress.Addr().(*net.TCPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		relay, err := ingress.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		exposure.accepted <- relay
		_ = target.SetDeadline(time.Now().Add(5 * time.Second))
		origin, err := target.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		defer origin.Close()
		clients = append(clients, client)
		origins = append(origins, origin)
	}
	overflow, err := net.DialTCP("tcp", nil, ingress.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer overflow.Close()
	relay, err := ingress.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	exposure.accepted <- relay
	_ = overflow.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := overflow.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("overflow should close promptly: %v", err)
	}
	if _, err := clients[0].Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = origins[0].SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(origins[0], b[:]); err != nil || b[0] != 'x' {
		t.Fatalf("existing flow failed at capacity: %q %v", b, err)
	}
	if err := exposure.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy workers did not join")
	}
	for _, origin := range origins {
		_ = origin.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := origin.Read(b[:]); !errors.Is(err, io.EOF) {
			t.Fatalf("local socket survived shutdown: %v", err)
		}
	}
}

func TestTCPProxyCancellationInterruptsFailureResponse(t *testing.T) {
	// net.Pipe is the owned stream endpoint here. With an unavailable target
	// the 503 write blocks until cancellation closes it; no peer read is needed.
	relay, peer := net.Pipe()
	defer peer.Close()
	unavailable, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := unavailable.Addr().String()
	_ = unavailable.Close()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- proxyConnection(ctx, target, relay) }()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	var firstByte [1]byte
	if _, err := peer.Read(firstByte[:]); err != nil {
		cancel()
		t.Fatal(err)
	}
	if firstByte[0] != 'H' {
		cancel()
		t.Fatalf("unexpected response byte %q", firstByte)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed-dial response survived cancellation")
	}
}
