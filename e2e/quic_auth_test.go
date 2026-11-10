package e2e_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/gosuda/portal-tunnel/v2/portal"
)

func startQUICRelay(t *testing.T, ctx context.Context) (*portal.Server, string) {
	t.Helper()
	port := harnessPort(t, "127.0.0.1")
	leasePort := harnessPort(t, "127.0.0.1")
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	relay, err := portal.NewServer(portal.ServerConfig{PortalURL: "https://" + addr, StateDir: t.TempDir(), SNIListenAddr: addr, SNIPort: port, MinPort: leasePort, MaxPort: leasePort})
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.SetTransportPolicy(true, 0, false, 0); err != nil {
		t.Fatal(err)
	}
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := relay.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
		if err := relay.Wait(); err != nil {
			t.Error(err)
		}
	})
	return relay, addr
}

func dialQUICFrom(t *testing.T, ctx context.Context, addr, sourceIP string) *quic.Conn {
	t.Helper()
	server, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(sourceIP)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpConn.Close() })
	dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	defer dialCancel()
	peer, err := quic.Dial(dialCtx, udpConn, server, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"portal-tunnel"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.CloseWithError(0, "test complete") })
	return peer
}

func TestQUICPendingAuthenticationBoundAndShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	relay, addr := startQUICRelay(t, ctx)

	var peers []*quic.Conn
	for source := 1; source <= 16; source++ {
		for i := 0; i < 4; i++ {
			peers = append(peers, dialQUICFrom(t, ctx, addr, fmt.Sprintf("127.0.0.%d", source)))
		}
		if len(peers) == 8 {
			stream, err := peers[1].OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Write([]byte(`{"access_token":"`)); err != nil {
				t.Fatal(err)
			}
		}
	}
	extra := dialQUICFrom(t, ctx, addr, "127.0.0.17")
	select {
	case <-extra.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("connection beyond pending-auth capacity remained open")
	}
	for i, peer := range peers {
		if err := peer.Context().Err(); err != nil {
			t.Fatalf("pending connection %d closed early: %v", i, context.Cause(peer.Context()))
		}
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := relay.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	if err := relay.Wait(); err != nil {
		t.Fatal(err)
	}
	for i, peer := range peers {
		select {
		case <-peer.Context().Done():
		case <-shutdownCtx.Done():
			t.Fatalf("shutdown left pending connection %d open", i)
		}
	}
}

func TestQUICPendingAuthPerSourceBoundAndTimeoutRelease(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	_, addr := startQUICRelay(t, ctx)

	var held []*quic.Conn
	for i := 0; i < 4; i++ {
		held = append(held, dialQUICFrom(t, ctx, addr, "127.0.0.1"))
	}
	fifth := dialQUICFrom(t, ctx, addr, "127.0.0.1")
	select {
	case <-fifth.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("connection beyond per-source pending-auth capacity remained open")
	}
	other := dialQUICFrom(t, ctx, addr, "127.0.0.2")
	select {
	case <-other.Context().Done():
		t.Fatalf("another source was rejected under its own cap: %v", context.Cause(other.Context()))
	case <-time.After(500 * time.Millisecond):
	}
	for i, peer := range held {
		select {
		case <-peer.Context().Done():
		case <-time.After(6 * time.Second):
			t.Fatalf("authentication timeout left held connection %d open", i)
		}
	}
	reacquired := dialQUICFrom(t, ctx, addr, "127.0.0.1")
	select {
	case <-reacquired.Context().Done():
		t.Fatalf("released source could not reacquire a slot: %v", context.Cause(reacquired.Context()))
	case <-time.After(500 * time.Millisecond):
	}
}
