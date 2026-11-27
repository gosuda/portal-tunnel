package e2e_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
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

func dialPendingPeers(t *testing.T, ctx context.Context, addr string) []*quic.Conn {
	t.Helper()
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
	return peers
}

func dialExtraUntilRejected(t *testing.T, ctx context.Context, addr string) []*quic.Conn {
	t.Helper()
	// The relay admits connections in handshake-completion order, which can
	// lag behind dial order while the host is busy. An extra connection
	// dialed before the relay has observed all 64 pending peers is admitted
	// instead of rejected. Retry with a fresh source address until a
	// rejection is observed; each address is used once so only the global
	// bound can close the probe.
	var held []*quic.Conn
	for attempt := 0; attempt < 5; attempt++ {
		extra := dialQUICFrom(t, ctx, addr, fmt.Sprintf("127.0.0.%d", 17+attempt))
		select {
		case <-extra.Context().Done():
			if isBoundRejection(extra) {
				return held
			}
			// Admitted, then lost before the bound closed it (its
			// authentication timer fired): its slot is already released,
			// so it proves nothing. Keep probing.
			continue
		case <-time.After(2 * time.Second):
		}
		// Admitted and still held: keep it open so its pending slot stays
		// occupied. Closing it before the next probe would free a slot, and
		// a later rejection would no longer prove the bound is exactly 64.
		held = append(held, extra)
	}
	t.Fatal("connection beyond pending-auth capacity remained open")
	return nil
}

// isBoundRejection reports whether the relay closed the connection for
// lack of pending-auth capacity, rather than the connection timing out or
// failing another way after admission. The busy and timeout paths share
// close code 1 (see runQUICBackhaulListener and handleQUICBackhaulConn in
// portal/server.go), so the reason has to carry the distinction. Match the
// stable concept word instead of the full sentence, so rewording the
// sentence alone cannot flip the classification without changing behavior.
func isBoundRejection(conn *quic.Conn) bool {
	_, err := conn.OpenStreamSync(context.Background())
	var appErr *quic.ApplicationError
	if !errors.As(err, &appErr) {
		return false
	}
	return appErr.Remote && appErr.ErrorCode == 1 && strings.Contains(appErr.ErrorMessage, "busy")
}

// assertPendingBoundExact requires the relay to hold exactly the dialed
// peers and nothing more: a rejection observed while an admitted probe was
// already closed would also pass with the bound one slot too wide.
func assertPendingBoundExact(t *testing.T, peers, held []*quic.Conn) {
	t.Helper()
	live := 0
	for _, conn := range peers {
		if conn.Context().Err() == nil {
			live++
		}
	}
	for _, conn := range held {
		if conn.Context().Err() == nil {
			live++
		}
	}
	if live != len(peers) {
		t.Fatalf("live pending connections = %d, want exactly %d", live, len(peers))
	}
}

func assertPeersAlive(t *testing.T, peers []*quic.Conn) {
	t.Helper()
	for i, peer := range peers {
		if err := peer.Context().Err(); err != nil {
			t.Fatalf("pending connection %d closed early: %v", i, context.Cause(peer.Context()))
		}
	}
}

func shutdownRelayAndAssertClosed(t *testing.T, relay *portal.Server, peers []*quic.Conn) {
	t.Helper()
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

func TestQUICPendingAuthenticationBoundAndShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	relay, addr := startQUICRelay(t, ctx)

	peers := dialPendingPeers(t, ctx, addr)
	held := dialExtraUntilRejected(t, ctx, addr)
	assertPeersAlive(t, peers)
	assertPendingBoundExact(t, peers, held)
	shutdownRelayAndAssertClosed(t, relay, append(peers, held...))
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
