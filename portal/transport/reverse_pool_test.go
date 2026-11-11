package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestReserveOfferCommitsProtocolAckBeforeClaimMarker(t *testing.T) {
	relay := NewReversePool(time.Minute, 1)
	t.Cleanup(relay.Close)
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	ack := startReserveAckReader(t, client)
	reservation, err := relay.ReserveOffer(server)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	claimed := startReserveClaim(ctx, t, relay)
	commitReserveOffer(t, server, reservation)
	verifyReserveAckClaim(t, client, ack, claimed)
}

func startReserveAckReader(t *testing.T, client net.Conn) <-chan byte {
	t.Helper()
	ack := make(chan byte, 1)
	go func() {
		var value [1]byte
		_, _ = client.Read(value[:])
		ack <- value[0]
	}()
	return ack
}

func startReserveClaim(ctx context.Context, t *testing.T, relay *ReversePool) <-chan net.Conn {
	t.Helper()
	claimed := make(chan net.Conn, 1)
	go func() {
		conn, err := relay.Acquire(ctx)
		if err == nil {
			_ = WriteTLSStart(conn, [16]byte{})
		}
		claimed <- conn
	}()
	return claimed
}

func commitReserveOffer(t *testing.T, server net.Conn, reservation *offerReservation) {
	t.Helper()
	if _, err := server.Write([]byte{7}); err != nil {
		t.Fatal(err)
	}
	if err := reservation.Commit(); err != nil {
		t.Fatal(err)
	}
}

func verifyReserveAckClaim(t *testing.T, client net.Conn, ack <-chan byte, claimed <-chan net.Conn) {
	t.Helper()
	if got := <-ack; got != 7 {
		t.Fatalf("protocol acknowledgement = %d", got)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var frame [1 + types.TLSBindingSize]byte
	if _, err := io.ReadFull(client, frame[:]); err != nil {
		t.Fatalf("read claim frame: %v", err)
	}
	if frame[0] != types.ReverseMarkerTLSStart {
		t.Fatalf("claim marker = %d", frame[0])
	}
	conn := <-claimed
	if conn == nil {
		t.Fatal("accepted offer was not acquired")
	}
	_ = conn.Close()
}

func TestTLSBindingFramingRoundTrip(t *testing.T) {
	relay := NewReversePool(time.Minute, 1)
	t.Cleanup(relay.Close)
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	offerTLSBindingFramingRoundTrip(t, relay, serverConn)

	binding := [16]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	claimed, claimErr := startBindingClaim(t, relay, binding)
	verifyBindingRoundTrip(t, clientConn, binding, claimed, claimErr)
}

func offerTLSBindingFramingRoundTrip(t *testing.T, relay *ReversePool, serverConn net.Conn) {
	t.Helper()
	if err := relay.Offer(serverConn); err != nil {
		t.Fatal(err)
	}
}

func startBindingClaim(t *testing.T, relay *ReversePool, binding [16]byte) (<-chan net.Conn, <-chan error) {
	t.Helper()
	claimed := make(chan net.Conn, 1)
	claimErr := make(chan error, 1)
	go func() {
		conn, err := relay.Acquire(context.Background())
		if err != nil {
			claimErr <- err
			return
		}
		if err := WriteTLSStart(conn, binding); err != nil {
			_ = conn.Close()
			claimErr <- err
			return
		}
		claimed <- conn
	}()
	return claimed, claimErr
}

func verifyBindingRoundTrip(t *testing.T, clientConn net.Conn, binding [16]byte, claimed <-chan net.Conn, claimErr <-chan error) {
	t.Helper()
	gotBinding, err := ReadStart(context.Background(), clientConn, time.Second)
	if err != nil {
		t.Fatalf("RunSession: %v", err)
	}
	if !bytes.Equal(gotBinding, binding[:]) {
		t.Fatalf("session binding = %#x, want %#x", gotBinding, binding[:])
	}
	select {
	case conn := <-claimed:
		_ = conn.Close()
	case err := <-claimErr:
		t.Fatalf("Claim: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Claim did not complete")
	}
}

func TestReversePoolCloseReleasesAllAcquirers(t *testing.T) {
	pool := NewReversePool(time.Minute, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	results := make(chan error, 8)
	for range cap(results) {
		go func() {
			_, err := pool.Acquire(ctx)
			results <- err
		}()
	}
	pool.Close()
	for range cap(results) {
		if err := <-results; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Acquire after shutdown: %v", err)
		}
	}
}

func TestReversePoolCommittedReservationSurvivesConcurrentClose(t *testing.T) {
	_, _, peer, reservation, closed := setupReservationRace(t)
	if err := reservation.Commit(); err != nil {
		t.Fatalf("acknowledged reservation could not commit: %v", err)
	}
	reservation.Cancel()
	awaitPoolClosed(t, closed)
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("committed connection survived pool close")
	}
}

func TestReversePoolCanceledReservationSurvivesConcurrentClose(t *testing.T) {
	_, conn, _, reservation, closed := setupReservationRace(t)
	reservation.Cancel()
	reservation.Cancel()
	awaitPoolClosed(t, closed)
	if err := conn.SetDeadline(time.Now()); err != nil {
		t.Fatalf("cancellation closed caller-owned connection: %v", err)
	}
}

func setupReservationRace(t *testing.T) (*ReversePool, net.Conn, net.Conn, *offerReservation, chan struct{}) {
	t.Helper()
	pool := NewReversePool(time.Minute, 1)
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = conn.Close() })
	t.Cleanup(func() { _ = peer.Close() })
	reservation, err := pool.ReserveOffer(conn)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { pool.Close(); close(closed) }()
	return pool, conn, peer, reservation, closed
}

func awaitPoolClosed(t *testing.T, closed <-chan struct{}) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after reservation resolution")
	}
}

func TestReversePoolAcquireTransfersUnframedConnection(t *testing.T) {
	pool := NewReversePool(time.Minute, 1)
	defer pool.Close()
	conn, peer := net.Pipe()
	defer peer.Close()
	offerUnframedConnection(t, pool, conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	acquired := acquireUnframedConnection(ctx, t, pool, conn)
	defer acquired.Close()
	pool.Close()
	verifyUnframedPayload(t, acquired, peer)
}

func offerUnframedConnection(t *testing.T, pool *ReversePool, conn net.Conn) {
	t.Helper()
	if err := pool.Offer(conn); err != nil {
		t.Fatal(err)
	}
}

func acquireUnframedConnection(ctx context.Context, t *testing.T, pool *ReversePool, want net.Conn) net.Conn {
	t.Helper()
	acquired, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if acquired != want {
		t.Fatal("Acquire wrapped the connection")
	}
	return acquired
}

func verifyUnframedPayload(t *testing.T, acquired net.Conn, peer net.Conn) {
	t.Helper()
	written := make(chan error, 1)
	go func() { _, err := acquired.Write([]byte("payload")); written <- err }()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, len("payload"))
	if _, err := io.ReadFull(peer, got); err != nil || string(got) != "payload" {
		t.Fatalf("acquired data = %q, %v", got, err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestReserveOfferLeavesRejectedConnectionWithCaller(t *testing.T) {
	relay := NewReversePool(time.Minute, 1)
	t.Cleanup(relay.Close)
	firstServer, firstClient := net.Pipe()
	t.Cleanup(func() { _ = firstClient.Close() })
	if err := relay.Offer(firstServer); err != nil {
		t.Fatal(err)
	}

	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	if _, err := relay.ReserveOffer(server); err == nil {
		t.Fatal("full queue accepted another connection")
	}
	written := make(chan error, 1)
	go func() {
		_, err := server.Write([]byte{9})
		written <- err
	}()
	var value [1]byte
	if _, err := client.Read(value[:]); err != nil || value[0] != 9 {
		t.Fatalf("rejected connection ownership = %d, %v", value[0], err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestAcquireAfterCloseFailsWithNetErrClosed(t *testing.T) {
	relay := NewReversePool(time.Minute, 1)
	relay.Close()

	conn, err := relay.Acquire(context.Background())
	if conn != nil {
		t.Fatal("Claim() after Close() returned a connection")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Claim() after Close() error = %v, want net.ErrClosed", err)
	}
}

func TestReversePoolPauseDropsIdleConnectionsAndRefusesOffers(t *testing.T) {
	pool := NewReversePool(0, 2)
	t.Cleanup(pool.Close)
	local, remote := net.Pipe()
	t.Cleanup(func() { _ = remote.Close() })
	if err := pool.Offer(local); err != nil {
		t.Fatal(err)
	}
	pauseIdleConnections(t, pool, remote)
	refuseOfferWhilePaused(t, pool)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	resumeOfferAcquire(ctx, t, pool)
}

func pauseIdleConnections(t *testing.T, pool *ReversePool, remote net.Conn) {
	t.Helper()
	closeIdle := pool.Pause()
	if closeIdle == nil || pool.ReadyCount() != 0 {
		t.Fatalf("Pause left %d idle connections", pool.ReadyCount())
	}
	closeIdle()
	if _, err := remote.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("idle connection stayed open: %v", err)
	}
}

func refuseOfferWhilePaused(t *testing.T, pool *ReversePool) {
	t.Helper()
	refused, refusedRemote := net.Pipe()
	t.Cleanup(func() { _ = refusedRemote.Close() })
	if err := pool.Offer(refused); !errors.Is(err, errPoolPaused) {
		t.Fatalf("Offer() while paused = %v", err)
	}
	if _, err := refusedRemote.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("refused connection stayed open: %v", err)
	}
}

func resumeOfferAcquire(ctx context.Context, t *testing.T, pool *ReversePool) {
	t.Helper()
	pool.Resume()
	accepted, acceptedRemote := net.Pipe()
	t.Cleanup(func() { _ = acceptedRemote.Close() })
	if err := pool.Offer(accepted); err != nil {
		t.Fatalf("Offer() after Resume = %v", err)
	}
	if conn, err := pool.Acquire(ctx); err != nil || conn != accepted {
		t.Fatalf("Acquire() after Resume = %v, %v", conn, err)
	}
}

func TestReversePoolPauseBeatsAnOutstandingReservation(t *testing.T) {
	pool := NewReversePool(0, 2)
	t.Cleanup(pool.Close)
	local, remote := net.Pipe()
	t.Cleanup(func() {
		_ = local.Close()
		_ = remote.Close()
	})
	reservation, err := pool.ReserveOffer(local)
	if err != nil {
		t.Fatal(err)
	}
	pool.Pause()
	if err := reservation.Commit(); !errors.Is(err, errPoolPaused) {
		t.Fatalf("Commit() after Pause = %v", err)
	}
	if pool.ReadyCount() != 0 {
		t.Fatal("a paused pool parked a reserved connection")
	}
	reservation.Cancel()
}
