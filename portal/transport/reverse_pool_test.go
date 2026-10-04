package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestReserveOfferCommitsProtocolAckBeforeClaimMarker(t *testing.T) {
	relay := NewReversePool(time.Minute, 1)
	t.Cleanup(relay.Close)
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	ack := make(chan byte, 1)
	go func() {
		var value [1]byte
		_, _ = client.Read(value[:])
		ack <- value[0]
	}()
	reservation, err := relay.ReserveOffer(server)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	claimed := make(chan net.Conn, 1)
	go func() {
		conn, err := relay.Acquire(ctx)
		if err == nil {
			_ = WriteTLSStart(conn, [16]byte{})
		}
		claimed <- conn
	}()
	if _, err := server.Write([]byte{7}); err != nil {
		t.Fatal(err)
	}
	if err := reservation.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := <-ack; got != 7 {
		t.Fatalf("protocol acknowledgement = %d", got)
	}

	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var frame [1 + tlsBindingSize]byte
	if _, err := io.ReadFull(client, frame[:]); err != nil {
		t.Fatalf("read claim frame: %v", err)
	}
	if frame[0] != markerTLSStart {
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
	if err := relay.Offer(serverConn); err != nil {
		t.Fatal(err)
	}

	binding := [16]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
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

func TestReversePoolReservationSurvivesConcurrentClose(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprint(commit), func(t *testing.T) {
			pool := NewReversePool(time.Minute, 1)
			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()
			reservation, err := pool.ReserveOffer(conn)
			if err != nil {
				t.Fatal(err)
			}
			closed := make(chan struct{})
			go func() { pool.Close(); close(closed) }()
			if commit {
				if err := reservation.Commit(); err != nil {
					t.Fatalf("acknowledged reservation could not commit: %v", err)
				}
			} else {
				reservation.Cancel()
			}
			reservation.Cancel()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("Close did not finish after reservation resolution")
			}
			if commit {
				if _, err := peer.Read(make([]byte, 1)); err == nil {
					t.Fatal("committed connection survived pool close")
				}
			} else if err := conn.SetDeadline(time.Now()); err != nil {
				t.Fatalf("cancellation closed caller-owned connection: %v", err)
			}
		})
	}
}

func TestReversePoolAcquireTransfersUnframedConnection(t *testing.T) {
	pool := NewReversePool(time.Minute, 1)
	defer pool.Close()
	conn, peer := net.Pipe()
	defer peer.Close()
	if err := pool.Offer(conn); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	acquired, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer acquired.Close()
	if acquired != conn {
		t.Fatal("Acquire wrapped the connection")
	}
	pool.Close()
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

	// Closing the relay must release pending claimers with net.ErrClosed,
	// never leave them waiting for a connection that will never arrive.
	conn, err := relay.Acquire(context.Background())
	if conn != nil {
		t.Fatal("Claim() after Close() returned a connection")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Claim() after Close() error = %v, want net.ErrClosed", err)
	}
}
