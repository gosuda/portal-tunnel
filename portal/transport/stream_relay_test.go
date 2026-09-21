package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestReserveOfferCommitsProtocolAckBeforeClaimMarker(t *testing.T) {
	relay := NewRelayStream("lease", time.Minute, 1)
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
	if _, err := server.Write([]byte{7}); err != nil {
		t.Fatal(err)
	}
	if err := reservation.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := <-ack; got != 7 {
		t.Fatalf("protocol acknowledgement = %d", got)
	}

	claimed := make(chan net.Conn, 1)
	go func() {
		conn, _ := relay.Claim(context.Background(), [16]byte{})
		claimed <- conn
	}()
	var frame [1 + tlsBindingSize]byte
	if _, err := io.ReadFull(client, frame[:]); err != nil {
		t.Fatalf("read claim frame: %v", err)
	}
	if frame[0] != markerTLSStart {
		t.Fatalf("claim marker = %d", frame[0])
	}
	_ = (<-claimed).Close()
}

func TestTLSBindingFramingRoundTrip(t *testing.T) {
	relay := NewRelayStream("lease", time.Minute, 1)
	t.Cleanup(relay.Close)
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	if err := relay.OfferConn(serverConn); err != nil {
		t.Fatal(err)
	}

	binding := [16]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	claimed := make(chan net.Conn, 1)
	claimErr := make(chan error, 1)
	go func() {
		conn, err := relay.Claim(context.Background(), binding)
		if err != nil {
			claimErr <- err
			return
		}
		claimed <- conn
	}()

	stream := NewClientStream(time.Second)
	session, err := stream.RunSession(context.Background(), clientConn)
	if err != nil {
		t.Fatalf("RunSession: %v", err)
	}
	if session.Conn != clientConn {
		t.Fatal("RunSession replaced the raw connection")
	}
	if !bytes.Equal(session.Binding, binding[:]) {
		t.Fatalf("session binding = %#x, want %#x", session.Binding, binding[:])
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

func TestReserveOfferLeavesRejectedConnectionWithCaller(t *testing.T) {
	relay := NewRelayStream("lease", time.Minute, 1)
	t.Cleanup(relay.Close)
	firstServer, firstClient := net.Pipe()
	t.Cleanup(func() { _ = firstClient.Close() })
	if err := relay.OfferConn(firstServer); err != nil {
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

func TestClaimAfterCloseFailsWithNetErrClosed(t *testing.T) {
	relay := NewRelayStream("lease", time.Minute, 1)
	relay.Close()

	// Closing the relay must release pending claimers with net.ErrClosed,
	// never leave them waiting for a connection that will never arrive.
	conn, err := relay.Claim(context.Background(), [16]byte{})
	if conn != nil {
		t.Fatal("Claim() after Close() returned a connection")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Claim() after Close() error = %v, want net.ErrClosed", err)
	}
}
