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

func TestOfferConnReadyWritesProtocolAckBeforeClaimMarker(t *testing.T) {
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
	if err := relay.OfferConnReady(server, func() error {
		_, err := server.Write([]byte{7})
		return err
	}); err != nil {
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

	activatorBindings := make(chan []byte, 1)
	activator := TLSActivationFunc(func(ctx context.Context, raw net.Conn, b []byte) (net.Conn, error) {
		activatorBindings <- append([]byte(nil), b...)
		return raw, nil
	})
	stream := NewClientStream(1, time.Second)
	sessionDone := make(chan error, 1)
	go func() {
		_, err := stream.RunSession(context.Background(), clientConn, activator)
		sessionDone <- err
	}()

	select {
	case got := <-activatorBindings:
		if !bytes.Equal(got, binding[:]) {
			t.Fatalf("activator binding = %#x, want %#x", got, binding[:])
		}
	case err := <-sessionDone:
		t.Fatalf("RunSession finished before activation: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("activator never received a binding")
	}
	if err := <-sessionDone; err != nil {
		t.Fatalf("RunSession: %v", err)
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

func TestOfferConnReadyLeavesRejectedConnectionWithCaller(t *testing.T) {
	relay := NewRelayStream("lease", time.Minute, 1)
	t.Cleanup(relay.Close)
	firstServer, firstClient := net.Pipe()
	t.Cleanup(func() { _ = firstClient.Close() })
	if err := relay.OfferConn(firstServer); err != nil {
		t.Fatal(err)
	}

	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	called := false
	if err := relay.OfferConnReady(server, func() error { called = true; return nil }); err == nil {
		t.Fatal("full queue accepted another connection")
	}
	if called {
		t.Fatal("ready callback ran without a reserved queue slot")
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
