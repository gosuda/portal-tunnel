package transport

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/internal/protocol"
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
		conn, _ := relay.Claim(context.Background())
		claimed <- conn
	}()
	var marker [1]byte
	if _, err := client.Read(marker[:]); err != nil || marker[0] != protocol.MarkerTLSStart {
		t.Fatalf("claim marker = %d, %v", marker[0], err)
	}
	_ = (<-claimed).Close()
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
