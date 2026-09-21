package keyless

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestFixHelloOnWriteCapturesFragmentedClientHello(t *testing.T) {
	hello := []byte{clientHelloType, 0, 0, 6, 1, 2, 3, 4, 5, 6}
	firstRecord := append([]byte{tlsHandshakeContentType, 3, 3, 0, 3}, hello[:3]...)
	secondRecord := append([]byte{tlsHandshakeContentType, 3, 3, 0, byte(len(hello) - 3)}, hello[3:]...)
	wire := append(firstRecord, secondRecord...)
	wire = append(wire, []byte("after hello")...)

	registry := NewBindingRegistry(time.Minute)
	binding := registry.Issue("lease", nil)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	received := make(chan struct {
		wire []byte
		err  error
	}, 1)
	go func() {
		got := make([]byte, len(wire))
		_, err := io.ReadFull(server, got)
		received <- struct {
			wire []byte
			err  error
		}{wire: got, err: err}
	}()

	conn := registry.FixHelloOnWrite(client, binding)
	for _, fragment := range [][]byte{wire[:2], wire[2:9], wire[9 : len(firstRecord)+len(secondRecord)], wire[len(firstRecord)+len(secondRecord):]} {
		if _, err := conn.Write(fragment); err != nil {
			t.Fatalf("write fragmented client hello: %v", err)
		}
	}

	result := <-received
	if result.err != nil {
		t.Fatalf("read wrapped connection: %v", result.err)
	}
	if !bytes.Equal(result.wire, wire) {
		t.Fatalf("wire bytes changed: got %x, want %x", result.wire, wire)
	}
	if err := registry.ValidateAndConsume(binding[:], "lease", hello); err != nil {
		t.Fatalf("validate reassembled client hello: %v", err)
	}
}
