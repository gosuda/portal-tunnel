package keyless

import (
	"bytes"
	"errors"
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

func TestClientHelloAccumulatorRejectsInvalidRecordBounds(t *testing.T) {
	record := func(contentType byte, payload []byte) []byte {
		header := []byte{tlsHandshakeContentType, 3, 3, byte(len(payload) >> 8), byte(len(payload))}
		header[0] = contentType
		return append(header, payload...)
	}
	for _, tc := range []struct {
		name string
		wire []byte
		want error
	}{
		{"empty record", []byte{tlsHandshakeContentType, 3, 3, 0, 0}, errClientHelloTLSRecordHasInvalid},
		{"oversized record", []byte{tlsHandshakeContentType, 3, 3, 0x40, 0x01}, errClientHelloTLSRecordHasInvalid},
		{"non-handshake content", record(23, []byte{1, 2, 3, 4, 5}), errClientHelloContainsNonHandshakeTLS},
		{"first message not client hello", record(tlsHandshakeContentType, []byte{2, 0, 0, 6, 1, 2, 3, 4, 5, 6}), errFirstTLSHandshakeMessageNotClient},
		{"empty handshake message", record(tlsHandshakeContentType, []byte{clientHelloType, 0, 0, 0}), errClientHelloHandshakeHasInvalidLength},
	} {
		var acc clientHelloAccumulator
		if _, _, err := acc.add(tc.wire); !errors.Is(err, tc.want) {
			t.Fatalf("%s: add error = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestClientHelloAccumulatorAcceptsBoundarySizes(t *testing.T) {
	hello := func(messageLen int) []byte {
		out := []byte{clientHelloType, byte(messageLen >> 16), byte(messageLen >> 8), byte(messageLen)}
		return append(out, bytes.Repeat([]byte{0x61}, messageLen)...)
	}
	pack := func(body []byte) []byte {
		var wire []byte
		for len(body) > 0 {
			n := min(len(body), maxTLSRecordPayload)
			header := []byte{tlsHandshakeContentType, 3, 3, byte(n >> 8), byte(n)}
			wire = append(wire, header...)
			wire = append(wire, body[:n]...)
			body = body[n:]
		}
		return wire
	}
	for _, messageLen := range []int{maxTLSRecordPayload - 1 - 4, maxTLSRecordPayload - 4} {
		want := hello(messageLen)
		var acc clientHelloAccumulator
		got, complete, err := acc.add(pack(want))
		if err != nil || !complete || !bytes.Equal(got, want) {
			t.Fatalf("messageLen %d: add = %d bytes, %v, %v", messageLen, len(got), complete, err)
		}
	}
	want := hello(maxClientHelloSize - 4)
	var acc clientHelloAccumulator
	if got, complete, err := acc.add(pack(want)); err != nil || !complete || !bytes.Equal(got, want) {
		t.Fatalf("max client hello: add = %d bytes, %v, %v", len(got), complete, err)
	}
	var over clientHelloAccumulator
	if _, _, err := over.add(pack(hello(maxClientHelloSize - 3))); !errors.Is(err, errClientHelloHandshakeHasInvalidLength) {
		t.Fatalf("oversized handshake: add error = %v, want handshake length error", err)
	}
}
