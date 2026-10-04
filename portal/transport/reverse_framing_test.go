package transport

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestReadRawStartSkipsKeepaliveAndPreservesPayload(t *testing.T) {
	relay, client := net.Pipe()
	defer relay.Close()
	defer client.Close()
	written := make(chan error, 1)
	go func() {
		if err := WriteKeepalive(relay); err != nil {
			written <- err
			return
		}
		if err := WriteRawStart(relay); err != nil {
			written <- err
			return
		}
		_, err := relay.Write([]byte("raw"))
		written <- err
	}()
	binding, err := ReadStart(context.Background(), client, time.Second)
	if err != nil || binding != nil {
		t.Fatalf("raw start = %x, %v", binding, err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var payload [3]byte
	if _, err := io.ReadFull(client, payload[:]); err != nil || string(payload[:]) != "raw" {
		t.Fatalf("raw payload = %q, %v", payload, err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestReadStartRejectsMalformedFraming(t *testing.T) {
	for _, frame := range [][]byte{{0xff}, {markerTLSStart, 1, 2}} {
		relay, client := net.Pipe()
		go func() { _, _ = relay.Write(frame); _ = relay.Close() }()
		if _, err := ReadStart(context.Background(), client, time.Second); err == nil {
			t.Fatalf("accepted invalid frame %x", frame)
		}
		if err := client.SetDeadline(time.Now()); err == nil {
			t.Fatal("invalid framing left the connection open")
		}
	}
}

func TestReadStartCancellationInterruptsIdleRead(t *testing.T) {
	relay, client := net.Pipe()
	defer relay.Close()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := ReadStart(ctx, client, time.Hour); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt framing")
	}
}
