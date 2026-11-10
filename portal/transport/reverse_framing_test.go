package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestTLSStartHonorsCallerAndSessionDeadlines(t *testing.T) {
	for _, tc := range []struct {
		name   string
		budget time.Duration
		want   time.Duration
	}{
		{name: "remaining claim budget", budget: 100 * time.Millisecond, want: 100 * time.Millisecond},
		{name: "expired claim", budget: -time.Second},
		{name: "session limit", budget: time.Minute, want: 5 * time.Second},
		{name: "no caller deadline", want: 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				relay, client := net.Pipe()
				defer relay.Close()
				defer client.Close()
				start := time.Now()
				var deadline time.Time
				if tc.budget != 0 {
					deadline = start.Add(tc.budget)
				}
				// An unread peer blocks the real framing write until its deadline.
				err := WriteTLSStart(relay, [types.TLSBindingSize]byte{}, deadline)
				if tc.budget < 0 {
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("expired framing returned %v, want deadline exceeded", err)
					}
				} else if timeout, ok := errors.AsType[net.Error](err); !ok || !timeout.Timeout() {
					t.Fatalf("blocked framing returned %v, want a timeout", err)
				}
				if elapsed := time.Since(start); elapsed != tc.want {
					t.Fatalf("blocked framing took %v, want %v", elapsed, tc.want)
				}
			})
		})
	}
}

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
	for _, frame := range [][]byte{{0xff}, {types.ReverseMarkerTLSStart, 1, 2}} {
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

func TestReadStartRequiresFullTLSBinding(t *testing.T) {
	relay, client := net.Pipe()
	go func() {
		_, _ = relay.Write([]byte{types.ReverseMarkerTLSStart})
		_, _ = relay.Write(bytes.Repeat([]byte{0x61}, types.TLSBindingSize-1))
		_ = relay.Close()
	}()
	if _, err := ReadStart(context.Background(), client, time.Second); err == nil {
		t.Fatal("short TLS binding accepted")
	}
	if err := client.SetDeadline(time.Now()); err == nil {
		t.Fatal("short TLS binding left the connection open")
	}
}

func TestReadStartPreservesBytesAfterBinding(t *testing.T) {
	relay, client := net.Pipe()
	defer relay.Close()
	defer client.Close()
	binding := bytes.Repeat([]byte{0x62}, types.TLSBindingSize)
	go func() {
		_, _ = relay.Write(append([]byte{types.ReverseMarkerTLSStart}, append(binding, []byte("payload")...)...))
	}()
	got, err := ReadStart(context.Background(), client, time.Second)
	if err != nil || !bytes.Equal(got, binding) {
		t.Fatalf("binding = %x, %v", got, err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var trailing [7]byte
	if _, err := io.ReadFull(client, trailing[:]); err != nil || string(trailing[:]) != "payload" {
		t.Fatalf("trailing = %q, %v", trailing, err)
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
