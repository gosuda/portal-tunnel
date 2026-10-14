package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestReverseMuxHalfClosePreservesResponse(t *testing.T) {
	relay, connector := newReverseMuxPair(t)
	accepted := make(chan net.Conn, 1)
	done := make(chan error, 1)
	go func() {
		conn, _, err := relay.Accept()
		if err != nil {
			done <- err
			return
		}
		accepted <- conn
		if err := ConfirmReverseStream(conn, true); err != nil {
			done <- err
			return
		}
		data, err := io.ReadAll(conn)
		if err == nil && string(data) != "request" {
			err = errors.New("request mismatch")
		}
		if err == nil {
			_, err = conn.Write([]byte("response"))
		}
		_ = conn.Close()
		done <- err
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, err := connector.Open(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	half, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("reverse mux does not expose half-close")
	}
	if err := half.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn)
	if err != nil || string(data) != "response" {
		t.Fatalf("half-close response=%q err=%v", data, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = (<-accepted).Close()
}

func TestReverseMuxFullCloseCannotBeReopenedByDeadline(t *testing.T) {
	relay, connector := newReverseMuxPair(t)
	accepted := make(chan net.Conn, 1)
	errs := make(chan error, 1)
	go func() {
		conn, _, err := relay.Accept()
		if err != nil {
			errs <- err
			return
		}
		accepted <- conn
		errs <- ConfirmReverseStream(conn, true)
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, err := connector.Open(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := <-accepted
	defer peer.Close()
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); readDone <- err }()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed stream reset deadline: %v", err)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("closed stream read succeeded")
		}
	case <-ctx.Done():
		t.Fatal("full close failed to interrupt read")
	}
}
