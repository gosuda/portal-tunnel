package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestReverseMuxAuthenticatesEveryStream(t *testing.T) {
	relay, connector := newReverseMuxPair(t)
	accepted := make(chan net.Conn, 1)
	authorized := make(chan string, 2)
	serverErr := make(chan error, 1)
	go func() {
		for {
			conn, capability, err := relay.Accept()
			if err != nil {
				serverErr <- err
				return
			}
			authorized <- capability
			acceptedCapability := capability == "current-capability"
			if err := ConfirmReverseStream(conn, acceptedCapability); err != nil {
				_ = conn.Close()
				serverErr <- err
				return
			}
			if !acceptedCapability {
				_ = conn.Close()
				continue
			}
			accepted <- conn
			serverErr <- nil
			return
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if conn, err := connector.Open(ctx, "stale-capability"); conn != nil || !errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeUnauthorized}) {
		t.Fatalf("Open() with stale capability = (%v, %v), want unauthorized", conn, err)
	}
	current, err := connector.Open(ctx, "current-capability")
	if err != nil {
		t.Fatalf("Open() with current capability error = %v", err)
	}
	defer current.Close()

	serverConn := <-accepted
	defer serverConn.Close()
	if err := <-serverErr; err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	for _, want := range []string{"stale-capability", "current-capability"} {
		if got := <-authorized; got != want {
			t.Fatalf("authorized capability = %q, want %q", got, want)
		}
	}
}

func newReverseMuxPair(t *testing.T) (*ReverseMux, *ReverseMux) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	server, err := yamux.Server(serverConn, reverseMuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	client, err := yamux.Client(clientConn, reverseMuxConfig())
	if err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	return &ReverseMux{session: server}, &ReverseMux{session: client}
}

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
