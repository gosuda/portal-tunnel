package transport

import (
	"context"
	"errors"
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
