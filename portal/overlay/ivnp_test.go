//go:build !windows

package overlay

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"gosuda.org/ivnp"
)

func TestLoadOrCreateIVNPDestinationPersistsIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ivnp.destination")
	first, err := loadOrCreateIVNPDestination(path)
	if err != nil {
		t.Fatalf("loadOrCreateIVNPDestination(first) error = %v", err)
	}
	firstAddress := first.B32()
	first.ReleaseSensitive()

	second, err := loadOrCreateIVNPDestination(path)
	if err != nil {
		t.Fatalf("loadOrCreateIVNPDestination(second) error = %v", err)
	}
	t.Cleanup(second.ReleaseSensitive)
	if second.B32() != firstAddress {
		t.Fatalf("second destination = %q, want %q", second.B32(), firstAddress)
	}
}

func TestIVNPOpenHopStreamUsesI2PStreamNetwork(t *testing.T) {
	network := ivnp.NewLocalStreamNetwork()
	destination := strings.Repeat("a", 52) + ".b32.i2p"
	listener, err := network.ListenI2P(context.Background(), net.JoinHostPort(destination, "7778"))
	if err != nil {
		t.Fatalf("ListenI2P() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	overlay := &IVNP{network: network}
	overlay.ready.Store(true)
	type result struct {
		stream HopStream
		err    error
	}
	accepted := make(chan result, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			accepted <- result{err: acceptErr}
			return
		}
		stream, readErr := readHopStream(conn)
		accepted <- result{stream: stream, err: readErr}
	}()
	conn, err := overlay.OpenHopStream(context.Background(), destination, "hop-token")
	if err != nil {
		t.Fatalf("OpenHopStream() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	result := <-accepted
	if result.err != nil {
		t.Fatalf("readHopStream() error = %v", result.err)
	}
	if result.stream.Token != "hop-token" {
		t.Fatalf("received token = %q", result.stream.Token)
	}
}
