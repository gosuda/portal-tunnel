package transport

import (
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestRelayDatagramStartFailureAndClose(t *testing.T) {
	occupied, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	addr := occupied.LocalAddr().(*net.UDPAddr)
	endpoint := NewRelayDatagram(types.NewServiceIdentityKey("lease", "test"), addr.Port)
	defer endpoint.Close()
	if err := endpoint.Start(); err == nil {
		t.Fatal("Start bound an occupied port")
	}
	_ = occupied.Close()
	if err := endpoint.Start(); err != nil {
		t.Fatalf("Start after releasing port: %v", err)
	}
	if err := endpoint.Start(); err != nil {
		t.Fatalf("repeated Start: %v", err)
	}
	endpoint.Close()
	if err := endpoint.Start(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Start after Close: %v", err)
	}
	rebound, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("Close did not release the socket: %v", err)
	}
	_ = rebound.Close()
}

func TestDatagramSessionCloseUnblocksAccept(t *testing.T) {
	session := NewDatagramSession(1, false)
	closed := make(chan error, 1)
	go func() { _, err := session.Accept(nil); closed <- err }()
	session.Close("test complete")
	session.Close("already closed")
	if err := <-closed; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v", err)
	}
	if err := session.Send(1, []byte("closed")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Send after Close: %v", err)
	}
}

func TestRelayDatagramConcurrentStartAndClose(t *testing.T) {
	endpoint := NewRelayDatagram(types.NewServiceIdentityKey("lease", "test"), 0)
	var workers sync.WaitGroup
	workers.Go(func() {
		if err := endpoint.Start(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("Start racing Close: %v", err)
		}
	})
	workers.Go(endpoint.Close)
	workers.Wait()
	if err := endpoint.Start(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed endpoint restarted: %v", err)
	}
}
