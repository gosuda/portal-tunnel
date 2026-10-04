package transport

import (
	"errors"
	"net"
	"testing"
)

func TestRelayDatagramStartFailureAndClose(t *testing.T) {
	occupied, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	addr := occupied.LocalAddr().(*net.UDPAddr)
	endpoint := NewRelayDatagram("lease", addr.Port)
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
	if err := <-closed; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v", err)
	}
}
