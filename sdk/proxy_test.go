package sdk

import (
	"bufio"
	"net"
	"net/http"
	"testing"
)

func TestProxyConnectionAnswers503WhenOriginIsDown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for a free origin port: %v", err)
	}
	closedOrigin := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close origin listener: %v", err)
	}

	visitor, relay := net.Pipe()
	defer visitor.Close()
	proxied := make(chan error, 1)
	go func() { proxied <- proxyConnection(t.Context(), closedOrigin, relay) }()

	response, err := http.ReadResponse(bufio.NewReader(visitor), nil)
	if err != nil {
		t.Fatalf("read response for a down origin: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusServiceUnavailable)
	}
	if err := <-proxied; err != nil {
		t.Fatalf("proxyConnection returned %v, want nil", err)
	}
}
