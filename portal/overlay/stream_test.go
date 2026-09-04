package overlay

import (
	"net"
	"testing"
)

func TestHopTokenFrameRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	writeResult := make(chan error, 1)
	go func() { writeResult <- writeHopToken(client, "hop-token") }()
	stream, err := readHopStream(server)
	if err != nil {
		t.Fatalf("readHopStream() error = %v", err)
	}
	if err := <-writeResult; err != nil {
		t.Fatalf("writeHopToken() error = %v", err)
	}
	if stream.Token != "hop-token" || stream.Conn != server {
		t.Fatalf("readHopStream() = %#v", stream)
	}
}
