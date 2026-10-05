package portal

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestLeaseOwnsReverseMuxReplacementAndClose(t *testing.T) {
	accepted := make(chan *transport.ReverseMux, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux, err := transport.AcceptReverseMux(w, r)
		if err == nil {
			accepted <- mux
		}
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	firstPeer, err := transport.DialReverseMux(ctx, target, "capability")
	if err != nil {
		t.Fatal(err)
	}
	defer firstPeer.Close()
	first := <-accepted
	record := &leaseRecord{reverse: transport.NewReversePool(time.Minute, 1)}
	defer record.Close()
	if err := record.attachReverseMux(first); err != nil {
		t.Fatal(err)
	}
	secondPeer, err := transport.DialReverseMux(ctx, target, "capability")
	if err != nil {
		t.Fatal(err)
	}
	defer secondPeer.Close()
	second := <-accepted
	if err := record.attachReverseMux(second); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstPeer.Done():
	case <-ctx.Done():
		t.Fatal("replaced carrier remained open")
	}
	record.detachReverseMux(first)
	select {
	case <-secondPeer.Done():
		t.Fatal("late release closed the replacement")
	default:
	}
	record.Close()
	select {
	case <-secondPeer.Done():
	case <-ctx.Done():
		t.Fatal("lease close left its active carrier open")
	}
	if err := record.attachReverseMux(second); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed lease accepted a carrier: %v", err)
	}
}

func TestRawTCPRejectsConnectionWhileNotRoutable(t *testing.T) {
	record := &leaseRecord{Identity: types.Identity{Name: "demo", Address: "0x1"}}
	server := &Server{registry: &leaseRegistry{blocked: map[types.ServiceIdentityKey]time.Time{record.ServiceKey(): time.Now()}}}
	client, inbound := net.Pipe()
	defer client.Close()
	server.bridgeTCPConn(record, inbound)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Fatalf("blocked TCP connection remained open: %v", err)
	}
}

func TestLeaseCloseRejectsRawTCPStillStarting(t *testing.T) {
	record := &leaseRecord{reverse: transport.NewReversePool(time.Minute, 1)}
	defer record.Close()
	reverse, peer := net.Pipe()
	defer peer.Close()
	defer reverse.Close()
	if err := record.reverse.Offer(reverse); err != nil {
		t.Fatal(err)
	}
	inbound, client := net.Pipe()
	defer client.Close()
	server := &Server{registry: &leaseRegistry{bps: NewBPSManager()}}
	done := make(chan struct{})
	go func() { server.bridgeTCPConn(record, inbound); close(done) }()

	// The peer withholds its start-frame read while the lease closes. Once
	// acquired, the connection is the ingress handler's responsibility.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for record.reverse.ReadyCount() != 0 {
		select {
		case <-ctx.Done():
			t.Fatal("raw ingress did not acquire its connection")
		case <-time.After(time.Millisecond):
		}
	}
	record.Close()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	var marker [1]byte
	if _, err := io.ReadFull(peer, marker[:]); err != nil || marker[0] != 0x01 {
		t.Fatalf("pending raw start = %x, %v", marker, err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("closed lease forwarded a pending raw connection: %v", err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("pending raw ingress survived lease close")
	}
}
