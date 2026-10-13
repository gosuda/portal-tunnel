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
	record := &leaseRecord{Identity: types.Identity{Name: "demo", Address: "0x1"}, ExpiresAt: time.Now().Add(time.Hour), reverse: transport.NewReversePool(time.Minute, 1)}
	defer record.Close()
	registry := &leaseRegistry{records: []*leaseRecord{record}, blocked: map[types.ServiceIdentityKey]time.Time{record.ServiceKey(): time.Now()}}
	client, inbound := net.Pipe()
	defer client.Close()
	defer inbound.Close()
	if _, err := registry.admitBridge(t.Context(), record, inbound); !errors.Is(err, errLeaseRejected) {
		t.Fatalf("blocked TCP admission = %v", err)
	}
}

func TestLeaseCloseRejectsRawTCPStillStarting(t *testing.T) {
	record := &leaseRecord{ExpiresAt: time.Now().Add(time.Hour), reverse: transport.NewReversePool(time.Minute, 1)}
	defer record.Close()
	registry := &leaseRegistry{records: []*leaseRecord{record}}
	inbound, client := net.Pipe()
	defer client.Close()
	bridge, err := registry.admitBridge(t.Context(), record, inbound)
	if err != nil {
		t.Fatal(err)
	}
	defer record.releaseBridge(bridge)
	reverse, peer := net.Pipe()
	defer peer.Close()
	defer reverse.Close()
	if err := registry.activateBridge(record, bridge, reverse); err != nil {
		t.Fatal(err)
	}
	record.Close()
	for _, conn := range []net.Conn{client, peer} {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("closed lease retained endpoint: %v", err)
		}
	}
	if err := registry.activateBridge(record, bridge, reverse); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed lease activated bridge: %v", err)
	}
}
