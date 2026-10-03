package transport

import (
	"net"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestRelayDatagramDropsTrafficWhileNotRoutable(t *testing.T) {
	d := NewRelayDatagram("demo:0x1", 0)
	t.Cleanup(d.Close)
	replies := make(chan []byte, 1)
	flowID := d.touchFlow("udp:client", func(payload []byte) error {
		replies <- payload
		return nil
	})

	d.dispatch(types.DatagramFrame{FlowID: flowID, Payload: []byte("blocked")})
	select {
	case <-replies:
		t.Fatal("non-routable datagram was forwarded")
	default:
	}

	d.SetRoutable(true)
	d.dispatch(types.DatagramFrame{FlowID: flowID, Payload: []byte("allowed")})
	select {
	case payload := <-replies:
		if string(payload) != "allowed" {
			t.Fatalf("forwarded payload = %q", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("routable datagram was not forwarded")
	}
}

func TestRelayTCPPortRejectsConnectionWhileNotRoutable(t *testing.T) {
	port := &RelayTCPPort{}
	client, inbound := net.Pipe()
	port.claim(inbound)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("non-routable TCP connection remained open")
	}
	_ = client.Close()
}
