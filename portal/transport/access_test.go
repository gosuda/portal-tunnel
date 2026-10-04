package transport

import (
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestRelayDatagramDropsTrafficWhileDisabled(t *testing.T) {
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

	d.SetEnabled(true)
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
