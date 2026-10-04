package transport

import (
	"net"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestRelayDatagramRoutesRepliesOnlyWhileEnabled(t *testing.T) {
	d := NewRelayDatagram("demo:0x1", 0)
	t.Cleanup(d.Close)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	d.conn = conn
	for _, payload := range []string{"first client", "second client"} {
		client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		flowID := d.touchFlow(client.LocalAddr().(*net.UDPAddr).AddrPort())
		d.SetEnabled(false)
		d.dispatch(types.DatagramFrame{FlowID: flowID, Payload: []byte("blocked")})
		d.SetEnabled(true)
		d.dispatch(types.DatagramFrame{FlowID: flowID, Payload: []byte(payload)})
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 64)
		n, _, err := client.ReadFromUDP(buf)
		if err != nil || string(buf[:n]) != payload {
			t.Fatalf("UDP reply = %q, %v; want %q", buf[:n], err, payload)
		}
	}
}
