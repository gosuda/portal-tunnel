package transport

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestDatagramSessionMaximumPayloadAndFlowID(t *testing.T) {
	server, client := newAuthTestConnections(t)
	session := NewDatagramSession(4, false)
	defer session.Close("test complete")
	if _, err := session.Bind(server); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	payload := bytes.Repeat([]byte{0xa5}, types.MaxUDPPayloadSize)
	frame := types.DatagramFrame{FlowID: ^uint32(0), Payload: payload, LeaseDone: session.leaseDone}
	if err := session.SendFrame(frame); err != nil {
		t.Fatalf("send maximum payload: %v", err)
	}
	wire, err := client.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	received, err := types.DecodeDatagram(wire)
	if err != nil || received.FlowID != frame.FlowID || !bytes.Equal(received.Payload, payload) {
		t.Fatalf("maximum payload round trip: %+v, %v", received, err)
	}
	if err := client.SendDatagram(types.EncodeDatagram(frame.FlowID, payload)); err != nil {
		t.Fatal(err)
	}
	received, err = session.Accept(ctx.Done())
	if err != nil || received.FlowID != frame.FlowID || !bytes.Equal(received.Payload, payload) {
		t.Fatalf("maximum inbound payload: %+v, %v", received, err)
	}
}
