package transport

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestDatagramSessionMaximumPayloadAndFlowID(t *testing.T) {
	server, client := newAuthTestConnections(t)
	session := bindMaxPayloadSession(t, server)
	defer session.Close("test complete")
	frame := makeMaxPayloadFrame(t, session)
	verifyMaxPayloadOutbound(t, session, client, frame)
	verifyMaxPayloadInbound(t, session, client, frame)
}

func bindMaxPayloadSession(t *testing.T, server *quic.Conn) *DatagramSession {
	t.Helper()
	session := NewDatagramSession(4, false)
	if _, err := session.Bind(server); err != nil {
		t.Fatal(err)
	}
	return session
}

func makeMaxPayloadFrame(t *testing.T, session *DatagramSession) types.DatagramFrame {
	t.Helper()
	payload := bytes.Repeat([]byte{0xa5}, types.MaxUDPPayloadSize)
	return types.DatagramFrame{FlowID: ^uint32(0), Payload: payload, LeaseDone: session.leaseDone}
}

func verifyMaxPayloadOutbound(t *testing.T, session *DatagramSession, client *quic.Conn, frame types.DatagramFrame) {
	t.Helper()
	if err := session.SendFrame(frame); err != nil {
		t.Fatalf("send maximum payload: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	wire, err := client.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	received, err := decodeDatagram(wire)
	if err != nil || received.FlowID != frame.FlowID || !bytes.Equal(received.Payload, frame.Payload) {
		t.Fatalf("maximum payload round trip: %+v, %v", received, err)
	}
}

func verifyMaxPayloadInbound(t *testing.T, session *DatagramSession, client *quic.Conn, frame types.DatagramFrame) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := client.SendDatagram(encodeDatagram(frame.FlowID, frame.Payload)); err != nil {
		t.Fatal(err)
	}
	received, err := session.Accept(ctx.Done())
	if err != nil || received.FlowID != frame.FlowID || !bytes.Equal(received.Payload, frame.Payload) {
		t.Fatalf("maximum inbound payload: %+v, %v", received, err)
	}
}
