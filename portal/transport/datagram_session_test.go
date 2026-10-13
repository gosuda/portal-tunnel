package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestDatagramSessionClearDiscardsPreviousLease(t *testing.T) {
	s := NewDatagramSession(4, false)
	defer s.Close("test")
	if err := s.SendFrame(types.DatagramFrame{FlowID: 1}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("missing ownership should be closed: %v", err)
	}
	oldLease := s.leaseDone
	s.incoming <- types.DatagramFrame{FlowID: 1, Payload: []byte("stale"), LeaseDone: oldLease}
	s.Clear("replacement lease")
	select {
	case <-oldLease:
	default:
		t.Fatal("old lease still live")
	}
	s.incoming <- types.DatagramFrame{FlowID: 1, Payload: []byte("current"), LeaseDone: s.leaseDone}
	frame, err := s.Accept(nil)
	if err != nil || string(frame.Payload) != "current" {
		t.Fatalf("Accept = %+v, %v", frame, err)
	}
	if err := s.SendFrame(types.DatagramFrame{FlowID: 1, LeaseDone: oldLease}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("stale reply not rejected before transport: %v", err)
	}
}

func TestDatagramSessionReconnectPreservesLease(t *testing.T) {
	session := NewDatagramSession(4, false)
	defer session.Close("test")
	first, _ := newAuthTestConnections(t)
	if _, err := session.Bind(first); err != nil {
		t.Fatal(err)
	}
	lease := session.leaseDone
	second, peer := newAuthTestConnections(t)
	if _, err := session.Bind(second); err != nil {
		t.Fatal(err)
	}
	if session.leaseDone != lease {
		t.Fatal("reconnect replaced lease ownership")
	}
	frame := types.DatagramFrame{FlowID: 7, Payload: []byte("same lease"), LeaseDone: lease}
	if err := session.SendFrame(frame); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	data, err := peer.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	received, err := types.DecodeDatagram(data)
	if err != nil || received.FlowID != frame.FlowID || string(received.Payload) != string(frame.Payload) {
		t.Fatalf("reconnected reply: %+v %v", received, err)
	}
	session.Clear("new lease")
	if err := session.SendFrame(frame); err == nil || errors.Is(err, errNoConnection) {
		t.Fatalf("old reply accepted by replacement: %v", err)
	}
	session.Close("shutdown")
	session.Clear("late shutdown")
}

func TestDatagramSessionCloseInterruptsSending(t *testing.T) {
	session := NewDatagramSession(4, false)
	defer session.Close("test")
	conn, _ := newAuthTestConnections(t)
	if _, err := session.Bind(conn); err != nil {
		t.Fatal(err)
	}
	frame := types.DatagramFrame{FlowID: 1, Payload: make([]byte, types.MaxUDPPayloadSize), LeaseDone: session.leaseDone}
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		close(started)
		for {
			if err := session.SendFrame(frame); err != nil {
				return
			}
		}
	}()
	<-started
	session.Close("shutdown")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session sender survived close")
	}
}

func TestDatagramSessionRejectsPeerWithoutDatagrams(t *testing.T) {
	session := NewDatagramSession(4, false)
	defer session.Close("test")
	conn, _ := newAuthTestConnections(t, &quic.Config{})
	if _, err := session.Bind(conn); err == nil {
		t.Fatal("bound peer without DATAGRAM support")
	}
	if session.Connected() {
		t.Fatal("rejected peer became active")
	}
	select {
	case <-conn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("rejected peer remained open")
	}
}
