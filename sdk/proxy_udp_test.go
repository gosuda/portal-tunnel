package sdk

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestUDPFlowCapacityAndClose(t *testing.T) {
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	m := newUDPFlowManager(target, nil)
	defer m.Close()
	ctx := context.Background()
	var first *net.UDPConn
	for id := range types.DefaultUDPMaxFlows {
		conn, err := m.getOrCreate(ctx, types.DatagramFrame{FlowID: uint32(id)})
		if err != nil {
			t.Fatal(err)
		}
		if id == 0 {
			first = conn
		}
	}
	if _, err := m.getOrCreate(ctx, types.DatagramFrame{FlowID: types.DefaultUDPMaxFlows}); err == nil {
		t.Fatal("new flow admitted at capacity")
	}
	conn, err := m.getOrCreate(ctx, types.DatagramFrame{FlowID: 0})
	if err != nil || conn != first {
		t.Fatal("established flow lost at capacity")
	}
	m.Close()
	if _, err := first.Write([]byte("closed")); err == nil {
		t.Fatal("socket survived close")
	}
	if _, err := m.getOrCreate(ctx, types.DatagramFrame{}); err == nil {
		t.Fatal("flow admitted after close")
	}
}

func TestUDPFlowReaderCannotRemoveReplacement(t *testing.T) {
	m := newUDPFlowManager(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, nil)
	defer m.Close()
	frame := types.DatagramFrame{FlowID: 1}
	conn, err := m.getOrCreate(context.Background(), frame)
	if err != nil {
		t.Fatal(err)
	}
	key := udpFlowKey{flowID: 1}
	m.mu.Lock()
	old := m.flows[key]
	delete(m.flows, key)
	m.mu.Unlock()
	replacement, err := m.getOrCreate(context.Background(), frame)
	if err != nil {
		t.Fatal(err)
	}
	m.removeFlow(key, old)
	_ = conn.Close()
	m.mu.Lock()
	current := m.flows[key]
	m.mu.Unlock()
	if current == nil || current.conn != replacement {
		t.Fatal("old reader removed replacement")
	}
}

func TestUDPLeaseEndClosesLocalSocket(t *testing.T) {
	m := newUDPFlowManager(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, nil)
	defer m.Close()
	lease := make(chan struct{})
	conn, err := m.getOrCreate(context.Background(), types.DatagramFrame{FlowID: 1, LeaseDone: lease})
	if err != nil {
		t.Fatal(err)
	}
	close(lease)
	deadline := time.Now().Add(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		m.mu.Lock()
		remaining := len(m.flows)
		m.mu.Unlock()
		if remaining == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lease left local reader alive")
		}
		<-ticker.C
	}
	if _, err := conn.Write([]byte("closed")); err == nil {
		t.Fatal("lease socket survived")
	}
	if _, err := m.getOrCreate(context.Background(), types.DatagramFrame{FlowID: 1, LeaseDone: lease}); err == nil {
		t.Fatal("stale lease admitted")
	}
}

func TestUDPFlowCapacityIncludesDetachedReaders(t *testing.T) {
	m := newUDPFlowManager(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, nil)
	defer m.Close()
	// Keep the actual sockets/readers alive after removing lookup entries,
	// modelling the interval between retirement and reader completion.
	for id := range types.DefaultUDPMaxFlows {
		conn, err := m.getOrCreate(t.Context(), types.DatagramFrame{FlowID: uint32(id)})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
	}
	m.mu.Lock()
	clear(m.flows)
	m.mu.Unlock()
	if _, err := m.getOrCreate(t.Context(), types.DatagramFrame{FlowID: types.DefaultUDPMaxFlows}); err == nil {
		t.Fatal("detached live readers did not consume capacity")
	}
}

func TestUDPFlowOldReaderRejectsReplacement(t *testing.T) {
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	exposure := &Exposure{}
	exposure.options.UDPEnabled = true
	m := newUDPFlowManager(origin.LocalAddr().(*net.UDPAddr), exposure)
	defer m.Close()
	conn, err := m.getOrCreate(t.Context(), types.DatagramFrame{FlowID: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	replacementConn, err := net.DialUDP("udp", nil, origin.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	replacement := &udpFlowEntry{conn: replacementConn}
	key := udpFlowKey{flowID: 1}
	m.mu.Lock()
	m.flows[key] = replacement
	m.mu.Unlock()
	if _, err := origin.WriteToUDP([]byte("old reply"), conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	// The old reader must stop before touching the replacement or attempting
	// to relay this packet. The exposure has no connection, so a reader that
	// incorrectly continues through send would remain live.
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		m.mu.Lock()
		done := m.readers == 0
		intact := m.flows[key] == replacement && replacement.lastSeen.IsZero()
		m.mu.Unlock()
		if !intact {
			t.Fatal("old reader touched replacement")
		}
		if done {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("old reader continued through replacement")
		case <-ticker.C:
		}
	}
}

func TestUDPFlowTemporaryBackhaulFailurePreservesSocket(t *testing.T) {
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	// An actual exposure with no available relay returns net.ErrClosed from
	// SendDatagram, as it does during a temporary backhaul absence.
	exposure := &Exposure{}
	exposure.options.UDPEnabled = true
	m := newUDPFlowManager(origin.LocalAddr().(*net.UDPAddr), exposure)
	defer m.Close()
	conn, err := m.getOrCreate(t.Context(), types.DatagramFrame{FlowID: 1})
	if err != nil {
		t.Fatal(err)
	}
	key := udpFlowKey{flowID: 1}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for range 2 {
		m.mu.Lock()
		entry := m.flows[key]
		m.mu.Unlock()
		if entry == nil {
			t.Fatal("temporary send failure removed flow")
		}
		m.mu.Lock()
		before := entry.lastSeen
		m.mu.Unlock()
		if _, err := origin.WriteToUDP([]byte("reply"), conn.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		deadline := time.NewTimer(time.Second)
		for {
			m.mu.Lock()
			entry := m.flows[key]
			read := entry != nil && entry.lastSeen.After(before)
			m.mu.Unlock()
			if entry == nil {
				deadline.Stop()
				t.Fatal("temporary send failure removed flow")
			}
			if read {
				break
			}
			select {
			case <-deadline.C:
				t.Fatal("reader did not survive previous send failure")
			case <-ticker.C:
			}
		}
		deadline.Stop()
	}
	existing, err := m.getOrCreate(t.Context(), types.DatagramFrame{FlowID: 1})
	if err != nil || existing != conn {
		t.Fatal("same-lease socket was replaced")
	}
}
