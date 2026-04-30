package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	defaultMaxPacketSize       = 1350
	defaultFlowIdleTimeout     = 30 * time.Second
	defaultFlowCleanupInterval = 30 * time.Second
)

type flowState struct {
	key      string
	lastSeen time.Time
	reply    func([]byte) error
}

// RelayDatagram owns UDP ingress and QUIC backhaul binding for one lease.
type RelayDatagram struct {
	identityKey string
	port        int
	session     *datagramSession
	flowTable   map[uint32]*flowState
	addrIndex   map[string]uint32
	nextFlow    uint32

	conn *net.UDPConn

	cancel    context.CancelFunc
	closeOnce sync.Once
	mu        sync.Mutex
}

func NewRelayDatagram(identityKey string, port int) *RelayDatagram {
	d := &RelayDatagram{
		identityKey: identityKey,
		port:        port,
		session: newDatagramSession(256, true, func(err error) {
			log.Warn().
				Err(err).
				Str("component", "quic-backhaul").
				Str("identity_key", identityKey).
				Msg("quic backhaul receive loop ended")
		}),
		flowTable: make(map[uint32]*flowState),
		addrIndex: make(map[string]uint32),
		nextFlow:  1,
	}
	go d.runDispatchLoop()
	go d.runCleanupLoop()
	return d
}

func (d *RelayDatagram) Start(ctx context.Context) error {
	if d == nil || d.port <= 0 {
		return nil
	}

	addr := &net.UDPAddr{Port: d.port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp :%d: %w", d.port, err)
	}
	d.conn = conn

	relayCtx, cancel := context.WithCancel(ctx)
	d.cancel = cancel
	go d.readLoop(relayCtx)

	log.Info().
		Str("component", "udp-relay").
		Str("identity_key", d.identityKey).
		Int("port", d.port).
		Msg("udp relay started")

	return nil
}

func (d *RelayDatagram) Close() {
	if d == nil {
		return
	}

	d.closeOnce.Do(func() {
		if d.cancel != nil {
			d.cancel()
		}
		d.session.Stop("lease stopped")
		if d.conn != nil {
			_ = d.conn.Close()
		}
		log.Info().
			Str("component", "udp-relay").
			Str("identity_key", d.identityKey).
			Int("port", d.port).
			Msg("udp relay stopped")
	})
}

func (d *RelayDatagram) BindBackhaul(conn *quic.Conn) error {
	if _, err := d.session.Bind(conn); err != nil {
		return err
	}

	log.Info().
		Str("component", "quic-backhaul").
		Str("identity_key", d.identityKey).
		Str("remote_addr", conn.RemoteAddr().String()).
		Msg("quic backhaul connection registered")
	return nil
}

func (d *RelayDatagram) sendDatagram(flowID uint32, payload []byte) error {
	if d == nil {
		return net.ErrClosed
	}
	return d.session.Send(flowID, payload)
}

func (d *RelayDatagram) touchFlow(key string, reply func([]byte) error) uint32 {
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	if id, ok := d.addrIndex[key]; ok {
		if flow, exists := d.flowTable[id]; exists && flow != nil {
			flow.lastSeen = now
			if reply != nil {
				flow.reply = reply
			}
			return id
		}
		delete(d.addrIndex, key)
	}

	id := d.nextFlow
	d.nextFlow++
	d.flowTable[id] = &flowState{
		key:      key,
		lastSeen: now,
		reply:    reply,
	}
	d.addrIndex[key] = id
	return id
}

func (d *RelayDatagram) UDPPort() int {
	if d == nil {
		return 0
	}
	return d.port
}

func (d *RelayDatagram) runDispatchLoop() {
	for {
		select {
		case <-d.session.Done():
			return
		case frame := <-d.session.incoming:
			d.dispatch(frame)
		}
	}
}

func (d *RelayDatagram) dispatch(frame types.DatagramFrame) {
	d.mu.Lock()
	flow, ok := d.flowTable[frame.FlowID]
	if !ok || flow == nil || flow.reply == nil {
		d.mu.Unlock()
		return
	}

	flow.lastSeen = time.Now()
	reply := flow.reply
	d.mu.Unlock()

	if err := reply(frame.Payload); err != nil {
		log.Warn().
			Err(err).
			Str("component", "udp-relay").
			Str("identity_key", d.identityKey).
			Uint32("flow_id", frame.FlowID).
			Msg("flow writeback failed")
		d.forgetFlow(frame.FlowID)
	}
}

func (d *RelayDatagram) runCleanupLoop() {
	ticker := time.NewTicker(defaultFlowCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.session.Done():
			return
		case now := <-ticker.C:
			d.expireIdleFlows(now)
		}
	}
}

func (d *RelayDatagram) expireIdleFlows(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for flowID, flow := range d.flowTable {
		if flow == nil || now.Sub(flow.lastSeen) > defaultFlowIdleTimeout {
			if flow != nil {
				delete(d.addrIndex, flow.key)
			}
			delete(d.flowTable, flowID)
		}
	}
}

func (d *RelayDatagram) forgetFlow(flowID uint32) {
	d.mu.Lock()
	defer d.mu.Unlock()

	flow, ok := d.flowTable[flowID]
	if !ok {
		return
	}
	if flow != nil {
		delete(d.addrIndex, flow.key)
	}
	delete(d.flowTable, flowID)
}

func (d *RelayDatagram) readLoop(ctx context.Context) {
	buf := make([]byte, defaultMaxPacketSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = d.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, clientAddr, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			log.Warn().
				Str("component", "udp-relay").
				Str("identity_key", d.identityKey).
				Err(err).
				Msg("readLoop exiting: unexpected read error")
			return
		}

		flowID := d.touchFlow("udp:"+clientAddr.String(), func(payload []byte) error {
			_, err := d.conn.WriteToUDP(payload, clientAddr)
			return err
		})
		payload := make([]byte, n)
		copy(payload, buf[:n])

		if err := d.sendDatagram(flowID, payload); err != nil {
			log.Warn().
				Str("component", "udp-relay").
				Str("identity_key", d.identityKey).
				Err(err).
				Uint32("flow_id", flowID).
				Int("bytes", n).
				Msg("send datagram to quic backhaul failed, dropping packet")
			continue
		}
	}
}
