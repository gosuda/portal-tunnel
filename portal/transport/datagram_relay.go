package transport

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	defaultMaxPacketSize       = 1350
	defaultFlowCleanupInterval = 30 * time.Second
)

type flowState struct {
	addr     netip.AddrPort
	lastSeen time.Time
}

// RelayDatagram owns UDP ingress and QUIC backhaul binding for one lease.
type RelayDatagram struct {
	identityKey string
	port        int
	session     *DatagramSession
	flowTable   map[uint32]*flowState
	addrIndex   map[netip.AddrPort]uint32
	nextFlow    uint32
	enabled     atomic.Bool

	conn *net.UDPConn

	started bool
	mu      sync.Mutex
}

func NewRelayDatagram(identityKey string, port int) *RelayDatagram {
	return &RelayDatagram{
		identityKey: identityKey,
		port:        port,
		session:     NewDatagramSession(256, true),
		flowTable:   make(map[uint32]*flowState),
		addrIndex:   make(map[netip.AddrPort]uint32),
		nextFlow:    1,
	}
}

// Start acquires UDP ingress and starts the owned workers once. Construction
// and failed starts leave no goroutines running; a closed endpoint cannot restart.
func (d *RelayDatagram) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case <-d.session.Done():
		return net.ErrClosed
	default:
	}
	if d.started {
		return nil
	}
	if d.port > 0 {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: d.port})
		if err != nil {
			return fmt.Errorf("listen udp :%d: %w", d.port, err)
		}
		d.conn = conn
		go d.readLoop()
	}
	d.started = true
	go d.runDispatchLoop()
	go d.runCleanupLoop()

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

	d.mu.Lock()
	d.session.Close("lease stopped")
	conn := d.conn
	d.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (d *RelayDatagram) BindBackhaul(conn *quic.Conn) error {
	recvDone, err := d.session.Bind(conn)
	if err != nil {
		return err
	}
	go func() {
		if err := <-recvDone; err != nil {
			log.Warn().
				Err(err).
				Str("component", "quic-backhaul").
				Str("identity_key", d.identityKey).
				Msg("quic backhaul receive loop ended")
		}
	}()

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

func (d *RelayDatagram) touchFlow(addr netip.AddrPort) uint32 {
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	if id, ok := d.addrIndex[addr]; ok {
		if flow, exists := d.flowTable[id]; exists && flow != nil {
			flow.lastSeen = now
			return id
		}
		delete(d.addrIndex, addr)
	}

	id := d.nextFlow
	d.nextFlow++
	d.flowTable[id] = &flowState{
		addr:     addr,
		lastSeen: now,
	}
	d.addrIndex[addr] = id
	return id
}

func (d *RelayDatagram) UDPPort() int {
	if d == nil {
		return 0
	}
	return d.port
}

// SetEnabled gates traffic in both directions while keeping the socket bound.
func (d *RelayDatagram) SetEnabled(enabled bool) {
	if d == nil {
		return
	}
	d.enabled.Store(enabled)
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
	if !d.enabled.Load() {
		return
	}
	d.mu.Lock()
	flow, ok := d.flowTable[frame.FlowID]
	if !ok || flow == nil || d.conn == nil {
		d.mu.Unlock()
		return
	}

	flow.lastSeen = time.Now()
	addr := flow.addr
	conn := d.conn
	d.mu.Unlock()

	if !d.enabled.Load() {
		return
	}
	if _, err := conn.WriteToUDPAddrPort(frame.Payload, addr); err != nil {
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
		if flow == nil || now.Sub(flow.lastSeen) > types.DefaultUDPFlowIdleTimeout {
			if flow != nil {
				delete(d.addrIndex, flow.addr)
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
		delete(d.addrIndex, flow.addr)
	}
	delete(d.flowTable, flowID)
}

func (d *RelayDatagram) readLoop() {
	buf := make([]byte, defaultMaxPacketSize)
	for {
		n, clientAddr, err := d.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Warn().
				Str("component", "udp-relay").
				Str("identity_key", d.identityKey).
				Err(err).
				Msg("readLoop exiting: unexpected read error")
			return
		}
		if !d.enabled.Load() {
			continue
		}

		flowID := d.touchFlow(clientAddr)
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
