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
	"golang.org/x/time/rate"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	defaultFlowCleanupInterval = 30 * time.Second
)

type flowState struct {
	addr     netip.AddrPort
	lastSeen time.Time
}

// RelayDatagram owns UDP ingress and QUIC backhaul binding for one lease.
type RelayDatagram struct {
	identityKey types.ServiceIdentityKey
	port        int
	session     *DatagramSession
	flowTable   map[uint32]*flowState
	addrIndex   map[netip.AddrPort]uint32
	nextFlow    uint32
	enabled     atomic.Bool
	newFlows    *rate.Limiter
	dropLogs    *rate.Limiter
	inBytes     atomic.Int64
	outBytes    atomic.Int64
	inPackets   atomic.Int64
	outPackets  atomic.Int64

	conn *net.UDPConn

	started bool
	mu      sync.Mutex
}

func NewRelayDatagram(identityKey types.ServiceIdentityKey, port int) *RelayDatagram {
	return &RelayDatagram{
		identityKey: identityKey,
		port:        port,
		session:     NewDatagramSession(256, true),
		flowTable:   make(map[uint32]*flowState),
		addrIndex:   make(map[netip.AddrPort]uint32),
		nextFlow:    1,
		newFlows:    rate.NewLimiter(types.DefaultUDPNewFlowsPerSecond, types.DefaultUDPNewFlowBurst),
		dropLogs:    rate.NewLimiter(rate.Every(time.Second), 1),
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
		Str("identity_key", d.identityKey.String()).
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
	clear(d.flowTable)
	clear(d.addrIndex)
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
				Str("identity_key", d.identityKey.String()).
				Msg("quic backhaul receive loop ended")
		}
	}()

	log.Info().
		Str("component", "quic-backhaul").
		Str("identity_key", d.identityKey.String()).
		Str("remote_addr", conn.RemoteAddr().String()).
		Msg("quic backhaul connection registered")
	return nil
}

func (d *RelayDatagram) touchFlow(addr netip.AddrPort, now time.Time) (id uint32, fresh, admitted bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	select {
	case <-d.session.Done():
		return 0, false, false
	default:
	}

	if id, ok := d.addrIndex[addr]; ok {
		if flow, exists := d.flowTable[id]; exists && flow != nil {
			flow.lastSeen = now
			return id, false, true
		}
		delete(d.addrIndex, addr)
	}

	if len(d.flowTable) >= types.DefaultUDPMaxFlows || !d.newFlows.AllowN(now, 1) {
		return 0, false, false
	}

	// The bounded table always leaves a free uint32 ID. Skip live IDs when
	// the counter wraps; zero is also a valid wire ID.
	for {
		id = d.nextFlow
		d.nextFlow++
		if _, exists := d.flowTable[id]; !exists {
			break
		}
	}
	d.flowTable[id] = &flowState{
		addr:     addr,
		lastSeen: now,
	}
	d.addrIndex[addr] = id
	return id, true, true
}

func (d *RelayDatagram) UDPPort() int {
	if d == nil {
		return 0
	}
	return d.port
}

func (d *RelayDatagram) ActiveFlowCount() int64 {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return int64(len(d.flowTable))
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
	if !d.enabled.Load() || len(frame.Payload) > types.MaxUDPPayloadSize {
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
	if n, err := conn.WriteToUDPAddrPort(frame.Payload, addr); err != nil {
		if d.dropLogs.Allow() {
			log.Warn().Err(err).Str("component", "udp-relay").
				Str("identity_key", d.identityKey.String()).
				Msg("flow writeback failed; further packet drops may be suppressed")
		}
		d.forgetFlow(frame.FlowID)
	} else {
		d.outBytes.Add(int64(n))
		d.outPackets.Add(1)
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
	// A full UDP receive buffer avoids Unix prefix forwarding and Windows
	// WSAEMSGSIZE errors. Unsupported payloads are dropped whole below.
	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := d.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Warn().
				Str("component", "udp-relay").
				Str("identity_key", d.identityKey.String()).
				Err(err).
				Msg("readLoop exiting: unexpected read error")
			return
		}
		d.forwardDatagram(clientAddr, buf[:n])
	}
}

// forwardDatagram admits state only for usable backhauls. A failed first send
// rolls the new entry back; its admission token remains spent to bound churn.
func (d *RelayDatagram) forwardDatagram(addr netip.AddrPort, payload []byte) {
	if !d.enabled.Load() || len(payload) > types.MaxUDPPayloadSize || !d.session.Connected() {
		return
	}
	flowID, fresh, admitted := d.touchFlow(addr, time.Now())
	if !admitted {
		return
	}
	if !d.enabled.Load() {
		if fresh {
			d.forgetFlow(flowID)
		}
		return
	}
	if err := d.session.Send(flowID, payload); err != nil {
		if fresh {
			d.forgetFlow(flowID)
		}
		if d.dropLogs.Allow() {
			log.Warn().Err(err).Str("component", "udp-relay").
				Str("identity_key", d.identityKey.String()).
				Msg("send to quic backhaul failed; further packet drops may be suppressed")
		}
	} else {
		d.inBytes.Add(int64(len(payload)))
		d.inPackets.Add(1)
	}
}

// TrafficStats counts successfully forwarded payload, excluding network framing.
func (d *RelayDatagram) TrafficStats() (inBytes, outBytes, inPackets, outPackets int64) {
	return d.inBytes.Load(), d.outBytes.Load(), d.inPackets.Load(), d.outPackets.Load()
}
