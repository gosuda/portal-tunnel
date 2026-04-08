package overlay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/gosuda/portal-tunnel/v2/portal/policy"
)

const (
	Version uint8 = 1

	// FlagKeepalive is set in Header.Flags for keepalive packets so that
	// the keepalive state is explicit without inspecting MsgType alone.
	FlagKeepalive uint8 = 1 << 0

	LinkHello  uint8 = 1
	RouteSetup uint8 = 2
	FlowOpen   uint8 = 3
	FlowClose  uint8 = 4
	Data       uint8 = 5
	Error      uint8 = 6
	Keepalive  uint8 = 7

	ErrorRouteNotFound      uint8 = 1
	ErrorNextHopUnavailable uint8 = 2
	ErrorTTLExpired         uint8 = 3
)

// headerSize is the on-wire size of a pepper-protocol header in bytes.
//
// Wire layout (24 bytes):
//
//	[0]     Version    uint8
//	[1]     Flags      uint8   – FlagKeepalive = 0x01
//	[2]     MsgType    uint8
//	[3]     ErrorCode  uint8   – 0 = no error
//	[4:8]   RouteID    uint32  – big-endian
//	[8:12]  FlowID     uint32  – big-endian
//	[12]    TTL        uint8
//	[13]    MaxHops    uint8   – maximum hops allowed for this route
//	[14:18] SrcNode    uint32  – originating node ID, big-endian
//	[18:22] DstNode    uint32  – destination node ID, big-endian
//	[22:24] BodyLength uint16  – big-endian
const headerSize = 24

// Header is the fixed-size pepper-protocol frame header.
// Every field is transmitted big-endian on the wire.
type Header struct {
	Version   uint8
	Flags     uint8  // FlagKeepalive and future flag bits
	MsgType   uint8
	ErrorCode uint8  // non-zero on Error messages
	RouteID   uint32
	FlowID    uint32
	TTL       uint8
	MaxHops   uint8  // maximum number of relay hops permitted
	SrcNode   uint32 // originating relay node ID
	DstNode   uint32 // destination relay node ID
	BodyLength uint16
}

type Relay struct {
	NodeID uint32

	mu          sync.RWMutex
	neighbors   map[uint32]*quic.Conn
	routes      map[uint32]uint32
	reverse     map[uint32]uint32
	ingressFlow map[uint32]*ingressRetry
}

type ingressRetry struct {
	flowID     uint32
	routes     [][]uint32
	routeIndex int
	attempts   int
	payload    []byte
}

func NewRelay(nodeID uint32) *Relay {
	return &Relay{
		NodeID:      nodeID,
		neighbors:   make(map[uint32]*quic.Conn),
		routes:      make(map[uint32]uint32),
		reverse:     make(map[uint32]uint32),
		ingressFlow: make(map[uint32]*ingressRetry),
	}
}

func Encode(h Header, body []byte) []byte {
	buf := make([]byte, headerSize+len(body))
	buf[0] = h.Version
	buf[1] = h.Flags
	buf[2] = h.MsgType
	buf[3] = h.ErrorCode
	binary.BigEndian.PutUint32(buf[4:8], h.RouteID)
	binary.BigEndian.PutUint32(buf[8:12], h.FlowID)
	buf[12] = h.TTL
	buf[13] = h.MaxHops
	binary.BigEndian.PutUint32(buf[14:18], h.SrcNode)
	binary.BigEndian.PutUint32(buf[18:22], h.DstNode)
	binary.BigEndian.PutUint16(buf[22:24], uint16(len(body)))
	copy(buf[headerSize:], body)
	return buf
}

func Decode(packet []byte) (Header, []byte, error) {
	if len(packet) < headerSize {
		return Header{}, nil, errors.New("short packet")
	}
	h := Header{
		Version:    packet[0],
		Flags:      packet[1],
		MsgType:    packet[2],
		ErrorCode:  packet[3],
		RouteID:    binary.BigEndian.Uint32(packet[4:8]),
		FlowID:     binary.BigEndian.Uint32(packet[8:12]),
		TTL:        packet[12],
		MaxHops:    packet[13],
		SrcNode:    binary.BigEndian.Uint32(packet[14:18]),
		DstNode:    binary.BigEndian.Uint32(packet[18:22]),
		BodyLength: binary.BigEndian.Uint16(packet[22:24]),
	}
	if int(h.BodyLength) != len(packet)-headerSize {
		return Header{}, nil, errors.New("invalid body length")
	}
	if h.Version != Version {
		return Header{}, nil, errors.New("unsupported version")
	}
	return h, packet[headerSize:], nil
}

func (r *Relay) AddNeighbor(nodeID uint32, conn *quic.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.neighbors[nodeID] = conn
}

func (r *Relay) StartNeighborLoop(ctx context.Context, nodeID uint32) error {
	r.mu.RLock()
	conn, ok := r.neighbors[nodeID]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("neighbor %d not found", nodeID)
	}
	for {
		pkt, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return err
		}
		r.HandlePacket(nodeID, pkt)
	}
}

func (r *Relay) SendLinkHello(nodeID uint32) error {
	return r.sendTo(nodeID, Header{Version: Version, MsgType: LinkHello, TTL: 1}, nil)
}

func (r *Relay) SendKeepalive(nodeID uint32) error {
	return r.sendTo(nodeID, Header{Version: Version, Flags: FlagKeepalive, MsgType: Keepalive, TTL: 1}, nil)
}

func (r *Relay) OpenFlowIngress(routeID, flowID uint32, routeOptions [][]uint32, payload []byte) error {
	if len(routeOptions) == 0 {
		return errors.New("route options empty")
	}
	st := &ingressRetry{
		flowID:     flowID,
		routes:     routeOptions,
		routeIndex: 0,
		attempts:   1,
		payload:    append([]byte(nil), payload...),
	}
	r.mu.Lock()
	r.ingressFlow[routeID] = st
	r.mu.Unlock()
	return r.sendIngressAttempt(routeID, st)
}

func (r *Relay) OpenFlowIngressWithPolicy(routeID, flowID uint32, candidates []uint32, maxHops int, payload []byte, load policy.NodeLoad, congestionLatencyMs float64) error {
	planner := NewRoutePolicy()
	route, err := planner.BuildRouteWithLoad(r.NodeID, candidates, maxHops, load, congestionLatencyMs)
	if err != nil {
		return err
	}
	return r.OpenFlowIngress(routeID, flowID, [][]uint32{route}, payload)
}

func (r *Relay) HandlePacket(from uint32, packet []byte) {
	h, body, err := Decode(packet)
	if err != nil {
		return
	}
	switch h.MsgType {
	case LinkHello:
		return
	case Keepalive:
		return
	case RouteSetup:
		r.handleRouteSetup(from, h, body)
	case FlowOpen, FlowClose, Data:
		r.forwardDataLike(from, h, body)
	case Error:
		r.handleError(h, body)
	}
}

func (r *Relay) handleRouteSetup(from uint32, h Header, body []byte) {
	hops, err := decodeHopList(body)
	if err != nil {
		r.sendErrorUpstream(from, h.RouteID, h.FlowID, ErrorRouteNotFound)
		return
	}
	idx := -1
	for i := range hops {
		if hops[i] == r.NodeID {
			idx = i
			break
		}
	}
	if idx < 0 {
		r.sendErrorUpstream(from, h.RouteID, h.FlowID, ErrorRouteNotFound)
		return
	}
	prev := uint32(0)
	if idx > 0 {
		prev = hops[idx-1]
	}
	next := uint32(0)
	if idx+1 < len(hops) {
		next = hops[idx+1]
	}

	r.mu.Lock()
	r.reverse[h.RouteID] = prev
	if next != 0 {
		r.routes[h.RouteID] = next
	} else {
		delete(r.routes, h.RouteID)
	}
	r.mu.Unlock()

	if next == 0 {
		return
	}
	if h.TTL <= 1 {
		r.sendErrorBackward(h.RouteID, h.FlowID, ErrorTTLExpired)
		return
	}
	h.TTL--
	if err := r.sendTo(next, h, body); err != nil {
		r.sendErrorBackward(h.RouteID, h.FlowID, ErrorNextHopUnavailable)
	}
}

func (r *Relay) forwardDataLike(from uint32, h Header, body []byte) {
	r.mu.RLock()
	next, ok := r.routes[h.RouteID]
	if !ok {
		if prev, hasPrev := r.reverse[h.RouteID]; hasPrev {
			r.mu.RUnlock()
			r.sendErrorUpstream(prev, h.RouteID, h.FlowID, ErrorRouteNotFound)
			return
		}
	}
	if ok {
		r.mu.RUnlock()
	} else {
		r.mu.RUnlock()
		r.sendErrorUpstream(from, h.RouteID, h.FlowID, ErrorRouteNotFound)
		return
	}
	if h.TTL <= 1 {
		r.sendErrorBackward(h.RouteID, h.FlowID, ErrorTTLExpired)
		return
	}
	h.TTL--
	if err := r.sendTo(next, h, body); err != nil {
		r.sendErrorBackward(h.RouteID, h.FlowID, ErrorNextHopUnavailable)
	}
}

func (r *Relay) handleError(h Header, body []byte) {
	_, err := decodeErrorBody(body)
	if err != nil {
		return
	}

	r.mu.RLock()
	st, ingress := r.ingressFlow[h.RouteID]
	prev, hasPrev := r.reverse[h.RouteID]
	r.mu.RUnlock()

	if ingress {
		r.retryIngress(h.RouteID, st)
		return
	}
	if hasPrev {
		err := r.sendTo(prev, h, body)
		if err != nil {
			return
		}
	}
}

func (r *Relay) retryIngress(routeID uint32, st *ingressRetry) {
	time.Sleep(1 * time.Second)

	r.mu.Lock()
	defer r.mu.Unlock()
	if st.attempts >= 5 {
		delete(r.ingressFlow, routeID)
		return
	}
	next := -1
	for i := 1; i <= len(st.routes); i++ {
		candidate := (st.routeIndex + i) % len(st.routes)
		if candidate != st.routeIndex {
			next = candidate
			break
		}
	}
	if next < 0 {
		delete(r.ingressFlow, routeID)
		return
	}
	st.routeIndex = next
	st.attempts++
	go func() {
		err := r.sendIngressAttempt(routeID, st)
		if err != nil {
			return
		}
	}()
}

func (r *Relay) sendIngressAttempt(routeID uint32, st *ingressRetry) error {
	hops := st.routes[st.routeIndex]
	if len(hops) < 2 {
		return errors.New("route must include ingress and at least one next hop")
	}
	if hops[0] != r.NodeID {
		return errors.New("ingress must be first hop")
	}
	next := hops[1]
	body := encodeHopList(hops)
	setup := Header{Version: Version, MsgType: RouteSetup, RouteID: routeID, FlowID: st.flowID, TTL: 32}
	if err := r.sendTo(next, setup, body); err != nil {
		return err
	}
	open := Header{Version: Version, MsgType: FlowOpen, RouteID: routeID, FlowID: st.flowID, TTL: 32}
	if err := r.sendTo(next, open, nil); err != nil {
		return err
	}
	if len(st.payload) > 0 {
		d := Header{Version: Version, MsgType: Data, RouteID: routeID, FlowID: st.flowID, TTL: 32}
		if err := r.sendTo(next, d, st.payload); err != nil {
			return err
		}
	}

	r.mu.Lock()
	r.routes[routeID] = next
	r.reverse[routeID] = 0
	r.mu.Unlock()
	return nil
}

func (r *Relay) sendErrorBackward(routeID, flowID uint32, code uint8) {
	r.mu.RLock()
	prev, ok := r.reverse[routeID]
	r.mu.RUnlock()
	if !ok {
		return
	}
	r.sendErrorUpstream(prev, routeID, flowID, code)
}

func (r *Relay) sendErrorUpstream(to, routeID, flowID uint32, code uint8) {
	if to == 0 {
		return
	}
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body[0:4], r.NodeID)
	h := Header{Version: Version, MsgType: Error, ErrorCode: code, RouteID: routeID, FlowID: flowID, TTL: 32}
	_ = r.sendTo(to, h, body)
}

func (r *Relay) sendTo(nodeID uint32, h Header, body []byte) error {
	r.mu.RLock()
	conn, ok := r.neighbors[nodeID]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("neighbor %d not connected", nodeID)
	}
	packet := Encode(h, body)
	return conn.SendDatagram(packet)
}

func encodeHopList(hops []uint32) []byte {
	buf := make([]byte, 1+len(hops)*4)
	buf[0] = uint8(len(hops))
	off := 1
	for _, hop := range hops {
		binary.BigEndian.PutUint32(buf[off:off+4], hop)
		off += 4
	}
	return buf
}

func decodeHopList(body []byte) ([]uint32, error) {
	if len(body) < 1 {
		return nil, errors.New("missing hop count")
	}
	count := int(body[0])
	if count == 0 {
		return nil, errors.New("empty hop list")
	}
	if len(body) != 1+count*4 {
		return nil, errors.New("invalid hop list length")
	}
	hops := make([]uint32, count)
	off := 1
	for i := 0; i < count; i++ {
		hops[i] = binary.BigEndian.Uint32(body[off : off+4])
		off += 4
	}
	return hops, nil
}

func decodeErrorBody(body []byte) (uint32, error) {
	if len(body) != 4 {
		return 0, errors.New("invalid error body")
	}
	nodeID := binary.BigEndian.Uint32(body[0:4])
	return nodeID, nil
}
