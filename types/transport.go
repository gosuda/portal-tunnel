package types

import (
	"encoding/binary"
	"errors"
	"time"
)

const (
	DefaultUDPFlowIdleTimeout   = 5 * time.Minute
	DefaultUDPMaxFlows          = 1024
	DefaultUDPNewFlowsPerSecond = 64
	DefaultUDPNewFlowBurst      = 128
	// QUICInitialPacketSize is the backhaul packet size and its lower limit.
	QUICInitialPacketSize = 1280
	// quic-go v0.59.0 reserves 37 bytes from the packet size for DATAGRAM
	// overhead. Reserve the largest flow-ID varint as well (1238-byte payload).
	MaxUDPPayloadSize = QUICInitialPacketSize - 37 - binary.MaxVarintLen32
)

var (
	errDatagramTooSmall       = errors.New("datagram too small to decode")
	errDatagramFlowIDOverflow = errors.New("datagram flow ID overflows uint32")
)

// DatagramFrame carries one relayed datagram.
// Wire encoding uses only FlowID and Payload with layout:
// [flowID varint][payload bytes]
type DatagramFrame struct {
	FlowID   uint32
	Payload  []byte
	Address  string
	RelayURL string
	UDPAddr  string
	// LeaseDone identifies local lease ownership; it is never encoded on wire.
	// Preserve it when replying to an accepted frame.
	LeaseDone <-chan struct{} `json:"-"`
}

// EncodeDatagram serialises a flow-framed datagram for transmission.
func EncodeDatagram(flowID uint32, payload []byte) []byte {
	var buf [binary.MaxVarintLen32]byte
	n := binary.PutUvarint(buf[:], uint64(flowID))
	out := make([]byte, n+len(payload))
	copy(out, buf[:n])
	copy(out[n:], payload)
	return out
}

// DecodeDatagram deserialises a flow-framed datagram.
func DecodeDatagram(data []byte) (DatagramFrame, error) {
	flowID, n := binary.Uvarint(data)
	if n <= 0 {
		return DatagramFrame{}, errDatagramTooSmall
	}
	if flowID > uint64(^uint32(0)) {
		return DatagramFrame{}, errDatagramFlowIDOverflow
	}
	return DatagramFrame{
		FlowID:  uint32(flowID),
		Payload: data[n:],
	}, nil
}
