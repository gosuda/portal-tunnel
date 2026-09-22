package types

import (
	"encoding/binary"
	"errors"
	"time"
)

const DefaultUDPFlowIdleTimeout = 5 * time.Minute

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
