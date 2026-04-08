package types

import (
	"encoding/binary"
	"errors"
)

// ErrDatagramTooSmall is returned when a datagram payload is too short to
// contain a valid flow ID varint.
var (
	ErrDatagramTooSmall        = errors.New("datagram too small to decode")
	ErrDatagramUnsupportedFlag = errors.New("datagram has unsupported flags")
)

// DatagramFrame carries one relayed datagram.
type DatagramFrame struct {
	FlowID   uint32
	Payload  []byte
	Address  string
	RelayURL string
	UDPAddr  string

	Segmented    bool
	MessageID    uint64
	SegmentIndex uint16
	SegmentCount uint16
}

const (
	DatagramFlagNone      = byte(0x00)
	DatagramFlagSegmented = byte(0x01)

	// DefaultDatagramSegmentPayload limits one segment payload for long packets.
	DefaultDatagramSegmentPayload = 1024
)

// EncodeDatagram serialises a non-segmented flow-framed datagram for transmission.
// Wire layout: [flowID varint][flags=DatagramFlagNone][payload bytes]
func EncodeDatagram(flowID uint32, payload []byte) []byte {
	var buf [binary.MaxVarintLen32]byte
	n := binary.PutUvarint(buf[:], uint64(flowID))
	out := make([]byte, n+1+len(payload))
	copy(out, buf[:n])
	out[n] = DatagramFlagNone
	copy(out[n+1:], payload)
	return out
}

// EncodeSegmentedDatagram serialises one segmented frame.
// Wire layout:
// [flowID varint][flags=DatagramFlagSegmented][messageID varint][segmentIndex varint][segmentCount varint][payload]
func EncodeSegmentedDatagram(flowID uint32, messageID uint64, segmentIndex, segmentCount uint16, payload []byte) []byte {
	var flowBuf [binary.MaxVarintLen32]byte
	var msgBuf [binary.MaxVarintLen64]byte
	var idxBuf [binary.MaxVarintLen32]byte
	var cntBuf [binary.MaxVarintLen32]byte

	flowN := binary.PutUvarint(flowBuf[:], uint64(flowID))
	msgN := binary.PutUvarint(msgBuf[:], messageID)
	idxN := binary.PutUvarint(idxBuf[:], uint64(segmentIndex))
	cntN := binary.PutUvarint(cntBuf[:], uint64(segmentCount))

	out := make([]byte, flowN+1+msgN+idxN+cntN+len(payload))
	pos := 0
	copy(out[pos:], flowBuf[:flowN])
	pos += flowN
	out[pos] = DatagramFlagSegmented
	pos++
	copy(out[pos:], msgBuf[:msgN])
	pos += msgN
	copy(out[pos:], idxBuf[:idxN])
	pos += idxN
	copy(out[pos:], cntBuf[:cntN])
	pos += cntN
	copy(out[pos:], payload)
	return out
}

// DecodeDatagram deserialises a flow-framed datagram.
func DecodeDatagram(data []byte) (DatagramFrame, error) {
	flowID, n := binary.Uvarint(data)
	if n <= 0 {
		return DatagramFrame{}, ErrDatagramTooSmall
	}
	if n >= len(data) {
		return DatagramFrame{
			FlowID: uint32(flowID),
		}, nil
	}

	flags := data[n]
	if flags != DatagramFlagNone && flags != DatagramFlagSegmented {
		return DatagramFrame{}, ErrDatagramUnsupportedFlag
	}
	if flags == DatagramFlagNone {
		return DatagramFrame{
			FlowID:  uint32(flowID),
			Payload: data[n+1:],
		}, nil
	}

	pos := n + 1
	messageID, read := binary.Uvarint(data[pos:])
	if read <= 0 {
		return DatagramFrame{}, ErrDatagramTooSmall
	}
	pos += read
	segmentIndex, read := binary.Uvarint(data[pos:])
	if read <= 0 {
		return DatagramFrame{}, ErrDatagramTooSmall
	}
	pos += read
	segmentCount, read := binary.Uvarint(data[pos:])
	if read <= 0 {
		return DatagramFrame{}, ErrDatagramTooSmall
	}
	pos += read
	return DatagramFrame{
		FlowID:       uint32(flowID),
		Payload:      data[pos:],
		Segmented:    true,
		MessageID:    messageID,
		SegmentIndex: uint16(segmentIndex),
		SegmentCount: uint16(segmentCount),
	}, nil
}
