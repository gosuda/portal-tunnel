package types

import (
	"encoding/binary"
	"testing"
)

func TestDecodeDatagramRejectsFlowIDOverflow(t *testing.T) {
	var encoded [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(encoded[:], uint64(^uint32(0))+1)

	if frame, err := DecodeDatagram(encoded[:n]); err == nil {
		t.Fatalf("DecodeDatagram() accepted overflowing flow ID as %d", frame.FlowID)
	}
}

func TestDatagramRoundTripPreservesMaximumFlowID(t *testing.T) {
	payload := []byte("payload")
	decoded, err := DecodeDatagram(EncodeDatagram(^uint32(0), payload))
	if err != nil {
		t.Fatalf("DecodeDatagram() error = %v", err)
	}
	if decoded.FlowID != ^uint32(0) || string(decoded.Payload) != string(payload) {
		t.Fatalf("decoded frame = %+v, want maximum uint32 flow ID and payload %q", decoded, payload)
	}
}
