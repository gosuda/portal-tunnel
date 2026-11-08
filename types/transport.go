package types

import (
	"encoding/binary"
	"time"
)

// Reverse stream activation markers precede application traffic.
const (
	ReverseMarkerKeepalive = 0x00
	ReverseMarkerRawStart  = 0x01
	ReverseMarkerTLSStart  = 0x02
	// TLSBindingSize binds one reverse connection to keyless transcript signing.
	TLSBindingSize = 16
)

const (
	QUICBackhaulALPN        = "portal-tunnel"
	KeylessRelayKeyID       = "relay-cert"
	OverlayCapabilityPrefix = "ov1"
	OverlayStreamPort       = "4017"
)

// Overlay reverse-offer responses. Older peers treat pending and denied as unavailable.
const (
	OverlayStatusUnavailable = byte(0)
	OverlayStatusAccepted    = byte(1)
	OverlayStatusCapacity    = byte(2)
	OverlayStatusPending     = byte(3)
	OverlayStatusDenied      = byte(4)
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
