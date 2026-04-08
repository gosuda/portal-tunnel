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

var errNoConnection = errors.New("no quic connection registered")

const (
	maxDatagramSegments     = 64
	reassemblyEntryTTL      = 30 * time.Second
	reassemblyCleanupPeriod = 5 * time.Second
)

// datagramSession owns one active QUIC DATAGRAM connection and exposes decoded frames.
type datagramSession struct {
	incoming       chan types.DatagramFrame
	dropIncoming   bool
	onReceiveError func(error)
	done           chan struct{}

	mu     sync.Mutex
	conn   *quic.Conn
	closed bool

	nextMessageID uint64
}

func newDatagramSession(bufferSize int, dropIncoming bool, onReceiveError func(error)) *datagramSession {
	if bufferSize <= 0 {
		bufferSize = 256
	}

	return &datagramSession{
		incoming:       make(chan types.DatagramFrame, bufferSize),
		dropIncoming:   dropIncoming,
		onReceiveError: onReceiveError,
		done:           make(chan struct{}),
	}
}

// Bind installs a new active QUIC connection and starts the receive loop.
// Any previously active connection is replaced and closed.
func (s *datagramSession) Bind(conn *quic.Conn) (<-chan struct{}, error) {
	if conn == nil {
		return nil, errors.New("quic connection is required")
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = conn.CloseWithError(0, "session closed")
		return nil, net.ErrClosed
	}
	old := s.conn
	s.conn = conn
	s.mu.Unlock()

	if old != nil {
		_ = old.CloseWithError(0, "replaced")
	}

	recvDone := make(chan struct{})
	go s.receiveLoop(conn, recvDone)
	return recvDone, nil
}

func (s *datagramSession) Done() <-chan struct{} {
	return s.done
}

func (s *datagramSession) hasConnection() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn != nil && !s.closed
}

func (s *datagramSession) Send(flowID uint32, payload []byte) error {
	// Send may be called concurrently by multiple goroutines (per-flow workers).
	// nextMessageID is advanced under the session mutex so segmented message IDs
	// remain unique per active session.
	s.mu.Lock()
	conn := s.conn
	closed := s.closed
	s.nextMessageID++
	messageID := s.nextMessageID
	s.mu.Unlock()

	if closed {
		return net.ErrClosed
	}
	if conn == nil {
		return errNoConnection
	}
	if len(payload) <= types.DefaultDatagramSegmentPayload {
		return conn.SendDatagram(types.EncodeDatagram(flowID, payload))
	}

	segmentCount := (len(payload) + types.DefaultDatagramSegmentPayload - 1) / types.DefaultDatagramSegmentPayload
	if segmentCount > maxDatagramSegments {
		return fmt.Errorf("datagram payload too large to segment: %d bytes", len(payload))
	}

	totalSegments := uint16(segmentCount)
	for i := 0; i < segmentCount; i++ {
		start := i * types.DefaultDatagramSegmentPayload
		end := start + types.DefaultDatagramSegmentPayload
		if end > len(payload) {
			end = len(payload)
		}
		frame := types.EncodeSegmentedDatagram(flowID, messageID, uint16(i), totalSegments, payload[start:end])
		if err := conn.SendDatagram(frame); err != nil {
			return err
		}
	}
	return nil
}

// Clear closes the active connection but keeps the session reusable.
func (s *datagramSession) Clear(reason string) {
	s.mu.Lock()
	conn := s.conn
	s.conn = nil
	s.mu.Unlock()

	if conn != nil {
		_ = conn.CloseWithError(0, reason)
	}
}

// Stop permanently closes the session and any active connection.
func (s *datagramSession) Stop(reason string) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	conn := s.conn
	s.conn = nil
	close(s.done)
	s.mu.Unlock()

	if conn != nil {
		_ = conn.CloseWithError(0, reason)
	}
}

func (s *datagramSession) receiveLoop(conn *quic.Conn, recvDone chan struct{}) {
	defer close(recvDone)
	type reassemblyKey struct {
		flowID    uint32
		messageID uint64
	}
	type reassemblyEntry struct {
		count       uint16
		segments    map[uint16][]byte
		totalBytes  int
		lastUpdated time.Time
	}
	reassembly := make(map[reassemblyKey]*reassemblyEntry)
	lastCleanup := time.Now()

	for {
		data, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			s.mu.Lock()
			isActive := s.conn == conn
			if isActive {
				s.conn = nil
			}
			closed := s.closed
			onReceiveError := s.onReceiveError
			s.mu.Unlock()

			if isActive && !closed && onReceiveError != nil {
				onReceiveError(err)
			}
			return
		}

		frame, err := types.DecodeDatagram(data)
		if err != nil {
			continue
		}
		if frame.Segmented {
			if frame.SegmentCount == 0 || frame.SegmentIndex >= frame.SegmentCount || frame.SegmentCount > maxDatagramSegments {
				continue
			}
			key := reassemblyKey{flowID: frame.FlowID, messageID: frame.MessageID}
			entry := reassembly[key]
			if entry == nil {
				entry = &reassemblyEntry{
					count:       frame.SegmentCount,
					segments:    make(map[uint16][]byte, int(frame.SegmentCount)),
					lastUpdated: time.Now(),
				}
				reassembly[key] = entry
			}
			if entry.count != frame.SegmentCount {
				log.Warn().
					Uint32("flow_id", frame.FlowID).
					Uint64("message_id", frame.MessageID).
					Uint16("expected_segment_count", entry.count).
					Uint16("received_segment_count", frame.SegmentCount).
					Msg("datagram segmentation protocol mismatch; dropping reassembly entry")
				delete(reassembly, key)
				continue
			}
			if _, exists := entry.segments[frame.SegmentIndex]; !exists {
				part := make([]byte, len(frame.Payload))
				copy(part, frame.Payload)
				entry.segments[frame.SegmentIndex] = part
				entry.totalBytes += len(part)
			}
			entry.lastUpdated = time.Now()
			if len(entry.segments) != int(entry.count) {
				now := time.Now()
				if now.Sub(lastCleanup) >= reassemblyCleanupPeriod {
					for k, candidate := range reassembly {
						if now.Sub(candidate.lastUpdated) > reassemblyEntryTTL {
							delete(reassembly, k)
						}
					}
					lastCleanup = now
				}
				continue
			}

			merged := make([]byte, 0, entry.totalBytes)
			complete := true
			for i := uint16(0); i < entry.count; i++ {
				part, ok := entry.segments[i]
				if !ok {
					complete = false
					break
				}
				merged = append(merged, part...)
			}
			delete(reassembly, key)
			if !complete {
				continue
			}
			frame.Payload = merged
			frame.Segmented = false
			frame.MessageID = 0
			frame.SegmentIndex = 0
			frame.SegmentCount = 0
		}

		if s.dropIncoming {
			select {
			case s.incoming <- frame:
			default:
			}
			continue
		}

		select {
		case s.incoming <- frame:
		case <-s.done:
			return
		}
	}
}
