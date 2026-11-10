package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/quic-go/quic-go"

	"github.com/gosuda/portal-tunnel/v2/types"
)

var (
	errQUICBackhaulConnectionIsRequired = errors.New("quic backhaul connection is required")
	errQUICDatagramSupportRequired      = errors.New("QUIC DATAGRAM support required")
	errUDPPayloadExceedsLimit           = errors.New("UDP payload exceeds limit")
	errDatagramTooSmall                 = errors.New("datagram too small to decode")
	errDatagramFlowIDOverflow           = errors.New("datagram flow ID overflows uint32")
)

var errNoConnection = errors.New("no quic backhaul connection registered")

// DatagramSession owns one active QUIC DATAGRAM connection and exposes decoded frames.
type DatagramSession struct {
	incoming     chan types.DatagramFrame
	dropIncoming bool
	done         chan struct{}

	mu        sync.Mutex
	conn      *quic.Conn
	leaseDone chan struct{}
}

func NewDatagramSession(bufferSize int, dropIncoming bool) *DatagramSession {
	if bufferSize <= 0 {
		bufferSize = 256
	}

	return &DatagramSession{
		incoming:     make(chan types.DatagramFrame, bufferSize),
		dropIncoming: dropIncoming,
		done:         make(chan struct{}),
		leaseDone:    make(chan struct{}),
	}
}

// Bind installs a new active backhaul connection and starts the receive loop.
// Any previously active connection is replaced and closed.
func (s *DatagramSession) Bind(conn *quic.Conn) (<-chan error, error) {
	if conn == nil {
		return nil, errQUICBackhaulConnectionIsRequired
	}

	if !conn.ConnectionState().SupportsDatagrams.Remote {
		_ = conn.CloseWithError(0, "QUIC DATAGRAM support required")
		return nil, errQUICDatagramSupportRequired
	}

	s.mu.Lock()
	select {
	case <-s.done:
		s.mu.Unlock()
		_ = conn.CloseWithError(0, "session closed")
		return nil, net.ErrClosed
	default:
	}
	old := s.conn
	s.conn = conn
	leaseDone := s.leaseDone
	s.mu.Unlock()

	if old != nil {
		_ = old.CloseWithError(0, "replaced")
	}

	recvDone := make(chan error, 1)
	go s.receiveLoop(conn, leaseDone, recvDone)
	return recvDone, nil
}

func (s *DatagramSession) Done() <-chan struct{} {
	return s.done
}

// Accept returns multiplexed frames until this session or its caller closes.
func (s *DatagramSession) Accept(done <-chan struct{}) (types.DatagramFrame, error) {
	for {
		select {
		case <-done:
			return types.DatagramFrame{}, net.ErrClosed
		case <-s.done:
			return types.DatagramFrame{}, net.ErrClosed
		case frame := <-s.incoming:
			select {
			case <-frame.LeaseDone:
				continue
			default:
			}
			return frame, nil
		}
	}
}

func (s *DatagramSession) Connected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn != nil && s.conn.Context().Err() == nil
}

func (s *DatagramSession) Send(flowID uint32, payload []byte) error {
	s.mu.Lock()
	conn, err := s.datagramConnectionLocked(payload)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return conn.SendDatagram(encodeDatagram(flowID, payload))
}

// SendFrame rejects replies belonging to a previous lease, including frames
// retained by an SDK caller while the listener re-registers.
func (s *DatagramSession) SendFrame(frame types.DatagramFrame) error {
	s.mu.Lock()
	if frame.LeaseDone != s.leaseDone {
		s.mu.Unlock()
		return fmt.Errorf("datagram lease ended: %w", net.ErrClosed)
	}
	conn, err := s.datagramConnectionLocked(frame.Payload)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return conn.SendDatagram(encodeDatagram(frame.FlowID, frame.Payload))
}

func (s *DatagramSession) datagramConnectionLocked(payload []byte) (*quic.Conn, error) {
	select {
	case <-s.done:
		return nil, net.ErrClosed
	default:
	}
	if len(payload) > types.MaxUDPPayloadSize {
		return nil, errUDPPayloadExceedsLimit
	}
	if s.conn == nil {
		return nil, errNoConnection
	}
	return s.conn, nil
}

// Clear closes the active connection but keeps the session reusable.
func (s *DatagramSession) Clear(reason string) {
	s.mu.Lock()
	select {
	case <-s.done:
		s.mu.Unlock()
		return
	default:
	}
	conn := s.conn
	s.conn = nil
	close(s.leaseDone)
	s.leaseDone = make(chan struct{})
	s.mu.Unlock()

	if conn != nil {
		_ = conn.CloseWithError(0, reason)
	}
}

// Close permanently closes the session and any active connection.
func (s *DatagramSession) Close(reason string) {
	s.mu.Lock()
	select {
	case <-s.done:
		s.mu.Unlock()
		return
	default:
	}
	conn := s.conn
	s.conn = nil
	close(s.done)
	close(s.leaseDone)
	s.mu.Unlock()

	if conn != nil {
		_ = conn.CloseWithError(0, reason)
	}
}

func (s *DatagramSession) receiveLoop(conn *quic.Conn, leaseDone <-chan struct{}, recvDone chan<- error) {
	var recvErr error
	defer func() {
		recvDone <- recvErr
		close(recvDone)
	}()

	for {
		data, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			s.mu.Lock()
			recvErr = s.detachConnLocked(conn, err)
			s.mu.Unlock()
			return
		}
		frame, ok := decodeDatagramFrame(data)
		if !ok {
			continue
		}
		frame.LeaseDone = leaseDone

		if s.forwardDatagramFrame(conn, frame) {
			return
		}
	}
}

func (s *DatagramSession) forwardDatagramFrame(conn *quic.Conn, frame types.DatagramFrame) bool {
	if s.dropIncoming {
		select {
		case s.incoming <- frame:
		default:
		}
		return false
	}
	select {
	case s.incoming <- frame:
		return false
	case <-s.done:
		return true
	case <-conn.Context().Done():
		return true
	}
}

func (s *DatagramSession) detachConnLocked(conn *quic.Conn, err error) error {
	if s.conn == conn {
		s.conn = nil
		return err
	}
	return nil
}

func decodeDatagramFrame(data []byte) (types.DatagramFrame, bool) {
	frame, err := decodeDatagram(data)
	if err != nil || len(frame.Payload) > types.MaxUDPPayloadSize {
		return types.DatagramFrame{}, false
	}
	return frame, true
}

func encodeDatagram(flowID uint32, payload []byte) []byte {
	var buf [binary.MaxVarintLen32]byte
	n := binary.PutUvarint(buf[:], uint64(flowID))
	out := make([]byte, n+len(payload))
	copy(out, buf[:n])
	copy(out[n:], payload)
	return out
}

func decodeDatagram(data []byte) (types.DatagramFrame, error) {
	flowID, n := binary.Uvarint(data)
	if n <= 0 {
		return types.DatagramFrame{}, errDatagramTooSmall
	}
	if flowID > uint64(^uint32(0)) {
		return types.DatagramFrame{}, errDatagramFlowIDOverflow
	}
	return types.DatagramFrame{
		FlowID:  uint32(flowID),
		Payload: data[n:],
	}, nil
}
