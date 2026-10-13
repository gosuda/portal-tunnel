package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/quic-go/quic-go"

	"github.com/gosuda/portal-tunnel/v2/types"
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
		return nil, errors.New("quic backhaul connection is required")
	}

	if !conn.ConnectionState().SupportsDatagrams.Remote {
		_ = conn.CloseWithError(0, "QUIC DATAGRAM support required")
		return nil, errors.New("QUIC DATAGRAM support required")
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
	return conn.SendDatagram(types.EncodeDatagram(flowID, payload))
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
	// SendDatagram may block under backpressure. Keep the connection selected
	// with the lease check, but let Clear/Close close it to interrupt the send.
	return conn.SendDatagram(types.EncodeDatagram(frame.FlowID, frame.Payload))
}

func (s *DatagramSession) datagramConnectionLocked(payload []byte) (*quic.Conn, error) {
	select {
	case <-s.done:
		return nil, net.ErrClosed
	default:
	}
	if len(payload) > types.MaxUDPPayloadSize {
		return nil, errors.New("UDP payload exceeds limit")
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
			if s.conn == conn {
				s.conn = nil
				recvErr = err
			}
			s.mu.Unlock()
			// Loop exit is intentional: this receive generation reports its
			// terminal error to its owner through recvDone.
			return
		}

		frame, err := types.DecodeDatagram(data)
		if err != nil {
			continue
		}

		if len(frame.Payload) > types.MaxUDPPayloadSize {
			continue
		}
		frame.LeaseDone = leaseDone

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
		case <-conn.Context().Done():
			return
		}
	}
}
