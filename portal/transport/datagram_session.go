package transport

import (
	"context"
	"errors"
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

	mu     sync.Mutex
	conn   *quic.Conn
	closed bool
}

func NewDatagramSession(bufferSize int, dropIncoming bool) *DatagramSession {
	if bufferSize <= 0 {
		bufferSize = 256
	}

	return &DatagramSession{
		incoming:     make(chan types.DatagramFrame, bufferSize),
		dropIncoming: dropIncoming,
		done:         make(chan struct{}),
	}
}

// Bind installs a new active backhaul connection and starts the receive loop.
// Any previously active connection is replaced and closed.
func (s *DatagramSession) Bind(conn *quic.Conn) (<-chan error, error) {
	if conn == nil {
		return nil, errors.New("quic backhaul connection is required")
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

	recvDone := make(chan error, 1)
	go s.receiveLoop(conn, recvDone)
	return recvDone, nil
}

func (s *DatagramSession) Done() <-chan struct{} {
	return s.done
}

// Accept returns multiplexed frames until this session or its caller closes.
func (s *DatagramSession) Accept(done <-chan struct{}) (types.DatagramFrame, error) {
	select {
	case <-done:
		return types.DatagramFrame{}, net.ErrClosed
	case <-s.done:
		return types.DatagramFrame{}, net.ErrClosed
	case frame := <-s.incoming:
		return frame, nil
	}
}

func (s *DatagramSession) Connected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn != nil && !s.closed
}

func (s *DatagramSession) Send(flowID uint32, payload []byte) error {
	s.mu.Lock()
	conn := s.conn
	closed := s.closed
	s.mu.Unlock()

	if closed {
		return net.ErrClosed
	}
	if conn == nil {
		return errNoConnection
	}
	return conn.SendDatagram(types.EncodeDatagram(flowID, payload))
}

// Clear closes the active connection but keeps the session reusable.
func (s *DatagramSession) Clear(reason string) {
	s.mu.Lock()
	conn := s.conn
	s.conn = nil
	s.mu.Unlock()

	if conn != nil {
		_ = conn.CloseWithError(0, reason)
	}
}

// Close permanently closes the session and any active connection.
func (s *DatagramSession) Close(reason string) {
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

func (s *DatagramSession) receiveLoop(conn *quic.Conn, recvDone chan<- error) {
	var recvErr error
	defer func() {
		recvDone <- recvErr
		close(recvDone)
	}()

	for {
		data, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			s.mu.Lock()
			if s.conn == conn && !s.closed {
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
