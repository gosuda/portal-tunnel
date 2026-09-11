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

// datagramSession owns one active QUIC DATAGRAM connection and exposes decoded frames.
type datagramSession struct {
	incoming       chan types.DatagramFrame
	dropIncoming   bool
	onReceiveError func(error)
	done           chan struct{}

	mu     sync.Mutex
	conn   *quic.Conn
	closed bool
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

// Bind installs a new active backhaul connection and starts the receive loop.
// Any previously active connection is replaced and closed.
func (s *datagramSession) Bind(conn *quic.Conn) (<-chan struct{}, error) {
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
