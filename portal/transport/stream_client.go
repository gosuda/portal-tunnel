package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

type ClientStream struct {
	accepted         chan net.Conn
	activeSessions   int
	handshakeTimeout time.Duration
	mu               sync.Mutex
}

func NewClientStream(readyTarget int, handshakeTimeout time.Duration) *ClientStream {
	return &ClientStream{
		accepted:         make(chan net.Conn, max(readyTarget*2, 1)),
		handshakeTimeout: handshakeTimeout,
	}
}

func (s *ClientStream) Accept(done <-chan struct{}) (net.Conn, error) {
	if s == nil {
		return nil, net.ErrClosed
	}
	select {
	case <-done:
		return nil, net.ErrClosed
	case conn := <-s.accepted:
		if conn == nil {
			return nil, net.ErrClosed
		}
		return conn, nil
	}
}

func (s *ClientStream) RunSession(
	ctx context.Context,
	conn net.Conn,
	tlsConfig *tls.Config,
) (bool, error) {
	if s == nil {
		return false, net.ErrClosed
	}
	return s.runSession(ctx, conn, tlsConfig)
}

func (s *ClientStream) ActiveSessions() int {
	if s == nil {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeSessions
}

func (s *ClientStream) Drain() {
	if s == nil {
		return
	}
	for {
		select {
		case conn := <-s.accepted:
			if conn != nil {
				_ = conn.Close()
			}
		default:
			return
		}
	}
}

func (s *ClientStream) runSession(
	ctx context.Context,
	conn net.Conn,
	tlsConfig *tls.Config,
) (bool, error) {
	if conn == nil {
		return false, net.ErrClosed
	}
	s.sessionOpened()
	defer s.sessionClosed()

	var marker [1]byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * s.handshakeTimeout))
		if _, err := io.ReadFull(conn, marker[:]); err != nil {
			_ = conn.Close()
			return false, err
		}
		_ = conn.SetReadDeadline(time.Time{})

		switch marker[0] {
		case types.MarkerKeepalive:
			continue
		case types.MarkerTLSStart:
			if err := s.activate(ctx, conn, tlsConfig); err != nil {
				_ = conn.Close()
				return true, err
			}
			return true, nil
		case types.MarkerRawStart:
			if err := s.activateRaw(ctx, conn); err != nil {
				_ = conn.Close()
				return true, err
			}
			return true, nil
		default:
			_ = conn.Close()
			return false, fmt.Errorf("unexpected reverse marker: 0x%02x", marker[0])
		}
	}
}

func (s *ClientStream) activate(ctx context.Context, conn net.Conn, tlsConfig *tls.Config) error {
	if tlsConfig == nil {
		return errors.New("tls config is unavailable")
	}

	tlsConn := tls.Server(conn, tlsConfig)
	handshakeCtx, cancel := context.WithTimeout(ctx, s.handshakeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		_ = tlsConn.Close()
		return ctx.Err()
	case s.accepted <- tlsConn:
		return nil
	}
}

func (s *ClientStream) activateRaw(ctx context.Context, conn net.Conn) error {
	select {
	case <-ctx.Done():
		_ = conn.Close()
		return ctx.Err()
	case s.accepted <- conn:
		return nil
	}
}

func (s *ClientStream) sessionOpened() {
	if s == nil {
		return
	}

	s.mu.Lock()
	s.activeSessions++
	s.mu.Unlock()
}

func (s *ClientStream) sessionClosed() {
	if s == nil {
		return
	}

	s.mu.Lock()
	if s.activeSessions > 0 {
		s.activeSessions--
	}
	s.mu.Unlock()
}
