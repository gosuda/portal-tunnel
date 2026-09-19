package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// TLSActivationFunc terminates TLS on a freshly claimed raw reverse
// connection. binding is the 16-byte per-connection value the relay wrote
// immediately after the markerTLSStart framing byte; implementations must
// present it back to the relay on every transcript-signing request.
type TLSActivationFunc func(ctx context.Context, raw net.Conn, binding []byte) (net.Conn, error)

type ClientStream struct {
	accepted         chan net.Conn
	handshakeTimeout time.Duration
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

// RunSession reads reverse-session markers from conn until a session starts.
// TLS sessions carry a 16-byte binding after markerTLSStart that is handed to
// activate; raw sessions never call it, so a nil activator is safe for
// raw-only sessions.
func (s *ClientStream) RunSession(
	ctx context.Context,
	conn net.Conn,
	activate TLSActivationFunc,
) (bool, error) {
	if s == nil {
		return false, net.ErrClosed
	}
	return s.runSession(ctx, conn, activate)
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
	activate TLSActivationFunc,
) (bool, error) {
	if conn == nil {
		return false, net.ErrClosed
	}

	var marker [1]byte
	var binding []byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * s.handshakeTimeout))
		if _, err := io.ReadFull(conn, marker[:]); err != nil {
			_ = conn.Close()
			return false, err
		}
		if marker[0] == markerTLSStart {
			binding = make([]byte, tlsBindingSize)
			if _, err := io.ReadFull(conn, binding); err != nil {
				_ = conn.Close()
				return false, err
			}
		}
		_ = conn.SetReadDeadline(time.Time{})

		switch marker[0] {
		case markerKeepalive:
			continue
		case markerTLSStart:
			if err := s.activate(ctx, conn, activate, binding); err != nil {
				_ = conn.Close()
				return true, err
			}
			return true, nil
		case markerRawStart:
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

func (s *ClientStream) activate(ctx context.Context, conn net.Conn, activate TLSActivationFunc, binding []byte) error {
	if activate == nil {
		return errors.New("tls activator is unavailable")
	}

	handshakeCtx, cancel := context.WithTimeout(ctx, s.handshakeTimeout)
	defer cancel()
	tlsConn, err := activate(handshakeCtx, conn, binding)
	if err != nil {
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
