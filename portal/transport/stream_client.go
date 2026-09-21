package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// ClientSession is a claimed reverse connection. Binding is present only for
// TLS sessions and contains the per-connection value carried by the framing.
type ClientSession struct {
	Conn    net.Conn
	Binding []byte
}

type ClientStream struct {
	handshakeTimeout time.Duration
}

func NewClientStream(handshakeTimeout time.Duration) *ClientStream {
	return &ClientStream{handshakeTimeout: handshakeTimeout}
}

// RunSession reads reverse-session markers from conn until a session starts.
// TLS sessions carry a 16-byte binding after markerTLSStart; raw sessions
// return a nil binding.
func (s *ClientStream) RunSession(ctx context.Context, conn net.Conn) (ClientSession, error) {
	if s == nil {
		return ClientSession{}, net.ErrClosed
	}
	return s.runSession(ctx, conn)
}

func (s *ClientStream) runSession(ctx context.Context, conn net.Conn) (ClientSession, error) {
	if conn == nil {
		return ClientSession{}, net.ErrClosed
	}

	var marker [1]byte
	for {
		if err := ctx.Err(); err != nil {
			_ = conn.Close()
			return ClientSession{}, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * s.handshakeTimeout))
		if _, err := io.ReadFull(conn, marker[:]); err != nil {
			_ = conn.Close()
			return ClientSession{}, err
		}
		var binding []byte
		if marker[0] == markerTLSStart {
			binding = make([]byte, tlsBindingSize)
			if _, err := io.ReadFull(conn, binding); err != nil {
				_ = conn.Close()
				return ClientSession{}, err
			}
		}
		_ = conn.SetReadDeadline(time.Time{})

		switch marker[0] {
		case markerKeepalive:
			continue
		case markerTLSStart:
			return ClientSession{Conn: conn, Binding: binding}, nil
		case markerRawStart:
			return ClientSession{Conn: conn}, nil
		default:
			_ = conn.Close()
			return ClientSession{}, fmt.Errorf("unexpected reverse marker: 0x%02x", marker[0])
		}
	}
}
