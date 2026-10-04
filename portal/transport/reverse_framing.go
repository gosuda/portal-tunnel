package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// Reverse-session framing is shared by native and multiplexed connections.
// TLS activation carries the binding required by transcript-signing requests.
const (
	markerKeepalive          = 0x00
	markerRawStart           = 0x01
	markerTLSStart           = 0x02
	tlsBindingSize           = 16
	defaultSessionWriteLimit = 5 * time.Second
)

// ReadStart skips keepalives and returns the TLS binding, or nil for raw
// traffic. The caller retains conn; invalid or interrupted framing closes it.
func ReadStart(ctx context.Context, conn net.Conn, timeout time.Duration) (binding []byte, err error) {
	if conn == nil {
		return nil, net.ErrClosed
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer func() {
		stop()
		if err != nil {
			_ = conn.Close()
		}
	}()
	var marker [1]byte
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := conn.SetReadDeadline(time.Now().Add(2 * timeout)); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(conn, marker[:]); err != nil {
			return nil, err
		}
		switch marker[0] {
		case markerKeepalive:
			continue
		case markerTLSStart:
			binding = make([]byte, tlsBindingSize)
			if _, err := io.ReadFull(conn, binding); err != nil {
				return nil, err
			}
		case markerRawStart:
		default:
			return nil, fmt.Errorf("unexpected reverse marker: 0x%02x", marker[0])
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return nil, err
		}
		return binding, nil
	}
}

func WriteTLSStart(conn net.Conn, binding [16]byte) error {
	frame := [1 + tlsBindingSize]byte{markerTLSStart}
	copy(frame[1:], binding[:])
	return writeStartFrame(conn, frame[:])
}

func WriteRawStart(conn net.Conn) error {
	return writeStartFrame(conn, []byte{markerRawStart})
}

func WriteKeepalive(conn net.Conn) error {
	return writeStartFrame(conn, []byte{markerKeepalive})
}

func writeStartFrame(conn net.Conn, frame []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(defaultSessionWriteLimit)); err != nil {
		return err
	}
	defer conn.SetWriteDeadline(time.Time{})
	return writeReverseStreamFrame(conn, frame)
}

func writeReverseStreamFrame(w io.Writer, parts ...[]byte) error {
	for _, part := range parts {
		for len(part) != 0 {
			n, err := w.Write(part)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrUnexpectedEOF
			}
			part = part[n:]
		}
	}
	return nil
}
