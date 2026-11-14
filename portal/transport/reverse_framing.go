package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const defaultSessionWriteLimit = 5 * time.Second

// ReverseStartMode identifies the framing mode signaled at the start of a reverse stream.
type ReverseStartMode uint8

const (
	ReverseStartTLS ReverseStartMode = iota + 1
	ReverseStartRaw
	ReverseStartLocalTLS
)

// ReadStartMode skips keepalives and returns the stream framing mode along with
// the TLS binding for ReverseStartTLS streams. The caller retains conn; invalid
// or interrupted framing closes it.
func ReadStartMode(ctx context.Context, conn net.Conn, timeout time.Duration) (mode ReverseStartMode, binding []byte, err error) {
	if conn == nil {
		return 0, nil, net.ErrClosed
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer func() {
		stop()
		if err != nil {
			_ = conn.Close()
		}
	}()
	marker, markerErr := nextReverseMarker(ctx, conn, timeout)
	if markerErr != nil {
		return 0, nil, markerErr
	}
	mode, startBinding, bindingErr := decodeReverseStart(conn, marker)
	if bindingErr != nil {
		return 0, nil, bindingErr
	}
	if deadlineErr := conn.SetReadDeadline(time.Time{}); deadlineErr != nil {
		return 0, nil, deadlineErr
	}
	return mode, startBinding, nil
}

func nextReverseMarker(ctx context.Context, conn net.Conn, timeout time.Duration) (byte, error) {
	for {
		marker, err := readReverseMarker(ctx, conn, timeout)
		if err != nil {
			return 0, err
		}
		if marker == types.ReverseMarkerKeepalive {
			continue
		}
		return marker, nil
	}
}

func decodeReverseStart(conn net.Conn, marker byte) (ReverseStartMode, []byte, error) {
	switch marker {
	case types.ReverseMarkerTLSStart:
		binding := make([]byte, types.TLSBindingSize)
		if _, err := io.ReadFull(conn, binding); err != nil {
			return 0, nil, err
		}
		return ReverseStartTLS, binding, nil
	case types.ReverseMarkerRawStart:
		return ReverseStartRaw, nil, nil
	case types.ReverseMarkerLocalTLSStart:
		return ReverseStartLocalTLS, nil, nil
	default:
		return 0, nil, fmt.Errorf("unexpected reverse marker: 0x%02x", marker)
	}
}

func readReverseMarker(ctx context.Context, conn net.Conn, timeout time.Duration) (byte, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * timeout)); err != nil {
		return 0, err
	}
	var marker [1]byte
	if _, err := io.ReadFull(conn, marker[:]); err != nil {
		return 0, err
	}
	return marker[0], nil
}

func WriteTLSStart(conn net.Conn, binding [types.TLSBindingSize]byte) error {
	frame := [1 + types.TLSBindingSize]byte{types.ReverseMarkerTLSStart}
	copy(frame[1:], binding[:])
	return writeStartFrame(conn, frame[:])
}

func WriteLocalTLSStart(conn net.Conn) error {
	return writeStartFrame(conn, []byte{types.ReverseMarkerLocalTLSStart})
}

func WriteRawStart(conn net.Conn) error {
	return writeStartFrame(conn, []byte{types.ReverseMarkerRawStart})
}

func WriteKeepalive(conn net.Conn) error {
	return writeStartFrame(conn, []byte{types.ReverseMarkerKeepalive})
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
