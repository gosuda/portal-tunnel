package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	reverseStreamAuthTimeout    = 10 * time.Second
	reverseCapabilityLimit      = 8 << 10
	reverseStreamStatusAccepted = byte(0)
	reverseStreamStatusRejected = byte(1)
)

// IsReverseMuxRequest reports whether r asks for the WebSocket carrier rather than the
// raw one. It reads only enough to choose; AcceptReverseMux validates the handshake.
func IsReverseMuxRequest(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket")
}

// ReverseMuxCapability returns the one capability a connector offered beside the
// ReverseSubprotocol marker, or "" without the marker or with any other count. The
// WebSocket constructor cannot set headers but can offer subprotocols, and keeping the
// capability out of the URL keeps a bearer token out of access logs.
func ReverseMuxCapability(r *http.Request) string {
	var marked bool
	var capabilities []string
	for _, raw := range strings.Split(strings.Join(r.Header.Values("Sec-WebSocket-Protocol"), ","), ",") {
		switch value := strings.TrimSpace(raw); value {
		case "":
		case types.ReverseSubprotocol:
			marked = true
		default:
			capabilities = append(capabilities, value)
		}
	}
	if !marked || len(capabilities) != 1 {
		return ""
	}
	return capabilities[0]
}

// ReverseMux is one connector's reverse connections, multiplexed over a WebSocket.
// The connector Opens each reverse connection; the relay Accepts them.
type ReverseMux struct {
	session *yamux.Session
}

// Open starts a reverse connection from the connector end and authenticates it
// with the capability current at the time the logical stream is opened.
func (m *ReverseMux) Open(ctx context.Context, capability string) (net.Conn, error) {
	stream, err := m.session.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := authenticateReverseStream(ctx, stream, capability); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return stream, nil
}

// Accept waits for the connector's next reverse connection and returns the
// capability presented on that logical stream. Authorization belongs to the caller.
func (m *ReverseMux) Accept() (net.Conn, string, error) {
	for {
		stream, err := m.session.AcceptStream()
		if err != nil {
			return nil, "", err
		}
		capability, err := readReverseStreamCapability(stream)
		if err != nil {
			_ = stream.Close()
			continue
		}
		return stream, capability, nil
	}
}

// Close ends the WebSocket and every reverse connection on it.
func (m *ReverseMux) Close() error {
	return m.session.Close()
}

// Done is closed once the session has ended, from either end.
func (m *ReverseMux) Done() <-chan struct{} {
	return m.session.CloseChan()
}

// authenticateReverseStream presents the current reverse capability on a newly
// opened logical stream. A mux authenticates its lease at the WebSocket boundary,
// but every stream must still prove that its short-lived capability is current.
func authenticateReverseStream(ctx context.Context, conn net.Conn, capability string) error {
	if conn == nil {
		return errors.New("reverse stream is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	capability = strings.TrimSpace(capability)
	if capability == "" || len(capability) > reverseCapabilityLimit {
		return errors.New("reverse capability is invalid")
	}

	deadline := time.Now().Add(reverseStreamAuthTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	defer conn.SetDeadline(time.Time{})

	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(capability)))
	if err := writeReverseStreamFrame(conn, size[:], []byte(capability)); err != nil {
		return err
	}
	var status [1]byte
	if _, err := io.ReadFull(conn, status[:]); err != nil {
		return err
	}
	if status[0] != reverseStreamStatusAccepted {
		return &types.APIRequestError{
			StatusCode: http.StatusForbidden,
			Code:       types.APIErrorCodeUnauthorized,
			Message:    "reverse capability is invalid",
		}
	}
	return nil
}

func readReverseStreamCapability(conn net.Conn) (string, error) {
	if conn == nil {
		return "", errors.New("reverse stream is required")
	}
	if err := conn.SetDeadline(time.Now().Add(reverseStreamAuthTimeout)); err != nil {
		return "", err
	}

	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return "", err
	}
	length := int(binary.BigEndian.Uint16(size[:]))
	if length == 0 || length > reverseCapabilityLimit {
		_, _ = conn.Write([]byte{reverseStreamStatusRejected})
		return "", errors.New("reverse capability is invalid")
	}
	raw := make([]byte, length)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return "", err
	}
	return string(raw), nil
}

// ConfirmReverseStream reports the caller's authorization decision to the connector.
// The stream carries application bytes only after an accepted response.
func ConfirmReverseStream(conn net.Conn, accepted bool) error {
	if conn == nil {
		return errors.New("reverse stream is required")
	}
	status := reverseStreamStatusRejected
	if accepted {
		status = reverseStreamStatusAccepted
	}
	_, err := conn.Write([]byte{status})
	_ = conn.SetDeadline(time.Time{})
	return err
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

// AcceptReverseMux completes the WebSocket handshake and starts the relay end of the
// session. Only the marker is selected, so the response never echoes the capability.
func AcceptReverseMux(w http.ResponseWriter, r *http.Request) (*ReverseMux, error) {
	socket, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // the capability is the credential; origin is not
		Subprotocols:       []string{types.ReverseSubprotocol},
	})
	if err != nil {
		return nil, err
	}
	conn := websocket.NetConn(context.Background(), socket, websocket.MessageBinary)
	session, err := yamux.Server(conn, reverseMuxConfig())
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &ReverseMux{session: session}, nil
}

// DialReverseMux opens the WebSocket to the reverse endpoint and starts the connector
// end of the session. ctx bounds the handshake only.
func DialReverseMux(ctx context.Context, reverseURL *url.URL, capability string) (*ReverseMux, error) {
	target := *reverseURL
	switch target.Scheme {
	case "https":
		target.Scheme = "wss"
	case "http":
		target.Scheme = "ws"
	}

	socket, resp, err := websocket.Dial(ctx, target.String(), &websocket.DialOptions{
		Subprotocols: []string{types.ReverseSubprotocol, capability},
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("dial reverse websocket: %w", err)
	}
	conn := websocket.NetConn(context.Background(), socket, websocket.MessageBinary)
	session, err := yamux.Client(conn, reverseMuxConfig())
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("start reverse session: %w", err)
	}
	return &ReverseMux{session: session}, nil
}

func reverseMuxConfig() *yamux.Config {
	config := yamux.DefaultConfig()
	config.LogOutput = io.Discard
	return config
}
