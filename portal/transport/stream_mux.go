package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// A connector without sockets - a browser - cannot dial TCP and upgrade to a raw
// stream, but it can open a WebSocket. It keeps one per lease and carries a yamux
// session on it; each stream is one reverse connection with the same ciphertext a raw
// one carries.

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

// Open starts a reverse connection from the connector end.
func (m *ReverseMux) Open() (net.Conn, error) {
	return m.session.OpenStream()
}

// Accept waits for the connector's next reverse connection at the relay end.
func (m *ReverseMux) Accept() (net.Conn, error) {
	return m.session.AcceptStream()
}

// Close ends the WebSocket and every reverse connection on it.
func (m *ReverseMux) Close() error {
	return m.session.Close()
}

// Done is closed once the session has ended, from either end.
func (m *ReverseMux) Done() <-chan struct{} {
	return m.session.CloseChan()
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
