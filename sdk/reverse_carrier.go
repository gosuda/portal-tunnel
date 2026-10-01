package sdk

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const socketTransportAvailable = runtime.GOOS != "js"

// reverseLeaseCarrier opens raw connections on native runtimes and owns the
// WebSocket reverse mux shared by one browser lease.
type reverseLeaseCarrier struct {
	listener *listener

	mu     sync.Mutex
	mux    *transport.ReverseMux
	closed bool
}

func newReverseLeaseCarrier(l *listener) *reverseLeaseCarrier {
	return &reverseLeaseCarrier{listener: l}
}

func (c *reverseLeaseCarrier) Open(ctx context.Context) (net.Conn, error) {
	if runtime.GOOS == "js" {
		return c.openMux(ctx)
	}
	return c.openRaw(ctx)
}

func (c *reverseLeaseCarrier) Close() error {
	if runtime.GOOS != "js" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.mux == nil {
		return nil
	}
	return c.mux.Close()
}

func (c *reverseLeaseCarrier) openRaw(ctx context.Context) (net.Conn, error) {
	reverseURL, capability, err := c.listener.reverseTarget()
	if err != nil {
		return nil, err
	}
	reverseTLS, err := c.listener.reverseTLSConfig(ctx, reverseURL)
	if err != nil {
		return nil, err
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: defaultDialTimeout},
		Config:    reverseTLS,
	}
	conn, err := dialer.DialContext(ctx, "tcp", utils.EnsurePort(reverseURL.Host))
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    reverseURL,
		Host:   reverseURL.Host,
		Header: make(http.Header),
	}
	req.Header.Set(types.HeaderReverseCapability, capability)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "raw")

	_ = conn.SetDeadline(time.Now().Add(defaultHandshakeTimeout))
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		apiErr := utils.DecodeAPIRequestError(resp)
		_ = conn.Close()
		return nil, apiErr
	}

	_ = conn.SetDeadline(time.Time{})
	return wrapBufferedConn(conn, reader), nil
}

func (c *reverseLeaseCarrier) openMux(ctx context.Context) (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.mux == nil || reverseMuxEnded(c.mux) {
		reverseURL, capability, err := c.listener.reverseTarget()
		if err != nil {
			return nil, err
		}
		handshakeCtx, cancel := context.WithTimeout(ctx, defaultHandshakeTimeout)
		mux, err := transport.DialReverseMux(handshakeCtx, reverseURL, capability)
		cancel()
		if err != nil {
			return nil, err
		}
		c.mux = mux
	}
	stream, err := c.mux.Open()
	if err != nil {
		return nil, fmt.Errorf("open reverse stream: %w", err)
	}
	return stream, nil
}

func reverseMuxEnded(mux *transport.ReverseMux) bool {
	select {
	case <-mux.Done():
		return true
	default:
		return false
	}
}
