//go:build js

package sdk

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/gosuda/portal-tunnel/v2/portal/transport"
)

const socketTransportAvailable = false

// reverseLeaseCarrier owns the WebSocket reverse mux shared by one lease.
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

func (c *reverseLeaseCarrier) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.mux == nil {
		return nil
	}
	return c.mux.Close()
}

func reverseMuxEnded(mux *transport.ReverseMux) bool {
	select {
	case <-mux.Done():
		return true
	default:
		return false
	}
}
