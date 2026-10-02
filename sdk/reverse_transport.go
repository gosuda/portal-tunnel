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

// leaseReverseTransport opens raw connections on native runtimes and owns the
// WebSocket reverse mux shared by one browser lease.
type leaseReverseTransport struct {
	listener *listener

	mu     sync.Mutex
	mux    *transport.ReverseMux
	closed bool
}

func newLeaseReverseTransport(l *listener) *leaseReverseTransport {
	return &leaseReverseTransport{listener: l}
}

func (t *leaseReverseTransport) Open(ctx context.Context) (net.Conn, error) {
	if runtime.GOOS == "js" {
		return t.openMux(ctx)
	}
	return t.openRaw(ctx)
}

func (t *leaseReverseTransport) Close() error {
	if runtime.GOOS != "js" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	if t.mux == nil {
		return nil
	}
	return t.mux.Close()
}

func (t *leaseReverseTransport) openRaw(ctx context.Context) (net.Conn, error) {
	reverseURL, capability, err := t.listener.reverseTarget()
	if err != nil {
		return nil, err
	}
	reverseTLS, err := t.listener.reverseTLSConfig(ctx, reverseURL)
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

func (t *leaseReverseTransport) openMux(ctx context.Context) (net.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, net.ErrClosed
	}
	reverseURL, capability, err := t.listener.reverseTarget()
	if err != nil {
		return nil, err
	}
	if t.mux == nil || reverseMuxEnded(t.mux) {
		handshakeCtx, cancel := context.WithTimeout(ctx, defaultHandshakeTimeout)
		mux, err := transport.DialReverseMux(handshakeCtx, reverseURL, capability)
		cancel()
		if err != nil {
			return nil, err
		}
		t.mux = mux
	}
	stream, err := t.mux.Open(ctx, capability)
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
