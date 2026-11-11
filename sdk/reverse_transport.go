package sdk

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"syscall"

	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type leaseReverseTransport struct {
	listener *listener

	mu  sync.Mutex
	mux *transport.ReverseMux
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
	if t.mux == nil {
		return nil
	}
	return t.mux.Close()
}

func (t *leaseReverseTransport) openRaw(ctx context.Context) (net.Conn, error) {
	conn, reverseURL, capability, err := t.openRawReverseDial(ctx)
	if err != nil {
		return nil, err
	}
	return openRawReverseHandshake(conn, reverseURL, capability)
}

func (t *leaseReverseTransport) openMux(ctx context.Context) (net.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
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

func validatePublicReverseHostname(host string) error {
	if utils.IsLocalOnlyRelayHost(host) {
		return fmt.Errorf("overlay gateway host %q is local-only", host)
	}
	if addr, err := netip.ParseAddr(host); err == nil && !utils.IsPublicIP(addr) {
		return fmt.Errorf("overlay gateway address %q is non-public", host)
	}
	return nil
}

func reverseTCPDialer(alternate bool) *net.Dialer {
	dialer := &net.Dialer{Timeout: defaultDialTimeout}
	if !alternate {
		return dialer
	}
	dialer.ControlContext = func(_ context.Context, _, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("parse overlay gateway dial address: %w", err)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || !utils.IsPublicIP(addr) {
			return fmt.Errorf("overlay gateway resolved to non-public address %q", host)
		}
		return nil
	}
	return dialer
}
