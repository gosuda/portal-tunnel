package sdk

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// leaseReverseTransport opens raw connections on native runtimes and owns the
// WebSocket reverse mux shared by one browser lease.
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
	reverseURL, capability, err := t.listener.reverseTarget()
	if err != nil {
		return nil, err
	}
	reverseTLS, err := t.listener.reverseTLSConfig(ctx, reverseURL)
	if err != nil {
		return nil, err
	}
	dialer := &tls.Dialer{
		NetDialer: reverseTCPDialer(t.listener.isAlternateReverseEndpoint(reverseURL.String())),
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

// Non-public and special-purpose ranges must never be destinations supplied by
// a relay-selected overlay gateway. IsGlobalUnicast alone includes many of
// these ranges, including private addresses and the shared CGNAT range.
var restrictedReversePrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

func isPublicReverseAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.Zone() != "" || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, prefix := range restrictedReversePrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func validatePublicReverseHostname(host string) error {
	if utils.IsLocalRelayHost(host) {
		return fmt.Errorf("overlay gateway host %q is local-only", host)
	}
	if addr, err := netip.ParseAddr(host); err == nil && !isPublicReverseAddr(addr) {
		return fmt.Errorf("overlay gateway address %q is non-public", host)
	}
	return nil
}

// ControlContext runs after name resolution and before connect. Checking the
// actual resolved address on each dial prevents DNS rebinding from reaching
// private endpoints. Direct connections to the explicitly configured relay
// retain their existing local-development behavior.
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
		if err != nil || !isPublicReverseAddr(addr) {
			return fmt.Errorf("overlay gateway resolved to non-public address %q", host)
		}
		return nil
	}
	return dialer
}
