package portal

import (
	"net"
	"sync"
)

// apiHandoff accepts already-inspected TLS connections without a TCP redial,
// preserving the socket peer for both HTTP and hijacked reverse sessions.
type apiHandoff struct {
	addr      net.Addr
	conns     chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

func (l *apiHandoff) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *apiHandoff) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (l *apiHandoff) Addr() net.Addr { return l.addr }
