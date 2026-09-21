package transport

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const defaultTCPPortClaimTimeout = 10 * time.Second

// RelayTCPPort owns a TCP listener on an allocated port for one lease. Accept
// pairs each inbound connection with a claimed reverse session; the caller
// owns the final connection pairing.
type RelayTCPPort struct {
	identityKey string
	port        int
	listener    net.Listener
	stream      *RelayStream
	pairs       chan tcpPair
	ctx         context.Context
	cancel      context.CancelFunc

	closeOnce sync.Once
}

type tcpPair struct {
	inbound net.Conn
	session net.Conn
}

func NewRelayTCPPort(identityKey string, port int, stream *RelayStream) *RelayTCPPort {
	return &RelayTCPPort{
		identityKey: identityKey,
		port:        port,
		stream:      stream,
	}
}

// Start opens the listener; Accept delivers paired connections after it
// succeeds.
func (t *RelayTCPPort) Start() error {
	if t == nil || t.port <= 0 {
		return nil
	}

	addr := &net.TCPAddr{Port: t.port}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	t.listener = listener
	t.ctx, t.cancel = context.WithCancel(context.Background())
	t.pairs = make(chan tcpPair)
	go t.acceptLoop()

	log.Info().
		Str("component", "tcp-port-relay").
		Str("identity_key", t.identityKey).
		Int("port", t.port).
		Msg("tcp port relay started")

	return nil
}

func (t *RelayTCPPort) Close() {
	if t == nil {
		return
	}

	t.closeOnce.Do(func() {
		if t.cancel != nil {
			t.cancel()
		}
		if t.listener != nil {
			_ = t.listener.Close()
		}
		log.Info().
			Str("component", "tcp-port-relay").
			Str("identity_key", t.identityKey).
			Int("port", t.port).
			Msg("tcp port relay stopped")
	})
}

func (t *RelayTCPPort) TCPPort() int {
	if t == nil {
		return 0
	}
	return t.port
}

// Accept returns the next inbound TCP connection paired with a claimed reverse
// session. Claims run independently from listener acceptance so a pending
// reverse session cannot delay later inbound connections.
func (t *RelayTCPPort) Accept() (net.Conn, net.Conn, error) {
	if t == nil || t.ctx == nil || t.pairs == nil {
		return nil, nil, net.ErrClosed
	}
	select {
	case pair := <-t.pairs:
		return pair.inbound, pair.session, nil
	case <-t.ctx.Done():
		return nil, nil, net.ErrClosed
	}
}

func (t *RelayTCPPort) acceptLoop() {
	defer t.cancel()
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			if t.ctx.Err() == nil {
				log.Warn().
					Str("component", "tcp-port-relay").
					Str("identity_key", t.identityKey).
					Err(err).
					Msg("accept loop exiting")
			}
			return
		}
		go t.claim(conn)
	}
}

func (t *RelayTCPPort) claim(conn net.Conn) {
	claimCtx, cancel := context.WithTimeout(t.ctx, defaultTCPPortClaimTimeout)
	defer cancel()

	session, err := t.stream.claimRaw(claimCtx)
	if err != nil {
		_ = conn.Close()
		if t.ctx.Err() == nil {
			log.Warn().
				Str("component", "tcp-port-relay").
				Str("identity_key", t.identityKey).
				Err(err).
				Msg("failed to claim reverse session for tcp port connection")
		}
		return
	}

	select {
	case t.pairs <- tcpPair{inbound: conn, session: session}:
	case <-t.ctx.Done():
		_ = conn.Close()
		_ = session.Close()
	}
}
