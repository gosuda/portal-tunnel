package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const defaultTCPPortClaimTimeout = 10 * time.Second

// RelayTCPPort owns a TCP listener on an allocated port for one lease.
type RelayTCPPort struct {
	identityKey string
	port        int
	listener    net.Listener
	stream      *RelayStream
	bridge      func(net.Conn, net.Conn)

	cancel    context.CancelFunc
	closeOnce sync.Once
}

func NewRelayTCPPort(identityKey string, port int, stream *RelayStream, bridge func(net.Conn, net.Conn)) *RelayTCPPort {
	return &RelayTCPPort{
		identityKey: identityKey,
		port:        port,
		stream:      stream,
		bridge:      bridge,
	}
}

func (t *RelayTCPPort) Start(ctx context.Context) error {
	if t == nil || t.port <= 0 {
		return nil
	}

	addr := &net.TCPAddr{Port: t.port}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	t.listener = listener

	relayCtx, cancel := context.WithCancel(ctx)
	t.cancel = cancel
	go t.acceptLoop(relayCtx)

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

func (t *RelayTCPPort) acceptLoop(ctx context.Context) {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			log.Warn().
				Str("component", "tcp-port-relay").
				Str("identity_key", t.identityKey).
				Err(err).
				Msg("accept loop exiting")
			return
		}

		go t.handleConn(ctx, conn)
	}
}

func (t *RelayTCPPort) handleConn(ctx context.Context, conn net.Conn) {
	claimCtx, cancel := context.WithTimeout(ctx, defaultTCPPortClaimTimeout)
	defer cancel()

	session, err := t.stream.claimRaw(claimCtx)
	if err != nil {
		_ = conn.Close()
		log.Warn().
			Str("component", "tcp-port-relay").
			Str("identity_key", t.identityKey).
			Err(err).
			Msg("failed to claim reverse session for tcp port connection")
		return
	}

	if t.bridge == nil {
		_ = conn.Close()
		_ = session.Close()
		return
	}
	t.bridge(conn, session)
}
