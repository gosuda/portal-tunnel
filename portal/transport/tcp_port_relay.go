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

	closeOnce sync.Once
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

// Accept returns the next inbound TCP connection paired with a claimed
// reverse session. A connection whose reverse session cannot be claimed in
// time is closed and the wait continues; the returned error ends acceptance.
func (t *RelayTCPPort) Accept() (net.Conn, net.Conn, error) {
	if t == nil || t.listener == nil {
		return nil, nil, net.ErrClosed
	}
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			return nil, nil, err
		}

		claimCtx, cancel := context.WithTimeout(context.Background(), defaultTCPPortClaimTimeout)
		session, err := t.stream.claimRaw(claimCtx)
		cancel()
		if err != nil {
			_ = conn.Close()
			log.Warn().
				Str("component", "tcp-port-relay").
				Str("identity_key", t.identityKey).
				Err(err).
				Msg("failed to claim reverse session for tcp port connection")
			continue
		}
		return conn, session, nil
	}
}
