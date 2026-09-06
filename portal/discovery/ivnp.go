package discovery

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"gosuda.org/ivnp"

	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// IVNPRelay resolves an authenticated destination against the current HTTPS
// verified catalog. It does not admit peers supplied by a stream or NetDB.
func (s *RelaySet) IVNPRelay(destination string) (types.RelayDescriptor, error) {
	if s == nil || destination == "" {
		return types.RelayDescriptor{}, errors.New("ivnp relay is not admitted")
	}
	now := time.Now().UTC()
	s.mu.RLock()
	defer s.mu.RUnlock()
	var admitted types.RelayDescriptor
	for _, state := range s.relays {
		desc := state.Descriptor
		if desc.IVNPDestination != destination || state.Trust != RelayVerified || state.Banned || state.Dead || !desc.ExpiresAt.After(now) {
			continue
		}
		if state.suppressActiveUntil.After(now) {
			continue
		}
		anchor, ok := s.keyIndex[strings.ToLower(desc.Address)]
		if !ok || desc.IssuedAt.Before(anchor.IssuedAt) {
			continue
		}
		if admitted.Address != "" && admitted.Address != desc.Address {
			return types.RelayDescriptor{}, errors.New("ambiguous ivnp relay identity")
		}
		admitted = desc
	}
	if admitted.Address == "" {
		return types.RelayDescriptor{}, errors.New("ivnp relay is not admitted")
	}
	return admitted, nil
}

// DialIVNP uses already selected relay reachability; it never chooses a route
// or falls back to a different Portal relay when the selection is invalid.
func (s *RelaySet) DialIVNP(ctx context.Context, endpoint ivnp.DestinationEndpoint, destination, port string) (net.Conn, error) {
	selected, err := s.IVNPRelay(destination)
	if err != nil {
		return nil, err
	}
	conn, err := transport.DialIVNP(ctx, endpoint, destination, port)
	if err != nil {
		return nil, err
	}
	current, err := s.IVNPRelay(destination)
	if err != nil || current.Address != selected.Address {
		_ = conn.SetDeadline(time.Now())
		_ = conn.Close()
		return nil, errors.New("ivnp relay admission changed during dial")
	}
	return conn, nil
}

// ListenIVNP gates accepted streams using IVNP-authenticated identity and the
// existing relay catalog. The caller owns endpoint readiness and lifetime, and
// must close the returned listener. Listen does not imply I2P readiness.
func (s *RelaySet) ListenIVNP(ctx context.Context, endpoint ivnp.DestinationEndpoint, address string) (net.Listener, error) {
	if s == nil || endpoint == nil {
		return nil, errors.New("ivnp endpoint and relay catalog are required")
	}
	listener, err := endpoint.ListenI2P(ctx, address)
	if err != nil {
		return nil, err
	}
	return &ivnpRelayListener{Listener: listener, relays: s}, nil
}

type ivnpRelayListener struct {
	net.Listener
	relays *RelaySet
}

func (l *ivnpRelayListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		destination, err := transport.IVNPPeerDestination(conn)
		if err == nil {
			_, err = l.relays.IVNPRelay(destination)
		}
		if err == nil {
			return conn, nil
		}
		// IVNP Close waits for a Streaming CLOSE acknowledgement. Rejected
		// peers must not hold the accept loop while that acknowledgement waits.
		_ = conn.SetDeadline(time.Now())
		_ = conn.Close()
	}
}
