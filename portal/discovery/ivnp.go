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
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// IVNPRelay resolves an authenticated destination against the current HTTPS
// verified catalog. It does not admit peers supplied by a stream or NetDB.
func (s *RelaySet) IVNPRelay(destination string) (types.RelayDescriptor, error) {
	destination, err := utils.NormalizeIVNPDestination(destination)
	if err != nil || s == nil {
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

// DialIVNP reaches the destination selected by the caller. The authenticated
// IVNP peer is checked by the transport; route authorization is bound to the
// reverse capability at the receiving relay rather than re-decided from a
// potentially stale local HTTPS catalog.
func (s *RelaySet) DialIVNP(ctx context.Context, endpoint ivnp.DestinationEndpoint, destination, port string) (net.Conn, error) {
	return transport.DialIVNP(ctx, endpoint, destination, port)
}

// ListenIVNP gates accepted streams using IVNP-authenticated identity. The
// reverse capability performs the route authorization after the peer identity
// is known, so this listener does not require a mutually converged HTTPS
// catalog. The caller owns endpoint readiness and lifetime.
func (s *RelaySet) ListenIVNP(ctx context.Context, endpoint ivnp.DestinationEndpoint, address string) (net.Listener, error) {
	if endpoint == nil {
		return nil, errors.New("ivnp endpoint is required")
	}
	listener, err := endpoint.ListenI2P(ctx, address)
	if err != nil {
		return nil, err
	}
	return &ivnpRelayListener{Listener: listener}, nil
}

type ivnpRelayListener struct {
	net.Listener
}

func (l *ivnpRelayListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if _, err := transport.IVNPPeerDestination(conn); err == nil {
			return conn, nil
		}
		// IVNP Close waits for a Streaming CLOSE acknowledgement. Rejected
		// peers must not hold the accept loop while that acknowledgement waits.
		_ = conn.SetDeadline(time.Now())
		_ = conn.Close()
	}
}
