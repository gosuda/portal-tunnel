package overlay

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"time"

	"gosuda.org/ivnp"
	"gosuda.org/ivnp/foundation"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// ReverseOffer is a capability-verified inbound reverse connection awaiting
// portal lease admission. Connection ownership transfers with the offer.
type ReverseOffer struct {
	ServiceIdentity types.ServiceIdentityKey
	LeaseID         string
	conn            net.Conn
}

// Connection returns the connection whose ownership transferred with the offer.
func (o ReverseOffer) Connection() net.Conn { return o.conn }

// Accept writes the accepted status for the reverse-offer protocol.
func (o ReverseOffer) Accept() error {
	_, err := o.respond(types.OverlayStatusAccepted)
	return err
}

// RejectUnavailable writes the unavailable status for the reverse-offer protocol.
func (o ReverseOffer) RejectUnavailable() { _, _ = o.respond(types.OverlayStatusUnavailable) }

// RejectCapacity writes the capacity status for the reverse-offer protocol.
func (o ReverseOffer) RejectCapacity() { _, _ = o.respond(types.OverlayStatusCapacity) }

// RejectPending writes the status of a lease that waits for approval.
func (o ReverseOffer) RejectPending() { _, _ = o.respond(types.OverlayStatusPending) }

// RejectDenied writes the status of a lease the relay denied or banned.
func (o ReverseOffer) RejectDenied() { _, _ = o.respond(types.OverlayStatusDenied) }

// Close releases the connection transferred with the offer.
func (o ReverseOffer) Close() { closeNow(o.conn) }

func (o ReverseOffer) respond(status byte) (int, error) { return o.conn.Write([]byte{status}) }

func (r *Runtime) acceptReverse(conn net.Conn) {
	handoff := false
	defer func() {
		if !handoff {
			closeNow(conn)
		}
	}()
	raw, ok := acceptReverseRead(conn)
	if !ok {
		return
	}
	claims, ok := r.acceptReverseVerify(conn, raw)
	if !ok {
		return
	}
	select {
	case r.offers <- ReverseOffer{ServiceIdentity: claims.LeaseIdentity.ServiceKey(), LeaseID: claims.LeaseID, conn: conn}:
		handoff = true
	case <-r.ctx.Done():
	}
}

func acceptReverseRead(conn net.Conn) ([]byte, bool) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var size uint16
	if err := binary.Read(conn, binary.BigEndian, &size); err != nil || size == 0 || int(size) > capabilityLimit {
		return nil, false
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return nil, false
	}
	return raw, true
}

func (r *Runtime) acceptReverseVerify(conn net.Conn, raw []byte) (capabilityClaims, bool) {
	peer, err := peerDestination(conn)
	if err != nil {
		_, _ = conn.Write([]byte{types.OverlayStatusUnavailable})
		return capabilityClaims{}, false
	}
	claims, err := verifyCapability(string(raw), time.Now().UTC())
	if err != nil || !strings.EqualFold(claims.Ingress.Address, r.config.Authority.Identity().Address) || claims.Ingress.IVNPDestination != r.Destination() || claims.GatewayDestination != peer {
		_, _ = conn.Write([]byte{types.OverlayStatusUnavailable})
		return capabilityClaims{}, false
	}
	return claims, true
}

func (r *Runtime) dial(ctx context.Context, destination string) (net.Conn, error) {
	if r.endpoint == nil {
		return nil, errOverlayEndpointIsUnavailable
	}
	destination, err := normalizeIVNPDestination(destination)
	if err != nil {
		return nil, err
	}
	conn, err := r.endpoint.DialContext(ctx, "i2p", net.JoinHostPort(destination, types.OverlayStreamPort))
	if err != nil {
		return nil, err
	}
	peer, err := peerDestination(conn)
	if err != nil || peer != destination {
		closeNow(conn)
		return nil, errOverlayPeerDoesNotMatchDestination
	}
	return conn, nil
}

func peerDestination(conn net.Conn) (string, error) {
	peer, ok := conn.RemoteAddr().(ivnp.Addr)
	if !ok || peer.Hash == (ivnp.Hash{}) || peer.Port == 0 {
		return "", errOverlayConnectionLacksPeerIdentity
	}
	return foundation.B32(peer.Hash), nil
}

func closeNow(conn net.Conn) {
	if conn == nil {
		return
	}
	_ = conn.SetDeadline(time.Now())
	_ = conn.Close()
}
