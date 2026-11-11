package portal

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func (s *Server) rejectBackhaulLease(control *transport.QUICBackhaulControl, admitErr error) {
	code, reason := types.APIErrorCodeInvalidRequest, "invalid control message"
	switch {
	case errors.Is(admitErr, errLeaseNotFound):
		code, reason = types.APIErrorCodeLeaseNotFound, "lease not found"
	case errors.Is(admitErr, errLeaseRejected), errors.Is(admitErr, errLeaseDenied):
		code, reason = types.APIErrorCodeLeaseRejected, "lease rejected"
	case errors.Is(admitErr, errUnauthorized):
		code, reason = types.APIErrorCodeUnauthorized, "unauthorized"
	case errors.Is(admitErr, errTransportMismatch):
		code, reason = types.APIErrorCodeTransportMismatch, "transport mismatch"
	}
	_ = control.Reject(code, reason)
}

func (s *Server) admitBackhaulLease(ctx context.Context, conn *quic.Conn) (*leaseRecord, bool) {
	control, err := transport.AcceptQUICBackhaulControl(ctx, conn)
	if err != nil {
		_ = conn.CloseWithError(1, "control read failed")
		return nil, false
	}
	lease, err := s.registry.admitLeaseByToken(control.AccessToken, true)
	if err != nil {
		s.rejectBackhaulLease(control, err)
		return nil, false
	}
	if err := lease.datagram.BindBackhaul(conn); err != nil {
		_ = control.Reject("broker_closed", "broker closed")
		return nil, false
	}
	if err := control.Accept(); err != nil {
		_ = conn.CloseWithError(1, "control response failed")
		return nil, false
	}
	return lease, true
}

func (s *Server) noteBackhaulConnected(conn *quic.Conn, lease *leaseRecord) {
	sourceAddr := netip.Addr{}
	if remote := conn.RemoteAddr(); remote != nil {
		if addrPort, err := netip.ParseAddrPort(remote.String()); err == nil {
			sourceAddr = addrPort.Addr().Unmap()
		}
	}
	s.registry.Touch(lease.ServiceKey(), sourceAddr, time.Now())
	log.Info().
		Str("component", "quic-backhaul-listener").
		Str("address", lease.Address).
		Str("lease_name", lease.Name).
		Str("remote_addr", conn.RemoteAddr().String()).
		Msg("quic backhaul connected")
}
