package portal

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"gosuda.org/ivnp"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func (s *Server) startIVNP(ctx context.Context) error {
	s.ivnpContext = ctx
	if s.relaySet == nil {
		return errors.New("ivnp requires HTTPS relay discovery")
	}
	cfg, err := ivnp.LoadConfig(s.config().IVNPConfigPath)
	if err != nil {
		return err
	}
	s.ivnpNode, err = ivnp.New(cfg, ivnp.Options{})
	if err != nil {
		return err
	}
	if err := s.ivnpNode.Start(ctx); err != nil {
		return err
	}
	readyCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	s.ivnpEndpoint, err = s.ivnpNode.DestinationController().CreateDestination(readyCtx, ivnp.DestinationSpec{})
	if err != nil {
		return err
	}
	ready, ok := s.ivnpEndpoint.(ivnp.ReadyDestinationEndpoint)
	if !ok {
		return errors.New("ivnp endpoint does not report readiness")
	}
	if err := ready.WaitReady(readyCtx); err != nil {
		return err
	}
	// Listener lifetime is the server's context, not the readiness timeout.
	s.ivnpListener, err = s.relaySet.ListenIVNP(ctx, s.ivnpEndpoint, ":"+types.IVNPStreamPort)
	if err != nil {
		return err
	}
	s.ivnpSlots = make(chan struct{}, 128)
	s.ivnpReady.Store(true)
	return nil
}

func (s *Server) runIVNP(ctx context.Context) error {
	defer s.ivnpReady.Store(false)
	for {
		conn, err := s.ivnpListener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case s.ivnpSlots <- struct{}{}:
			go func() { defer func() { <-s.ivnpSlots }(); s.acceptIVNPReverse(conn) }()
		default:
			_ = conn.SetDeadline(time.Now())
			_ = conn.Close()
		}
	}
}

func (s *Server) acceptIVNPReverse(conn net.Conn) {
	accepted := false
	defer func() {
		if !accepted {
			_ = conn.SetDeadline(time.Now())
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(defaultClaimTimeout))
	var size uint16
	if err := binary.Read(conn, binary.BigEndian, &size); err != nil || size == 0 || size > types.IVNPTokenLimit {
		return
	}
	token := make([]byte, size)
	if _, err := io.ReadFull(conn, token); err != nil {
		return
	}
	lease, err := s.registry.admitLeaseByToken(string(token), false)
	if err != nil {
		_, _ = conn.Write([]byte{0})
		return
	}
	if _, err := conn.Write([]byte{types.IVNPReverseAccepted}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	if err := lease.stream.OfferConn(conn); err != nil {
		return
	}
	accepted = true
}

func (s *Server) closeIVNP() {
	s.ivnpReady.Store(false)
	if s.ivnpListener != nil {
		_ = s.ivnpListener.Close()
	}
	if s.ivnpEndpoint != nil {
		_ = s.ivnpEndpoint.Close()
	}
	if s.ivnpNode != nil {
		_ = s.ivnpNode.Close()
		_ = s.ivnpNode.Wait()
	}
}

// connectThroughIVNP attaches an SDK socket to the ingress's existing reverse
// queue. The ingress alone validates its token, owns its lease, and claims the
// stream. The gateway owns only these paired live connections.
func (s *Server) connectThroughIVNP(w http.ResponseWriter, r *http.Request, destination, token string) {
	if !s.ivnpReady.Load() {
		writeAPIErrorResponse(w, errFeatureUnavailable)
		return
	}
	select {
	case s.ivnpSlots <- struct{}{}:
		defer func() { <-s.ivnpSlots }()
	default:
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "ivnp reverse capacity exhausted")
		return
	}
	if token == "" || len(token) > types.IVNPTokenLimit {
		writeAPIErrorResponse(w, errUnauthorized)
		return
	}
	ingress, err := s.relaySet.IVNPRelay(destination)
	if err != nil || destination == s.ivnpEndpoint.B32() {
		writeAPIErrorResponse(w, errUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultClaimTimeout)
	upstream, err := s.relaySet.DialIVNP(ctx, s.ivnpEndpoint, destination, types.IVNPStreamPort)
	cancel()
	if err != nil {
		writeAPIErrorResponse(w, errFeatureUnavailable)
		return
	}
	defer func() {
		_ = upstream.SetDeadline(time.Now())
		_ = upstream.Close()
	}()
	_ = upstream.SetDeadline(time.Now().Add(defaultClaimTimeout))
	if err := binary.Write(upstream, binary.BigEndian, uint16(len(token))); err != nil {
		writeAPIErrorResponse(w, errFeatureUnavailable)
		return
	}
	if _, err := io.Copy(upstream, strings.NewReader(token)); err != nil {
		writeAPIErrorResponse(w, errFeatureUnavailable)
		return
	}
	var response [1]byte
	if _, err := io.ReadFull(upstream, response[:]); err != nil || response[0] != types.IVNPReverseAccepted {
		writeAPIErrorResponse(w, errUnauthorized)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeAPIErrorResponse(w, errFeatureUnavailable)
		return
	}
	downstream, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer downstream.Close()
	stop := context.AfterFunc(s.ivnpContext, func() { _ = downstream.Close() })
	defer stop()
	_ = downstream.SetWriteDeadline(time.Now().Add(defaultClaimTimeout))
	if _, err := fmt.Fprint(buffered, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: raw\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	_ = downstream.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	s.proxy.bridge(&bufferedIVNPConn{Conn: downstream, reader: buffered.Reader}, upstream, ingress.Address, s.registry.policy.BPSManager())
}

type bufferedIVNPConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedIVNPConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *bufferedIVNPConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Close()
}
