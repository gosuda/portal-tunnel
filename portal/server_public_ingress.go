package portal

import (
	"context"
	"net"

	"github.com/gosuda/keyless_tls/relay/l4"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

func (s *Server) servePublicIngressConn(ctx context.Context, conn net.Conn) {
	inspecting := true
	defer func() { s.releaseIngress(conn, inspecting) }()
	wrappedConn, helloSpan, serverName, ok := s.inspectPublicIngressHello(ctx, conn)
	if !ok {
		return
	}
	if !s.promoteIngress() {
		_ = wrappedConn.Close()
		return
	}
	inspecting = false
	s.bridgePublicIngressLease(ctx, wrappedConn, serverName, helloSpan)
}

func (s *Server) inspectPublicIngressHello(ctx context.Context, conn net.Conn) (net.Conn, []byte, string, bool) {
	clientHello, wrappedConn, err := l4.InspectClientHello(conn, defaultClientHelloWait)
	if err != nil {
		if wrappedConn != nil {
			_ = wrappedConn.Close()
		} else {
			_ = conn.Close()
		}
		return nil, nil, "", false
	}
	helloSpan := clientHello.HandshakeMessage
	serverName := utils.NormalizeHostname(clientHello.ServerName)
	if serverName == "" || serverName == s.identity.Name || s.registry.cache.Has(serverName) {
		select {
		case s.apiHandoff.conns <- wrappedConn:
		case <-s.apiHandoff.done:
			_ = wrappedConn.Close()
		case <-ctx.Done():
			_ = wrappedConn.Close()
		}
		return nil, nil, "", false
	}
	return wrappedConn, helloSpan, serverName, true
}

func (s *Server) bridgePublicIngressLease(ctx context.Context, wrappedConn net.Conn, serverName string, helloSpan []byte) {
	record, ok := s.registry.Lookup(serverName)
	if !ok {
		log.Warn().
			Str("server_name", serverName).
			Str("remote_addr", wrappedConn.RemoteAddr().String()).
			Msg("unknown public ingress hostname")
		_ = wrappedConn.Close()
		return
	}
	if err := s.bridgeLeaseConn(ctx, wrappedConn, record, helloSpan); err != nil {
		log.Warn().Err(err).Msg("bridge public ingress")
		_ = wrappedConn.Close()
		return
	}
}
