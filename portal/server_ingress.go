package portal

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gosuda/keyless_tls/relay/l4"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/overlay"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type backhaulPendingSources struct {
	mu     sync.Mutex
	counts map[netip.Prefix]int
}

func newBackhaulPendingSources() *backhaulPendingSources {
	return &backhaulPendingSources{counts: make(map[netip.Prefix]int)}
}

func (p *backhaulPendingSources) acquire(remote net.Addr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	prefix, ok := backhaulSourcePrefix(remote)
	if !ok {
		return true
	}
	if p.counts[prefix] >= quicBackhaulPerSourceLimit {
		return false
	}
	p.counts[prefix]++
	return true
}

func (p *backhaulPendingSources) release(remote net.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	prefix, ok := backhaulSourcePrefix(remote)
	if !ok {
		return
	}
	if p.counts[prefix]--; p.counts[prefix] <= 0 {
		delete(p.counts, prefix)
	}
}

func backhaulSourcePrefix(remote net.Addr) (netip.Prefix, bool) {
	addrPort, err := netip.ParseAddrPort(remote.String())
	if err != nil {
		return netip.Prefix{}, false
	}
	addr := addrPort.Addr().Unmap()
	if addr.Is4() {
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	return netip.PrefixFrom(addr, 64).Masked(), true
}

func (s *Server) rejectAdmitReverseOffer(offer overlay.ReverseOffer, admitErr error) {
	switch {
	case errors.Is(admitErr, errLeaseRejected):
		offer.RejectPending()
	case errors.Is(admitErr, errLeaseDenied):
		offer.RejectDenied()
	default:
		offer.RejectUnavailable()
	}
}

func (s *Server) completeAdmitReverseOffer(lease *leaseRecord, offer overlay.ReverseOffer) {
	reservation, err := lease.reverse.ReserveOffer(offer.Connection())
	if err != nil {
		offer.RejectCapacity()
		offer.Close()
		return
	}
	defer reservation.Cancel()
	if err := offer.Accept(); err != nil {
		offer.Close()
		return
	}
	_ = offer.Connection().SetDeadline(time.Time{})
	if err := reservation.Commit(); err != nil {
		offer.Close()
		return
	}
}

func (s *Server) admitReverseOffer(offer overlay.ReverseOffer) {
	lease, err := s.registry.admitLeaseIdentity(offer.ServiceIdentity, offer.LeaseID, time.Now().UTC(), false)
	if err != nil {
		s.rejectAdmitReverseOffer(offer, err)
		offer.Close()
		return
	}
	s.completeAdmitReverseOffer(lease, offer)
}

func (s *Server) serveTCP(record *leaseRecord) {
	for {
		inbound, err := record.tcpListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if !s.admitIngress(inbound, false) {
			_ = inbound.Close()
			continue
		}
		bridge, err := s.registry.admitBridge(s.ingressCtx, record, inbound)
		if err != nil {
			_ = inbound.Close()
			s.releaseIngress(inbound, false)
			continue
		}
		go func() {
			defer s.releaseIngress(inbound, false)
			defer record.releaseBridge(bridge)
			s.bridgeTCPConn(record, bridge, inbound)
		}()
	}
}

func (s *Server) bridgeTCPConn(record *leaseRecord, bridge *leaseBridge, inbound net.Conn) {
	ctx, cancel := context.WithTimeout(bridge.ctx, defaultClaimTimeout)
	defer cancel()
	for {
		reverse, err := record.reverse.Acquire(ctx)
		if err != nil {
			return
		}
		if err := s.registry.activateBridge(record, bridge, reverse); err != nil {
			_ = reverse.Close()
			return
		}
		if err := transport.WriteRawStart(reverse); err != nil {
			_ = reverse.Close()
			continue
		}
		s.proxy.bridge(bridge.ctx, inbound, reverse, record.ServiceKey(), s.registry.bps)
		return
	}
}

// SetServiceIdentityAccess applies the relay's current access decision for one
// identity to the portal data path. The relay owns the decision; this only
// carries the result across the boundary, including revoking cached content.
// False means a newer relay snapshot has already reached Portal: the caller
// must reload the committed snapshot before retrying. Stale values never apply.
func (s *Server) admitIngress(conn net.Conn, inspecting bool) bool {
	s.ingressMu.Lock()
	defer s.ingressMu.Unlock()
	if s.ingressClosed {
		return false
	}
	if inspecting {
		if s.ingressInspecting >= publicInspectionLimit {
			return false
		}
	} else if s.ingressTenants >= publicIngressLimit {
		return false
	}
	if s.ingressConns == nil {
		s.ingressConns = make(map[net.Conn]struct{})
	}
	s.ingressConns[conn] = struct{}{}
	if inspecting {
		s.ingressInspecting++
	} else {
		s.ingressTenants++
	}
	s.ingressWorkers.Add(1)
	return true
}

func (s *Server) promoteIngress() bool {
	s.ingressMu.Lock()
	defer s.ingressMu.Unlock()
	if s.ingressClosed || s.ingressTenants >= publicIngressLimit {
		return false
	}
	s.ingressInspecting--
	s.ingressTenants++
	return true
}

func (s *Server) releaseIngress(conn net.Conn, inspecting bool) {
	s.ingressMu.Lock()
	delete(s.ingressConns, conn)
	if inspecting {
		s.ingressInspecting--
	} else {
		s.ingressTenants--
	}
	s.ingressMu.Unlock()
	s.ingressWorkers.Done()
}

func (s *Server) closeIngress() {
	s.ingressMu.Lock()
	s.ingressClosed = true
	conns := make([]net.Conn, 0, len(s.ingressConns))
	for conn := range s.ingressConns {
		conns = append(conns, conn)
	}
	s.ingressMu.Unlock()
	if s.sniListener != nil {
		_ = s.sniListener.Close()
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (s *Server) bridgeLeaseConn(ctx context.Context, conn net.Conn, record *leaseRecord, helloSpan []byte) error {
	bridge, err := s.registry.admitBridge(ctx, record, conn)
	if err != nil {
		return err
	}
	defer record.releaseBridge(bridge)
	claimCtx, cancel := context.WithTimeout(bridge.ctx, defaultClaimTimeout)
	defer cancel()
	binding := s.registry.bindings.Issue(record.id, helloSpan)
	defer s.registry.bindings.Discard(binding)
	for {
		session, err := record.reverse.Acquire(claimCtx)
		if err != nil {
			return fmt.Errorf("acquire lease connection: %w", err)
		}
		if err := s.registry.activateBridge(record, bridge, session); err != nil {
			_ = session.Close()
			return err
		}
		if err := transport.WriteTLSStart(session, binding); err != nil {
			_ = session.Close()
			continue
		}
		s.proxy.bridge(bridge.ctx, conn, session, record.ServiceKey(), s.registry.bps)
		return nil
	}
}

func (s *Server) runRegistryJanitor(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return errJanitorIntervalMustBePositive
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			now := time.Now()
			records := s.registry.cleanupExpired(now)
			s.registry.bindings.SweepExpired(now)
			for _, record := range records {
				s.deleteLeaseDNS(ctx, record)
			}
		}
	}
}

func (s *Server) newQUICBackhaulListener(apiTLS *tls.Config) (*quic.Listener, error) {
	if apiTLS.GetCertificate == nil {
		return nil, fmt.Errorf("quic backhaul requires api tls certificate")
	}
	return transport.ListenQUICBackhaul(s.config().SNIListenAddr, apiTLS.GetCertificate)
}

func (s *Server) dispatchRunQUICBackhaulListener(ctx context.Context, conn *quic.Conn, pending chan struct{}, sources *backhaulPendingSources, handlers *sync.WaitGroup) {
	if !sources.acquire(conn.RemoteAddr()) {
		_ = conn.CloseWithError(1, "backhaul authentication busy")
		return
	}
	select {
	case pending <- struct{}{}:
		remote := conn.RemoteAddr()
		authCtx, authCancel := context.WithTimeout(ctx, quicBackhaulAuthTimeout)
		handlers.Go(func() {
			defer authCancel()
			defer sources.release(remote)
			defer func() { <-pending }()
			s.handleQUICBackhaulConn(authCtx, conn)
		})
	default:
		sources.release(conn.RemoteAddr())
		_ = conn.CloseWithError(1, "backhaul authentication busy")
	}
}

func quicBackhaulListenerStopped(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	return ctx.Err() != nil || errors.Is(err, quic.ErrServerClosed) || errors.Is(err, net.ErrClosed)
}

func (s *Server) pollRunQUICBackhaulListener(ctx context.Context, pending chan struct{}, sources *backhaulPendingSources, handlers *sync.WaitGroup) error {
	for {
		conn, err := s.quicBackhaul.Accept(ctx)
		if quicBackhaulListenerStopped(ctx, err) {
			return nil
		}
		if err != nil {
			return err
		}
		s.dispatchRunQUICBackhaulListener(ctx, conn, pending, sources, handlers)
	}
}

func (s *Server) runQUICBackhaulListener(ctx context.Context) error {
	if s.quicBackhaul == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	var handlers sync.WaitGroup
	defer func() {
		cancel()
		handlers.Wait()
	}()
	pending := make(chan struct{}, quicBackhaulPendingLimit)
	sources := newBackhaulPendingSources()
	return s.pollRunQUICBackhaulListener(ctx, pending, sources, &handlers)
}

func relayDiscoveryRefreshStopped(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	return ctx.Err() != nil
}

func (s *Server) refreshRunRelayDiscoveryLoop(ctx context.Context, refresher *discovery.Refresher, now time.Time) error {
	self, err := s.newSelfDescriptor(now)
	if err != nil {
		return fmt.Errorf("build relay discovery descriptor: %w", err)
	}
	refreshErr := refresher.Refresh(ctx, &self)
	if relayDiscoveryRefreshStopped(ctx, refreshErr) {
		return nil
	}
	if refreshErr != nil {
		return refreshErr
	}
	return nil
}

func (s *Server) runRelayDiscoveryLoop(ctx context.Context) error {
	if s.relaySet == nil {
		<-ctx.Done()
		return nil
	}
	refresher := discovery.NewRefresher(s.relaySet)
	ticker := time.NewTicker(discovery.DiscoveryPollInterval)
	defer ticker.Stop()

	for {
		if err := s.refreshRunRelayDiscoveryLoop(ctx, refresher, time.Now().UTC()); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (s *Server) newSelfDescriptor(now time.Time) (types.RelayDescriptor, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	cfg := s.config()

	ivnpDestination := ""
	if s.overlay != nil {
		ivnpDestination = s.overlay.Destination()
	}
	return discovery.SignRelayDescriptor(types.RelayDescriptor{
		Address:           s.identity.Address,
		Version:           types.DiscoveryVersion,
		IssuedAt:          now,
		ExpiresAt:         now.Add(discovery.DiscoveryDescriptorTTL),
		APIHTTPSAddr:      cfg.PortalURL,
		IVNPDestination:   ivnpDestination,
		SupportsUDP:       s.supportsUDP(),
		SupportsTCP:       s.supportsTCP(),
		ActiveConnections: s.proxy.activeConnectionCount(),
		TCPBPS:            s.proxy.currentTCPBPS(now),
	}, s.authority)
}

func removeRelayURL(inputs []string, target string) []string {
	var filtered []string
	for _, input := range inputs {
		if input != target {
			filtered = append(filtered, input)
		}
	}
	return filtered
}

func (s *Server) servePublicIngressConn(ctx context.Context, conn net.Conn) {
	inspecting := true
	defer func() { s.releaseIngress(conn, inspecting) }()
	clientHello, wrappedConn, err := l4.InspectClientHello(conn, defaultClientHelloWait)
	if err != nil {
		if wrappedConn != nil {
			_ = wrappedConn.Close()
		} else {
			_ = conn.Close()
		}
		return
	}
	helloSpan := clientHello.HandshakeMessage
	serverName := utils.NormalizeHostname(clientHello.ServerName)
	localTLS := utils.IsLocalTLSHostname(serverName, s.registry.rootHostname)
	relayAPI := serverName == "" || serverName == s.identity.Name
	if !localTLS && (relayAPI || s.registry.cache.Has(serverName)) {
		select {
		case s.apiHandoff.conns <- wrappedConn:
		case <-s.apiHandoff.done:
			_ = wrappedConn.Close()
		case <-ctx.Done():
			_ = wrappedConn.Close()
		}
		return
	}
	if !s.promoteIngress() {
		_ = wrappedConn.Close()
		return
	}
	inspecting = false
	s.bridgePublicIngressLease(ctx, wrappedConn, serverName, helloSpan)
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
