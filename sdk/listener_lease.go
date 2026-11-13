package sdk

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/certmonitor"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type listenerSnapshot struct {
	hostname       string
	legacyHostname string

	aliasHostname       string
	udpAddr             string
	tcpAddr             string
	accessToken         string
	reverse             types.ReverseEndpoint
	expiresAt           time.Time
	tenantTLS           tenantTLSClient
	certificateObserver *certmonitor.CertificateObserver

	approval RelayApproval

	endpointsLogged bool

	chainCheckedAt time.Time
}

func (s listenerSnapshot) hasRawEndpoint() bool {
	return s.udpAddr != "" || s.tcpAddr != ""
}

func (l *listener) clearLease(reason string) *listenerSnapshot {
	if l == nil || l.lease == nil {
		return nil
	}
	lease := l.lease.Swap(listenerSnapshot{})

	if l.mitmManager != nil {
		l.mitmManager.reset()
	}
	if l.datagram != nil && reason != "" {
		l.datagram.Clear(reason)
	}
	if lease.accessToken == "" && lease.tenantTLS == nil {
		return nil
	}
	return &lease
}

func (l *listener) leaseSnapshot() (listenerSnapshot, bool) {
	if l == nil || l.lease == nil {
		return listenerSnapshot{}, false
	}
	lease := l.lease.Load()
	if lease.accessToken == "" {
		return listenerSnapshot{}, false
	}
	return lease, true
}

func (l *listener) Accept() (net.Conn, error) {
	if l.accepted == nil {
		return nil, net.ErrClosed
	}
	select {
	case <-l.doneCh:
		return nil, net.ErrClosed
	case conn := <-l.accepted:
		if conn == nil {
			return nil, net.ErrClosed
		}
		return conn, nil
	}
}

func (l *listener) admit(ctx context.Context, conn net.Conn) {
	defer func() { <-l.admitting }()

	nextConn, handled, err := l.mitmManager.maybeHandleConn(conn)
	if err != nil {
		log.Debug().
			Err(err).
			Str("relay_url", l.api.relayURL.String()).
			Str("address", l.identity.Address).
			Msg("admitting a self-probe or channel binding connection failed")
	}
	if handled {
		return
	}

	if ctx.Err() != nil {
		_ = nextConn.Close()
		return
	}
	select {
	case <-ctx.Done():
		_ = nextConn.Close()
	case l.accepted <- nextConn:
	}
}

func (l *listener) acceptDatagram() (types.DatagramFrame, error) {
	if l.datagram == nil {
		return types.DatagramFrame{}, net.ErrClosed
	}

	frame, err := l.datagram.Accept(l.doneCh)
	if err != nil {
		return types.DatagramFrame{}, err
	}

	frame.Payload = bytes.Clone(frame.Payload)
	if lease, ok := l.leaseSnapshot(); ok {
		frame.UDPAddr = lease.udpAddr
	}
	frame.Address = l.identity.Address
	if l.api != nil && l.api.relayURL != nil {
		frame.RelayURL = l.api.relayURL.String()
	}
	return frame, nil
}

func (l *listener) sendDatagram(frame types.DatagramFrame) error {
	if l.datagram == nil {
		return net.ErrClosed
	}

	if l.identity.Address == "" {
		return net.ErrClosed
	}
	if frameAddress := strings.TrimSpace(frame.Address); frameAddress != "" && frameAddress != l.identity.Address {
		return errDatagramFrameTargetsStaleAddress
	}
	return l.datagram.SendFrame(frame)
}

func (l *listener) publicURLForLease(lease listenerSnapshot) string {
	if endpoint, ok := lease.tenantTLS.(*namespaceTLS); ok && !endpoint.local.Ready() {
		return ""
	}
	return l.leaseURL(lease.hostname)
}

func (l *listener) aliasURLForLease(lease listenerSnapshot) string {
	return l.leaseURL(lease.aliasHostname)
}

func (l *listener) leaseURL(hostname string) string {
	baseURL := l.api.relayURL
	if baseURL == nil || strings.TrimSpace(hostname) == "" {
		return ""
	}
	authority := relayAuthority(baseURL, hostname)
	if authority == "" {
		return ""
	}
	scheme := cmp.Or(baseURL.Scheme, "https")
	return (&url.URL{
		Scheme: scheme,
		Host:   authority,
	}).String()
}

func relayAuthority(relayURL *url.URL, hostname string) string {
	if relayURL == nil {
		return ""
	}
	host := cmp.Or(strings.TrimSpace(hostname), strings.TrimSpace(relayURL.Hostname()))
	if host == "" {
		return ""
	}
	port := cmp.Or(relayURL.Port(), "443")
	return net.JoinHostPort(host, port)
}

func (l *listener) runStaticCache(ctx context.Context) {
	limits, available := l.api.cacheLimits()
	if !available {
		log.Info().Str("relay_url", l.api.relayURL.String()).Msg("relay cache unavailable; serving through the origin tunnel")
		return
	}
	syncer := l.cache.Subscribe(*l.api.relayURL, limits)
	defer syncer.Close()
	for syncer.Next(ctx) {
		lease, ok := l.leaseSnapshot()
		if !ok {
			return
		}
		if err := syncer.Sync(ctx, l.api.httpClient(), lease.accessToken); err != nil && ctx.Err() == nil {
			if l.runStaticCacheSync(ctx, err) {
				return
			}
		}
	}
}

func (l *listener) runStaticCacheSync(ctx context.Context, syncErr error) bool {
	log.Warn().Err(syncErr).Str("relay_url", l.api.relayURL.String()).Msg("static cache population skipped; origin tunnel remains available")
	if apiErr, ok := errors.AsType[*types.APIRequestError](syncErr); ok && (apiErr.StatusCode == http.StatusServiceUnavailable || apiErr.IsRateLimited()) {
		delay := cmp.Or(apiErr.RetryAfter, time.Second)
		if !utils.SleepOrDone(ctx, delay) {
			return true
		}
	}
	return false
}

func (l *listener) runLease(ctx context.Context) error {
	lease, ok := l.leaseSnapshot()
	if !ok || lease.hostname == "" {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errLeaseRefreshRequired
	}
	return l.runLeaseExecute(ctx, lease)
}

func (l *listener) runLeaseReportError(leaseCtx context.Context, errCh chan error, reportErr error) {
	select {
	case errCh <- reportErr:
	case <-leaseCtx.Done():
	}
}

func (l *listener) runLeaseStartProbe(leaseCtx context.Context, workers *sync.WaitGroup, probeReady chan struct{}) {
	workers.Add(1)
	go func() {
		defer workers.Done()
		l.mitmManager.run(leaseCtx, probeReady)
	}()
	if l.cache != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			l.runStaticCache(leaseCtx)
		}()
	}
}

func (l *listener) runLeaseStartSessions(leaseCtx context.Context, workers *sync.WaitGroup, errCh chan error, probeReady chan struct{}, lease listenerSnapshot) *leaseReverseTransport {
	reverseTransport := newLeaseReverseTransport(l)
	for sessionSlot := range defaultReadyTarget {
		sessionSlot++
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := l.runReverseSessionLoop(leaseCtx, lease.tenantTLS, sessionSlot, reverseTransport, probeReady); err != nil {
				l.runLeaseReportError(leaseCtx, errCh, err)
			}
		}()
	}
	return reverseTransport
}

func (l *listener) runLeaseStartLoops(leaseCtx context.Context, workers *sync.WaitGroup, errCh chan error) {
	// Certificate observations publish local status immediately. Remote reports
	// stay serialized with access-token rotation in the existing renewal loop.
	var renew chan struct{}
	if lease, ok := l.leaseSnapshot(); ok {
		if endpoint, ok := lease.tenantTLS.(*namespaceTLS); ok {
			renew = make(chan struct{}, 1)
			renew <- struct{}{}
			workers.Add(1)
			go func() {
				defer workers.Done()
				for {
					var expiry <-chan time.Time
					var timer *time.Timer
					if until := time.Until(endpoint.local.CertificateExpiry()); until > 0 {
						timer = time.NewTimer(until)
						expiry = timer.C
					}
					select {
					case <-leaseCtx.Done():
						if timer != nil {
							timer.Stop()
						}
						return
					case <-endpoint.local.CertificateChanges():
					case <-expiry:
					}
					if timer != nil {
						timer.Stop()
					}
					l.reportAvailable()
					select {
					case renew <- struct{}{}:
					default:
					}
				}
			}()
		}
	}
	if l.udpEnabled {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := l.runDatagramLoop(leaseCtx); err != nil {
				l.runLeaseReportError(leaseCtx, errCh, err)
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		if err := l.runRenewLoop(leaseCtx, renew); err != nil {
			l.runLeaseReportError(leaseCtx, errCh, err)
		}
	}()
}

func (l *listener) runLeaseAwait(ctx context.Context, cancel context.CancelFunc, workers *sync.WaitGroup, errCh chan error) error {
	select {
	case <-ctx.Done():
		cancel()
		workers.Wait()
		return ctx.Err()
	case err := <-errCh:
		cancel()
		workers.Wait()
		return err
	}
}

func (l *listener) runLeaseExecute(ctx context.Context, lease listenerSnapshot) error {
	leaseCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	probeReady := make(chan struct{}, 1)
	errCh := make(chan error, defaultReadyTarget+1)
	var workers sync.WaitGroup
	l.runLeaseStartProbe(leaseCtx, &workers, probeReady)
	reverseTransport := l.runLeaseStartSessions(leaseCtx, &workers, errCh, probeReady, lease)
	defer reverseTransport.Close()
	l.runLeaseStartLoops(leaseCtx, &workers, errCh)
	return l.runLeaseAwait(ctx, cancel, &workers, errCh)
}

type runReverseSessionLoopState struct {
	listener    *listener
	sessionSlot int
	retries     int
}

func (s *runReverseSessionLoopState) runReverseSessionLoopOpenFailed(ctx context.Context, lease listenerSnapshot, openErr error) (bool, error) {
	l := s.listener
	if errors.Is(openErr, context.Canceled) || errors.Is(openErr, net.ErrClosed) {
		return true, nil
	}
	if staleLeaseError(openErr) {
		return true, errLeaseRefreshRequired
	}
	l.reportRefusal(openErr)
	if l.isAlternateReverseEndpoint(lease.reverse.URL) {
		stop, failErr := l.failoverReverseEndpoint(ctx, lease, s.sessionSlot, openErr, "reverse endpoint connect")
		if failErr != nil {
			return true, failErr
		}
		if stop {
			return true, nil
		}
		return false, nil
	}
	s.retries++
	if !l.waitRetry(ctx, "reverse session connect", openErr, s.retries, s.sessionSlot) {
		return true, openErr
	}
	return false, nil
}

func (s *runReverseSessionLoopState) runReverseSessionLoopClaimRetry(ctx context.Context, lease listenerSnapshot, claimErr error) (bool, error) {
	l := s.listener
	if l.isAlternateReverseEndpoint(lease.reverse.URL) {
		stop, failErr := l.failoverReverseEndpoint(ctx, lease, s.sessionSlot, claimErr, "reverse endpoint session")
		if failErr != nil {
			return true, failErr
		}
		if stop {
			return true, nil
		}
		return false, nil
	}
	s.retries++
	if !l.waitRetry(ctx, "reverse session connect", claimErr, s.retries, s.sessionSlot) {
		return true, claimErr
	}
	return false, nil
}

func (s *runReverseSessionLoopState) runReverseSessionLoopSettle(ctx context.Context, lease listenerSnapshot, conn net.Conn, tenantTLS tenantTLSClient, probeReady chan<- struct{}) (bool, error) {
	l := s.listener
	l.reportStreamReady()
	select {
	case probeReady <- struct{}{}:
	default:
	}
	claimed, claimErr := l.claimReverseSession(ctx, conn, tenantTLS)
	switch {
	case claimErr == nil:
		s.retries = 0
		return false, nil
	case errors.Is(claimErr, context.Canceled), errors.Is(claimErr, net.ErrClosed):
		return true, nil
	case claimed:
		log.Debug().
			Err(claimErr).
			Str("relay_url", l.api.relayURL.String()).
			Str("address", l.identity.Address).
			Int("reverse_session_slot", s.sessionSlot).
			Msg("tenant tls handshake failed")
		s.retries = 0
		return false, nil
	default:
		return s.runReverseSessionLoopClaimRetry(ctx, lease, claimErr)
	}
}

func (l *listener) runReverseSessionLoop(ctx context.Context, tenantTLS tenantTLSClient, sessionSlot int, reverseTransport *leaseReverseTransport, probeReady chan<- struct{}) error {
	state := &runReverseSessionLoopState{listener: l, sessionSlot: sessionSlot}
	for {
		lease, _ := l.leaseSnapshot()
		conn, err := reverseTransport.Open(ctx)
		if err != nil {
			if done, returnErr := state.runReverseSessionLoopOpenFailed(ctx, lease, err); done {
				return returnErr
			}
			continue
		}
		if done, returnErr := state.runReverseSessionLoopSettle(ctx, lease, conn, tenantTLS, probeReady); done {
			return returnErr
		}
	}
}

func (l *listener) failoverReverseEndpoint(ctx context.Context, lease listenerSnapshot, sessionSlot int, err error, operation string) (bool, error) {
	if refreshErr := l.refreshReverseEndpointAfterFailure(ctx, lease.reverse.Capability); refreshErr != nil {
		return false, refreshErr
	}
	if !l.waitRetry(ctx, operation, err, 1, sessionSlot) {
		return true, nil
	}
	return false, nil
}

func (l *listener) claimReverseSession(ctx context.Context, conn net.Conn, tenantTLS tenantTLSClient) (bool, error) {
	defer l.reportStreamClosed()
	binding, err := transport.ReadStart(ctx, conn, defaultHandshakeTimeout)
	if err != nil {
		return false, err
	}

	acceptedConn := conn
	if len(binding) != 0 {
		handshakeCtx, cancel := context.WithTimeout(ctx, defaultHandshakeTimeout)
		defer cancel()
		acceptedConn, err = tenantTLS.TerminateConn(handshakeCtx, conn, binding)
		if err != nil {
			return true, err
		}
	}

	select {
	case <-ctx.Done():
		_ = acceptedConn.Close()
		return true, ctx.Err()
	case l.admitting <- struct{}{}:
	}
	go l.admit(ctx, acceptedConn)
	return true, nil
}

func (l *listener) isAlternateReverseEndpoint(rawURL string) bool {
	endpoint, err := url.Parse(strings.TrimSpace(rawURL))
	return err == nil && l.api != nil && l.api.relayURL != nil && (!strings.EqualFold(endpoint.Scheme, l.api.relayURL.Scheme) || !strings.EqualFold(endpoint.Host, l.api.relayURL.Host))
}

func (l *listener) validateReverseEndpointTransport(endpoint types.ReverseEndpoint) error {
	alternate := l.isAlternateReverseEndpoint(endpoint.URL)
	if runtime.GOOS == "js" && alternate {
		return errBrowserSDKCannotVerifyResolvedAddresses
	}
	if !l.overlay && endpoint.Overlay {
		return errRelayReturnedOverlayReverseEndpointBut
	}
	if !endpoint.Overlay {
		if alternate {
			return fmt.Errorf("relay reverse endpoint %s does not match the relay URL", endpoint.URL)
		}
		return l.validateDirectReverseEndpoint(endpoint)
	}

	return l.validateOverlayReverseEndpoint(endpoint)
}

func (l *listener) validateDirectReverseEndpoint(endpoint types.ReverseEndpoint) error {
	if endpoint.Gateway != nil {
		return errRelayReturnedGatewayMetadataDirectReverse
	}
	if l.overlay {
		l.warnOverlayDirect.Do(func() {
			log.Warn().
				Str("relay_url", l.api.relayURL.String()).
				Msg("overlay requested but the relay serves a direct reverse endpoint; continuing without overlay forwarding")
		})
	}
	return nil
}

func (l *listener) validateOverlayReverseEndpoint(endpoint types.ReverseEndpoint) error {
	if endpoint.Gateway == nil {
		return errRelayReturnedOverlayReverseEndpointWithout
	}
	gateway, err := discovery.VerifyRelayDescriptor(*endpoint.Gateway)
	if err != nil {
		return fmt.Errorf("verify overlay gateway descriptor: %w", err)
	}
	now := time.Now().UTC()
	if !gateway.ExpiresAt.After(now) || endpoint.ExpiresAt.After(gateway.ExpiresAt) {
		return errOverlayGatewayDescriptorDoesNotCover
	}
	if strings.TrimSpace(gateway.IVNPDestination) == "" {
		return errOverlayGatewayDescriptorHasNoDestination
	}
	gatewayURL, err := url.Parse(gateway.APIHTTPSAddr)
	if err != nil {
		return fmt.Errorf("parse overlay gateway URL: %w", err)
	}
	reverseURL, err := url.Parse(endpoint.URL)
	if err != nil {
		return fmt.Errorf("%w: %w", errInvalidOverlayReverseEndpointURL, err)
	}
	if reverseURL.Host == "" {
		return errInvalidOverlayReverseEndpointURL
	}
	if reverseURL.String() != utils.ResolveAPIURL(gatewayURL, types.PathSDKConnect).String() {
		return errOverlayReverseEndpointDoesNotMatch
	}
	return validatePublicReverseHostname(reverseURL.Hostname())
}
