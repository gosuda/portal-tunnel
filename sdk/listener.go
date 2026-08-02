package sdk

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type listenerConfig struct {
	Identity   types.Identity
	UDPEnabled bool
	TCPEnabled bool
	BanMITM    bool
	Metadata   func() types.LeaseMetadata
	RetryCount int
	relaySet   *discovery.RelaySet
}

var errLeaseRefreshRequired = errors.New("lease refresh required")

// shouldDropRelayFromActivePool is deliberately limited to errors that prove
// the relay cannot serve this client. Transport failures, including EOF, must
// be retried so a transient close cannot quarantine a relay for days.
func shouldDropRelayFromActivePool(err error) bool {
	return errors.Is(err, errRelayIncompatible) ||
		errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeFeatureUnavailable}) ||
		errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeTransportMismatch})
}

func isTerminalRelayError(err error) bool {
	return shouldDropRelayFromActivePool(err) ||
		errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeHostnameConflict}) ||
		errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeIPBanned})
}

func (l *listener) closeForTerminalRelayError(err error) bool {
	if !isTerminalRelayError(err) {
		return false
	}
	relayURL := l.route.ListenerRelayURL()
	var registrationErr *relayRegistrationError
	if errors.As(err, &registrationErr) && registrationErr.relayURL != "" {
		relayURL = registrationErr.relayURL
	}
	if l.relaySet != nil && relayURL != "" {
		l.relaySet.UnconfirmRelayURL(relayURL)
		if shouldDropRelayFromActivePool(err) {
			l.relaySet.DropRelayURLFromActivePool(relayURL)
		} else {
			l.relaySet.RecordActiveFailure(relayURL, 1)
		}
	}
	log.Error().
		Err(err).
		Str("relay_url", relayURL).
		Str("address", l.identity.Address).
		Msg("relay operation failed permanently; closing listener")
	_ = l.Close()
	return true
}

type listener struct {
	cancel    context.CancelFunc
	doneCh    <-chan struct{}
	closeOnce sync.Once

	relayURL       *url.URL
	route          discovery.Route
	metadata       func() types.LeaseMetadata
	identity       types.Identity
	relaySet       *discovery.RelaySet
	udpEnabled     bool
	tcpEnabled     bool
	dialTimeout    time.Duration
	requestTimeout time.Duration
	readyTarget    int
	retryCount     int
	retryWait      time.Duration
	leaseTTL       time.Duration
	renewBefore    time.Duration

	stream      *transport.ClientStream
	datagram    *transport.ClientDatagram
	mitmManager *mitmManager

	httpClient    *http.Client
	httpTransport *http.Transport
	tlsConfig     *tls.Config

	releaseVersion string

	lease *utils.Snapshot[listenerSnapshot]
}

// routeRelayURLs returns the public ingress relay and the relay that owns the
// lease and reverse stream. Multi-hop ingress forwards from entry to exit.
func routeRelayURLs(route discovery.Route) (entryURL, controlURL string, err error) {
	entryURL, err = utils.NormalizeRelayURL(route.ListenerRelayURL())
	if err != nil {
		return "", "", err
	}
	controlURL = entryURL
	if multiHop := route.MultiHop(); len(multiHop) > 0 {
		controlURL, err = utils.NormalizeRelayURL(multiHop[len(multiHop)-1])
		if err != nil {
			return "", "", err
		}
	}
	return entryURL, controlURL, nil
}

// newListener creates one relay listener. Multi-hop public ingress starts at
// the route entry, while lease control and the reverse stream terminate at
// the route exit.
// Only local config validation fails immediately; relay startup runs in the background until ready.
func newListener(ctx context.Context, route discovery.Route, cfg listenerConfig) (*listener, error) {
	listenerCtx, cancel := context.WithCancel(ctx)

	entryRelayURL, controlURL, err := routeRelayURLs(route)
	if err != nil {
		cancel()
		return nil, err
	}
	relayurl, err := url.Parse(controlURL)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("parse relay url: %w", err)
	}
	l := &listener{
		cancel:         cancel,
		doneCh:         listenerCtx.Done(),
		relayURL:       relayurl,
		route:          route.WithListenerRelayURL(entryRelayURL),
		metadata:       cfg.Metadata,
		identity:       cfg.Identity.Copy(),
		relaySet:       cfg.relaySet,
		udpEnabled:     cfg.UDPEnabled,
		tcpEnabled:     cfg.TCPEnabled,
		dialTimeout:    defaultDialTimeout,
		requestTimeout: defaultRequestTimeout,
		readyTarget:    defaultReadyTarget,
		retryCount:     cfg.RetryCount,
		retryWait:      defaultRetryWait,
		leaseTTL:       defaultLeaseTTL,
		renewBefore:    defaultRenewBefore,
		lease:          utils.NewSnapshot(listenerSnapshot{}, listenerSnapshot.snapshot),
	}
	l.mitmManager = newMITMManager(listenerCtx, l, cfg.BanMITM)
	l.stream = transport.NewClientStream(defaultReadyTarget, defaultHandshakeTimeout)
	if l.udpEnabled {
		l.datagram = transport.NewClientDatagram(func(err error) {
			log.Info().
				Err(err).
				Str("component", "sdk-quic-backhaul").
				Str("address", l.identity.Address).
				Msg("quic backhaul disconnected; waiting to reconnect")
		})
	}

	go l.run(listenerCtx)
	return l, nil
}

func (l *listener) metadataSnapshot() types.LeaseMetadata {
	if l.metadata == nil {
		return types.LeaseMetadata{}
	}
	return l.metadata()
}

func (l *listener) run(ctx context.Context) {
	var retries int

	for {
		err := l.registerAndConfigure(ctx)
		switch {
		case err == nil:
		case errors.Is(err, context.Canceled), errors.Is(err, net.ErrClosed):
			return
		default:
			if l.closeForTerminalRelayError(err) {
				return
			}
			retries++
			if !l.waitRetry(ctx, "lease registration", err, retries, 0) {
				_ = l.Close()
				return
			}
			continue
		}

		retries = 0
		publicURL := ""
		if lease, ok := l.leaseSnapshot(); ok {
			publicURL = l.publicURLForLease(lease)
		}
		event := log.Info().Str("address", l.identity.Address)
		if publicURL != "" {
			event.Msg("service ready at " + publicURL)
		} else {
			event.Msg("relay listener registered")
		}

		err = l.runLease(ctx)
		if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
			return
		}
		if l.closeForTerminalRelayError(err) {
			return
		}

		if errors.Is(err, errLeaseRefreshRequired) {
			lease := l.clearLease("lease refresh required")
			if lease != nil && lease.tlsCloser != nil {
				_ = lease.tlsCloser.Close()
			}
			l.resetTransport()
			relayURL := l.relayURL.String()
			log.Debug().
				Err(err).
				Str("relay_url", relayURL).
				Str("address", l.identity.Address).
				Msg("lease refresh required; re-registering")
			continue
		}

		relayURL := l.relayURL.String()
		log.Error().
			Err(err).
			Str("relay_url", relayURL).
			Str("address", l.identity.Address).
			Msg("listener connection retry budget exhausted; closing listener")
		_ = l.Close()
		return
	}
}

func (l *listener) Close() error {
	var closeErr error
	l.closeOnce.Do(func() {
		if l.cancel != nil {
			l.cancel()
		}

		lease := l.clearLease("")

		if l.stream != nil {
			l.stream.Drain()
		}
		if l.datagram != nil {
			l.datagram.Close()
		}

		if lease != nil && lease.hostname != "" && l.identity.Key() != "" && lease.accessToken != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			closeErr = errors.Join(closeErr, l.unregisterLease(ctx, lease.accessToken, lease.hopRoutes))
			cancel()
		}
		if lease != nil && lease.tlsCloser != nil {
			closeErr = errors.Join(closeErr, lease.tlsCloser.Close())
		}
		l.resetTransport()
	})
	return closeErr
}

type listenerSnapshot struct {
	hostname            string
	echConfigList       []byte
	udpAddr             string
	accessToken         string
	multihopAccessToken string
	expiresAt           time.Time
	sniPort             int
	publicURLBase       *url.URL
	tlsConfig           *tls.Config
	tlsCloser           io.Closer
	hopRoutes           []types.HopRoute
}

func (s listenerSnapshot) snapshot() listenerSnapshot {
	s.echConfigList = bytes.Clone(s.echConfigList)
	s.hopRoutes = append([]types.HopRoute(nil), s.hopRoutes...)
	if s.publicURLBase != nil {
		publicURLBase := *s.publicURLBase
		s.publicURLBase = &publicURLBase
	}
	if s.tlsConfig != nil {
		s.tlsConfig = s.tlsConfig.Clone()
	}
	return s
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
	if lease.accessToken == "" && lease.tlsCloser == nil {
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
	if l.stream == nil {
		return nil, net.ErrClosed
	}
	for {
		conn, err := l.stream.Accept(l.doneCh)
		if err != nil {
			return nil, err
		}

		nextConn, handled, handleErr := l.mitmManager.maybeHandleConn(conn)
		if handleErr != nil {
			log.Debug().
				Err(handleErr).
				Str("relay_url", l.relayURL.String()).
				Str("address", l.identity.Address).
				Msg("mitm self-probe handling failed")
		}
		if handled {
			continue
		}
		return &mitmProbeConn{Conn: nextConn, manager: l.mitmManager}, nil
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
	if l.relayURL != nil {
		frame.RelayURL = l.relayURL.String()
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
		return errors.New("datagram frame targets stale address")
	}
	return l.datagram.Send(frame.FlowID, frame.Payload)
}

func (l *listener) datagramReady() (string, bool, bool) {
	if l.datagram == nil {
		return "", false, false
	}

	hostname := ""
	udpAddr := ""
	if lease, ok := l.leaseSnapshot(); ok {
		hostname = lease.hostname
		udpAddr = lease.udpAddr
	}
	ready := l.datagram.Connected() && udpAddr != ""
	closed := false
	select {
	case <-l.doneCh:
		closed = true
	default:
	}
	pending := !ready && !closed && (hostname == "" || udpAddr != "")
	return udpAddr, ready, pending
}

func (l *listener) publicURLForLease(lease listenerSnapshot) string {
	baseURL := lease.publicURLBase
	if baseURL == nil {
		baseURL = l.relayURL
	}
	if baseURL == nil {
		return ""
	}
	if lease.hostname == "" {
		return ""
	}

	if baseURL.Scheme == "" {
		return "https://" + lease.hostname
	}

	host := lease.hostname
	sniPort := lease.sniPort
	scheme := strings.ToLower(strings.TrimSpace(baseURL.Scheme))
	if (scheme == "https" && sniPort == 443) || (scheme == "http" && sniPort == 80) {
		sniPort = 0
	}
	if sniPort > 0 {
		host = net.JoinHostPort(lease.hostname, fmt.Sprintf("%d", sniPort))
	}

	return (&url.URL{
		Scheme: baseURL.Scheme,
		Host:   host,
	}).String()
}

func (l *listener) runLease(ctx context.Context) error {
	lease, ok := l.leaseSnapshot()
	if !ok || lease.hostname == "" {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errLeaseRefreshRequired
	}
	leaseCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, max(l.readyTarget, 1)+1)
	if l.stream != nil && l.readyTarget > 0 {
		for sessionSlot := range l.readyTarget {
			sessionSlot++
			go func() {
				if err := l.runReverseSessionLoop(leaseCtx, lease.tlsConfig, sessionSlot); err != nil {
					select {
					case errCh <- err:
					case <-leaseCtx.Done():
					}
				}
			}()
		}
	}
	if l.udpEnabled {
		go l.runDatagramLoop(leaseCtx)
	}
	go func() {
		if err := l.runRenewLoop(leaseCtx); err != nil {
			select {
			case errCh <- err:
			case <-leaseCtx.Done():
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		cancel()
		return err
	}
}

func (l *listener) runReverseSessionLoop(ctx context.Context, tlsConfig *tls.Config, sessionSlot int) error {
	if l.stream == nil {
		return nil
	}

	var retries int
	for {
		conn, err := l.openReverseSession(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			retries++
			if !l.waitRetry(ctx, "reverse session connect", err, retries, sessionSlot) {
				return err
			}
			continue
		}

		claimed, err := l.stream.RunSession(ctx, conn, tlsConfig)
		switch {
		case err == nil:
			retries = 0
		case errors.Is(err, context.Canceled), errors.Is(err, net.ErrClosed):
			return nil
		case claimed:
			log.Debug().
				Err(err).
				Str("relay_url", l.relayURL.String()).
				Str("address", l.identity.Address).
				Int("reverse_session_slot", sessionSlot).
				Msg("tenant tls handshake failed")
			retries = 0
		default:
			retries++
			if !l.waitRetry(ctx, "reverse session connect", err, retries, sessionSlot) {
				return err
			}
		}
	}
}

func (l *listener) runDatagramLoop(ctx context.Context) {
	if l.datagram == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			l.datagram.Clear("lease stopped")
			return
		default:
		}

		conn, err := l.openQUICBackhaulSession(ctx)
		if err != nil {
			log.Info().
				Err(err).
				Str("component", "sdk-quic-backhaul").
				Str("address", l.identity.Address).
				Msg("quic backhaul unavailable; retrying")
			if !utils.SleepOrDone(ctx, 2*time.Second) {
				l.datagram.Clear("lease stopped")
				return
			}
			continue
		}

		log.Info().
			Str("component", "sdk-quic-backhaul").
			Str("address", l.identity.Address).
			Str("remote_addr", conn.RemoteAddr().String()).
			Msg("quic backhaul connected")

		recvDone, err := l.datagram.BindBackhaul(conn)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Info().
				Err(err).
				Str("component", "sdk-quic-backhaul").
				Str("address", l.identity.Address).
				Msg("quic backhaul did not bind cleanly; retrying")
			if !utils.SleepOrDone(ctx, time.Second) {
				return
			}
			continue
		}

		select {
		case <-ctx.Done():
			l.datagram.Clear("lease stopped")
			return
		case <-recvDone:
		}

		if !utils.SleepOrDone(ctx, time.Second) {
			return
		}
	}
}

func (l *listener) openReverseSession(ctx context.Context) (net.Conn, error) {
	lease, ok := l.leaseSnapshot()
	if !ok || lease.accessToken == "" {
		return nil, errors.New("access token is not available")
	}
	if l.tlsConfig == nil {
		return nil, errors.New("relay tls config is unavailable")
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: l.dialTimeout},
		Config:    l.tlsConfig.Clone(),
	}

	conn, err := dialer.DialContext(ctx, "tcp", utils.EnsurePort(l.relayURL.Host))
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    utils.ResolveAPIURL(l.relayURL, types.PathSDKConnect),
		Host:   l.relayURL.Host,
		Header: make(http.Header),
	}
	req.Header.Set(types.HeaderAccessToken, lease.accessToken)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "raw")

	if writeErr := req.Write(conn); writeErr != nil {
		_ = conn.Close()
		return nil, writeErr
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		apiErr := utils.DecodeAPIRequestError(resp)
		_ = conn.Close()
		return nil, apiErr
	}

	return wrapBufferedConn(conn, reader), nil
}

func (l *listener) openQUICBackhaulSession(ctx context.Context) (*quic.Conn, error) {
	lease, ok := l.leaseSnapshot()
	if !ok || lease.accessToken == "" {
		return nil, errors.New("access token is not available")
	}
	if lease.sniPort <= 0 {
		return nil, errors.New("sni port is not available")
	}
	if l.tlsConfig == nil {
		return nil, errors.New("relay tls config is unavailable")
	}
	host := strings.TrimSpace(l.relayURL.Hostname())
	if host == "" {
		host = strings.TrimSpace(l.relayURL.Host)
	}
	dialAddr := net.JoinHostPort(host, fmt.Sprintf("%d", lease.sniPort))
	return transport.DialQUICBackhaul(ctx, dialAddr, l.tlsConfig, lease.accessToken)
}

func (l *listener) runRenewLoop(ctx context.Context) error {
	const wakeThreshold = 10 * time.Second

	for {
		interval, err := l.renewDelay(time.Now())
		if err != nil {
			return err
		}

		// Round(0) strips the monotonic clock reading so that
		// time.Since uses wall-clock time.  The monotonic clock
		// freezes during macOS sleep, so without this the elapsed
		// duration would equal the timer interval, not real time.
		before := time.Now().Round(0)
		if interval > 0 {
			if !utils.SleepOrDone(ctx, interval) {
				return ctx.Err()
			}
		}
		elapsed := time.Since(before)

		// If the wall-clock jump is much larger than expected, the OS
		// likely suspended the process (e.g. macOS lid close).  The
		// server-side lease is almost certainly expired, so skip the
		// normal renew and go straight to re-registration.
		if elapsed > interval+wakeThreshold {
			log.Info().
				Dur("expected", interval).
				Dur("actual", elapsed).
				Str("address", l.identity.Address).
				Msg("system sleep/wake detected; resetting transport and re-registering")
			return errLeaseRefreshRequired
		}

		var retries int
		for {
			err := l.renewLease(ctx)
			if err == nil {
				break
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return err
			}
			if errors.Is(err, errLeaseRefreshRequired) {
				return err
			}
			if isTerminalRelayError(err) {
				return err
			}

			retries++
			if !l.waitRetry(ctx, "lease renewal", err, retries, 0) {
				return err
			}
		}
	}
}

func (l *listener) renewDelay(now time.Time) (time.Duration, error) {
	lease, ok := l.leaseSnapshot()
	if !ok || lease.accessToken == "" || !now.Before(lease.expiresAt) {
		return 0, errLeaseRefreshRequired
	}

	leaseTTL := l.leaseTTL
	if leaseTTL <= 0 {
		leaseTTL = defaultLeaseTTL
	}
	renewBefore := l.renewBefore
	if renewBefore <= 0 || renewBefore >= leaseTTL {
		renewBefore = leaseTTL / 2
	}
	if renewBefore <= 0 {
		renewBefore = time.Second
	}

	renewAt := lease.expiresAt.Add(-renewBefore)
	if !now.Before(renewAt) {
		return 0, nil
	}
	return renewAt.Sub(now), nil
}

func (l *listener) renewLease(ctx context.Context) error {
	lease, ok := l.leaseSnapshot()
	if !ok || lease.accessToken == "" || !time.Now().Before(lease.expiresAt) {
		return errLeaseRefreshRequired
	}

	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := l.renewRegisteredLease(requestCtx, l.leaseTTL, lease.accessToken)
	if err != nil {
		if errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseNotFound}) {
			return errLeaseRefreshRequired
		}
		return &relayRegistrationError{relayURL: l.relayURL.String(), err: err}
	}

	resp.AccessToken = strings.TrimSpace(resp.AccessToken)
	if resp.AccessToken == "" {
		return errors.New("relay did not return renewed access token")
	}
	multihopAccessToken := resp.AccessToken
	var entrySNIPort int
	if len(lease.hopRoutes) > 0 {
		multihopAccessToken, entrySNIPort, err = l.registerHopRoutes(requestCtx, resp.ExpiresAt, lease.hopRoutes)
		if err != nil {
			return err
		}
	}
	if l.lease == nil {
		return errLeaseRefreshRequired
	}
	_, updated := l.lease.UpdateIf(func(current listenerSnapshot) (listenerSnapshot, bool) {
		if current.accessToken != lease.accessToken {
			return current, false
		}
		next := current
		next.accessToken = resp.AccessToken
		next.expiresAt = resp.ExpiresAt
		next.multihopAccessToken = multihopAccessToken
		if entrySNIPort > 0 {
			next.sniPort = entrySNIPort
		}
		return next, true
	})
	if !updated {
		return errLeaseRefreshRequired
	}
	return nil
}

func (l *listener) registerAndConfigure(ctx context.Context) error {
	if err := l.initHTTPTransport(ctx); err != nil {
		return &relayRegistrationError{relayURL: l.relayURL.String(), err: err}
	}

	resp, hopRoutes, publicHostname, routeHostname, err := l.registerLease(ctx, l.leaseTTL, l.udpEnabled, l.tcpEnabled)
	if err != nil {
		return &relayRegistrationError{relayURL: l.relayURL.String(), err: err}
	}
	resp.AccessToken = strings.TrimSpace(resp.AccessToken)
	if resp.AccessToken == "" {
		return errors.New("relay did not return access token")
	}
	if l.udpEnabled && !resp.UDPEnabled {
		_ = l.unregisterLease(context.Background(), resp.AccessToken, hopRoutes)
		return &types.APIRequestError{
			Code:    types.APIErrorCodeFeatureUnavailable,
			Message: "relay did not enable required udp support",
		}
	}
	if l.udpEnabled && resp.SNIPort <= 0 {
		_ = l.unregisterLease(context.Background(), resp.AccessToken, hopRoutes)
		return errors.New("relay did not return sni port for udp transport")
	}
	multihopAccessToken := resp.AccessToken
	sniPort := resp.SNIPort
	if len(hopRoutes) > 0 {
		multihopAccessToken, sniPort, err = l.registerHopRoutes(ctx, resp.ExpiresAt, hopRoutes)
		if err != nil {
			_ = l.unregisterLease(context.Background(), resp.AccessToken, hopRoutes)
			return err
		}
	}
	keylessURL := l.relayURL.String()
	if multiHop := l.route.MultiHop(); len(multiHop) > 0 {
		keylessURL = multiHop[0]
	}
	publicURLBase := l.relayURL
	if normalizedKeylessURL, err := utils.NormalizeRelayURL(keylessURL); err == nil {
		if parsedKeylessURL, parseErr := url.Parse(normalizedKeylessURL); parseErr == nil {
			publicURLBase = parsedKeylessURL
		}
	}
	echKeys, echConfigList, err := l.tenantECHMaterials(publicHostname, routeHostname)
	if err != nil {
		_ = l.unregisterLease(context.Background(), resp.AccessToken, hopRoutes)
		return err
	}

	tlsConf, tenantTLSCloser, err := keyless.BuildClientTLSConfig(keylessURL, publicHostname, echKeys, func() http.Header {
		headers := http.Header{}
		accessToken := multihopAccessToken
		if snapshot, ok := l.leaseSnapshot(); ok && snapshot.multihopAccessToken != "" {
			accessToken = snapshot.multihopAccessToken
		}
		headers.Set(types.HeaderAccessToken, accessToken)
		return headers
	})
	if err != nil {
		_ = l.unregisterLease(context.Background(), resp.AccessToken, hopRoutes)
		if tenantTLSCloser != nil {
			_ = tenantTLSCloser.Close()
		}
		return err
	}

	if ctx.Err() != nil {
		_ = l.unregisterLease(context.Background(), resp.AccessToken, hopRoutes)
		if tenantTLSCloser != nil {
			_ = tenantTLSCloser.Close()
		}
		return ctx.Err()
	}
	next := listenerSnapshot{
		hostname:            publicHostname,
		echConfigList:       echConfigList,
		udpAddr:             resp.UDPAddr,
		accessToken:         resp.AccessToken,
		expiresAt:           resp.ExpiresAt,
		sniPort:             sniPort,
		publicURLBase:       publicURLBase,
		tlsConfig:           tlsConf,
		tlsCloser:           tenantTLSCloser,
		multihopAccessToken: multihopAccessToken,
		hopRoutes:           hopRoutes,
	}
	oldLease := l.lease.Swap(next)
	if oldLease.tlsCloser != nil {
		_ = oldLease.tlsCloser.Close()
	}
	if l.udpEnabled && l.datagram != nil {
		l.datagram.Clear("lease updated")
	}
	entryURL := l.route.ListenerRelayURL()
	if l.relaySet != nil && entryURL != "" {
		l.relaySet.ConfirmRelayURL(entryURL)
	}
	if len(echConfigList) > 0 {
		log.Info().
			Str("address", l.identity.Address).
			Str("route_hostname", routeHostname).
			Str("ech_config_list_base64", base64.StdEncoding.EncodeToString(echConfigList)).
			Msg("tenant ech config ready")
	}
	return nil
}

func (l *listener) tenantECHMaterials(publicHostname, routeHostname string) ([]tls.EncryptedClientHelloKey, []byte, error) {
	if routeHostname == "" {
		return nil, nil, nil
	}
	echSeed, err := identity.DeriveToken(l.identity, "tenant-ech", publicHostname, routeHostname)
	if err != nil {
		return nil, nil, fmt.Errorf("derive tenant ech seed: %w", err)
	}
	echKeys, echConfigList, err := keyless.EncryptedClientHelloMaterials(echSeed, routeHostname)
	if err != nil {
		return nil, nil, fmt.Errorf("prepare tenant ech materials: %w", err)
	}
	return echKeys, echConfigList, nil
}

func (l *listener) waitRetry(ctx context.Context, operation string, err error, retries, reverseSessionSlot int) bool {
	if ctx.Err() != nil {
		return false
	}

	relayURL := ""
	if l.relayURL != nil {
		relayURL = l.relayURL.String()
	}
	logger := log.With().
		Str("relay_url", relayURL).
		Str("operation", operation).
		Str("address", l.identity.Address).
		Logger()
	if reverseSessionSlot > 0 {
		logger = logger.With().Int("reverse_session_slot", reverseSessionSlot).Logger()
	}

	if l.retryCount > 0 && retries > l.retryCount {
		entryURL := l.route.ListenerRelayURL()
		if l.relaySet != nil && entryURL != "" {
			l.relaySet.UnconfirmRelayURL(entryURL)
			l.relaySet.RecordActiveFailure(entryURL, 1)
			l.relaySet.DropRelayURLFromActivePool(entryURL)
		}
		logger.Error().
			Err(err).
			Int("retry_count", l.retryCount).
			Msg("retry budget exhausted")
		return false
	}

	logger.Debug().
		Err(err).
		Int("retry_attempt", retries).
		Int("retry_count", l.retryCount).
		Dur("retry_wait", l.retryWait).
		Msg("operation failed; retrying")

	return utils.SleepOrDone(ctx, l.retryWait)
}

type bufferedConn struct {
	net.Conn
	reader *bytes.Reader
}

func wrapBufferedConn(conn net.Conn, reader *bufio.Reader) net.Conn {
	if reader == nil || reader.Buffered() == 0 {
		return conn
	}
	buf := make([]byte, reader.Buffered())
	if _, err := io.ReadFull(reader, buf); err != nil {
		return conn
	}
	return &bufferedConn{Conn: conn, reader: bytes.NewReader(buf)}
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if c.reader != nil && c.reader.Len() > 0 {
		return c.reader.Read(p)
	}
	return c.Conn.Read(p)
}
