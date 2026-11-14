package sdk

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/portal/certmonitor"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/localtls"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errDatagramFrameTargetsStaleAddress           = errors.New("datagram frame targets stale address")
	errBrowserSDKCannotVerifyResolvedAddresses    = errors.New("browser SDK cannot verify resolved addresses for relay-selected gateways; use a direct relay with overlay disabled")
	errRelayReturnedOverlayReverseEndpointBut     = errors.New("relay returned an overlay reverse endpoint but overlay is disabled")
	errRelayReturnedGatewayMetadataDirectReverse  = errors.New("relay returned gateway metadata for a direct reverse endpoint")
	errRelayReturnedOverlayReverseEndpointWithout = errors.New("relay returned an overlay reverse endpoint without a signed gateway descriptor")
	errOverlayGatewayDescriptorDoesNotCover       = errors.New("overlay gateway descriptor does not cover the reverse endpoint expiry")
	errOverlayGatewayDescriptorHasNoDestination   = errors.New("overlay gateway descriptor has no destination")
	errInvalidOverlayReverseEndpointURL           = errors.New("invalid overlay reverse endpoint URL")
	errOverlayReverseEndpointDoesNotMatch         = errors.New("overlay reverse endpoint does not match the signed gateway URL")
	errReverseCapabilityIsNotAvailable            = errors.New("reverse capability is not available")
	errRelayTLSConfigIsUnavailable                = errors.New("relay tls config is unavailable")
	errReverseEndpointHostnameIsUnavailable       = errors.New("reverse endpoint hostname is unavailable")
	errAccessTokenIsNotAvailable                  = errors.New("access token is not available")
	errRelayAuthorityIsUnavailable                = errors.New("relay authority is unavailable")
)

const (
	defaultDialTimeout      = 15 * time.Second
	defaultHandshakeTimeout = 30 * time.Second
	defaultLeaseTTL         = 2 * time.Minute
	defaultRenewBefore      = 30 * time.Second
	defaultReadyTarget      = 8
	defaultRetryWait        = 3 * time.Second

	defaultChainCheckInterval = time.Hour

	maxAdmitting = 64
)

type listenerConfig struct {
	CertificateMonitor *certmonitor.MonitorConfig
	TLSStateDir        string
	TLSRequireLocal    bool
	TLSCertFile        string
	TLSKeyFile         string
	Cache              *cache.Source
	Identity           types.Identity
	Overlay            bool
	UDPEnabled         bool
	TCPEnabled         bool
	BanMITM            bool
	Metadata           types.LeaseMetadata
	StartedAt          time.Time
}

type listenerStatus struct {
	state          RelayState
	failure        RelayFailure
	approval       RelayApproval
	certificateErr error
	err            error
	publicURL      string
	legacyURL      string
	aliasURL       string
	udpAddr        string
	tcpAddr        string
	version        string
}

var errLeaseRefreshRequired = errors.New("lease refresh required")

func isTerminalRelayError(err error) bool {
	if apiErr, ok := errors.AsType[*types.APIRequestError](err); ok && apiErr.IsRateLimited() {
		return false
	}
	if errors.Is(err, errRelayIncompatible) || errors.Is(err, localtls.ErrLocalCertificate) {
		return true
	}
	if errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeFeatureUnavailable}) ||
		errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeTransportMismatch}) ||
		errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeUDPDisabled}) ||
		errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeTCPPortDisabled}) ||
		errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeHostnameConflict}) {
		return true
	}
	var apiErr *types.APIRequestError
	return errors.As(err, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500
}

func relayApprovalFromError(err error) RelayApproval {
	switch {
	case errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseRejected}):
		return RelayApprovalPending
	case errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseDenied}):
		return RelayApprovalRefused
	default:
		return ""
	}
}

func staleLeaseError(err error) bool {
	return errors.Is(err, errLeaseRefreshRequired) ||
		errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseNotFound}) ||
		errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeUnauthorized})
}

func (l *listener) closeForTerminalRelayError(err error) bool {
	if !isTerminalRelayError(err) {
		return false
	}
	log.Error().
		Err(err).
		Str("relay_url", l.api.relayURL.String()).
		Str("address", l.identity.Address).
		Msg("relay operation failed permanently; closing listener")
	l.report(listenerStatus{state: RelayFailed, failure: RelayFailureTerminal, err: err})
	_ = l.Close()
	return true
}

type listener struct {
	certificateMonitor *certmonitor.MonitorConfig
	tlsStateDir        string
	tlsRequireLocal    bool
	tlsCertFile        string
	tlsKeyFile         string
	cancel             context.CancelFunc
	doneCh             <-chan struct{}
	closeOnce          sync.Once

	startedAt time.Time

	metadataMu        sync.RWMutex
	metadata          types.LeaseMetadata
	identity          types.Identity
	overlay           bool
	warnOverlayDirect sync.Once
	udpEnabled        bool
	tcpEnabled        bool
	cache             *cache.Source

	accepted      chan net.Conn
	admitting     chan struct{}
	datagram      *transport.DatagramSession
	mitmManager   *mitmManager
	statusUpdates chan listenerStatus
	readySessions atomic.Int32
	http2Enabled  atomic.Bool

	api           *apiClient
	reverseTLSMu  sync.Mutex
	reverseTLSURL string
	reverseTLS    *tls.Config
	reverseMu     sync.Mutex

	lease *utils.Snapshot[listenerSnapshot]
}

func newListener(ctx context.Context, relayURL string, cfg listenerConfig) (*listener, error) {
	listenerCtx, cancel := context.WithCancel(ctx)

	entryRelayURL, err := utils.NormalizeRelayURL(relayURL)
	if err != nil {
		cancel()
		return nil, err
	}
	relayurl, err := url.Parse(entryRelayURL)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("parse relay url: %w", err)
	}
	l := &listener{
		cancel:             cancel,
		doneCh:             listenerCtx.Done(),
		metadata:           cfg.Metadata.Copy(),
		identity:           cfg.Identity,
		overlay:            cfg.Overlay,
		statusUpdates:      make(chan listenerStatus),
		udpEnabled:         cfg.UDPEnabled,
		tcpEnabled:         cfg.TCPEnabled,
		cache:              cfg.Cache,
		tlsCertFile:        cfg.TLSCertFile,
		tlsKeyFile:         cfg.TLSKeyFile,
		tlsStateDir:        cfg.TLSStateDir,
		tlsRequireLocal:    cfg.TLSRequireLocal,
		certificateMonitor: cfg.CertificateMonitor,
		api:                &apiClient{relayURL: relayurl},
		lease:              utils.NewSnapshot(listenerSnapshot{}),
		startedAt:          cfg.StartedAt,
	}
	l.mitmManager = newMITMManager(l, cfg.BanMITM)
	l.accepted = make(chan net.Conn, defaultReadyTarget*2)
	l.admitting = make(chan struct{}, maxAdmitting)
	if l.udpEnabled {
		l.datagram = transport.NewDatagramSession(256, false)
	}
	go l.run(listenerCtx)
	return l, nil
}

func (l *listener) metadataSnapshot() types.LeaseMetadata {
	if l == nil {
		return types.LeaseMetadata{}
	}
	l.metadataMu.RLock()
	defer l.metadataMu.RUnlock()
	return l.metadata.Copy()
}

func (l *listener) report(status listenerStatus) {
	if l == nil || l.statusUpdates == nil {
		return
	}
	select {
	case <-l.doneCh:
	case l.statusUpdates <- status:
	}
}

func (l *listener) UpdateMetadata(metadata types.LeaseMetadata) {
	if l == nil {
		return
	}
	l.metadataMu.Lock()
	l.metadata = metadata.Copy()
	l.metadataMu.Unlock()
}

func (l *listener) reportStreamReady() {
	l.readySessions.Add(1)
	l.setApproval("")
	l.reportAvailable()
	l.logRawEndpoints()
}

func (l *listener) reportRefusal(err error) {
	approval := relayApprovalFromError(err)
	if approval == "" || !l.setApproval(approval) {
		return
	}
	l.reportAvailable()
}

func (l *listener) setApproval(approval RelayApproval) bool {
	_, changed := l.lease.UpdateIf(func(current listenerSnapshot) (listenerSnapshot, bool) {
		if approval != "" && l.readySessions.Load() > 0 {
			return current, false
		}
		if current.accessToken == "" || current.approval == approval {
			return current, false
		}
		current.approval = approval
		return current, true
	})
	return changed
}

func (l *listener) logRawEndpoints() {
	lease, first := l.lease.UpdateIf(func(current listenerSnapshot) (listenerSnapshot, bool) {
		if current.endpointsLogged || !current.hasRawEndpoint() {
			return current, false
		}
		current.endpointsLogged = true
		return current, true
	})
	if !first {
		return
	}
	event := log.Info().Str("address", l.identity.Address)
	if lease.udpAddr != "" {
		event = event.Str("udp_addr", lease.udpAddr)
	}
	if lease.tcpAddr != "" {
		event = event.Str("tcp_addr", lease.tcpAddr)
	}
	event.Msg("raw transport endpoints allocated")
}

func (l *listener) reportStreamClosed() {
	for {
		current := l.readySessions.Load()
		if current <= 0 {
			return
		}
		if l.readySessions.CompareAndSwap(current, current-1) {
			l.reportAvailable()
			return
		}
	}
}

func (l *listener) reportAvailable() {
	lease, ok := l.leaseSnapshot()
	if !ok {
		return
	}
	state := RelayConnecting
	if l.readySessions.Load() > 0 && lease.hostname != "" {
		state = RelayReady
	}
	if state == RelayConnecting && lease.approval != "" {
		l.report(listenerStatus{state: state, approval: lease.approval, version: l.api.relayReleaseVersion()})
		return
	}
	udpAddr := ""
	if l.datagram != nil && l.datagram.Connected() {
		udpAddr = lease.udpAddr
	}
	l.report(listenerStatus{
		state:     state,
		publicURL: l.leaseURL(lease.hostname),
		legacyURL: l.leaseURL(lease.legacyHostname),
		aliasURL:  l.aliasURLForLease(lease),
		udpAddr:   udpAddr,
		tcpAddr:   lease.tcpAddr,
		version:   l.api.relayReleaseVersion(),
	})
}

func (l *listener) run(ctx context.Context) {
	var retries int
	for {
		l.report(listenerStatus{state: RelayConnecting})
		err := l.registerAndConfigure(ctx)
		if err != nil {
			var stop bool
			retries, stop = l.settlelistenerRegistration(ctx, err, retries)
			if stop {
				return
			}
			continue
		}
		retries = 0
		lease, ok := l.leaseSnapshot()
		if !ok || (l.publicURLForLease(lease) == "" && !lease.hasRawEndpoint()) {
			log.Info().Str("address", l.identity.Address).Msg("relay listener registered")
		}
		err = l.runLease(ctx)
		if l.settlelistenerLease(err) {
			continue
		}
		return
	}
}

func (l *listener) settlelistenerRegistration(ctx context.Context, err error, retries int) (int, bool) {
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return retries, true
	}
	if l.closeForTerminalRelayError(err) {
		return retries, true
	}
	retries++
	if !l.waitRetry(ctx, "lease registration", err, retries, 0) {
		if ctx.Err() == nil {
			l.report(listenerStatus{state: RelayFailed, failure: RelayFailureRuntime, err: err})
		}
		_ = l.Close()
		return retries, true
	}
	return retries, false
}

func (l *listener) settlelistenerLease(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return false
	}
	if l.closeForTerminalRelayError(err) {
		return false
	}
	if errors.Is(err, errLeaseRefreshRequired) {
		l.resetForLeaseRefresh(err)
		return true
	}
	relayURL := l.api.relayURL.String()
	log.Error().
		Err(err).
		Str("relay_url", relayURL).
		Str("address", l.identity.Address).
		Msg("listener connection retry budget exhausted; closing listener")
	l.report(listenerStatus{state: RelayFailed, failure: RelayFailureRuntime, err: err})
	_ = l.Close()
	return false
}

func (l *listener) resetForLeaseRefresh(err error) {
	lease := l.clearLease("lease refresh required")
	if lease != nil && lease.tenantTLS != nil {
		_ = lease.tenantTLS.Close()
		lease.certificateObserver.Close()
	}
	l.api.resetTransport()
	l.clearReverseTLSCache()
	relayURL := l.api.relayURL.String()
	log.Debug().
		Err(err).
		Str("relay_url", relayURL).
		Str("address", l.identity.Address).
		Msg("lease refresh required; re-registering")
}

func (l *listener) Close() error {
	var closeErr error
	l.closeOnce.Do(func() {
		closeErr = l.runCloseCleanup()
	})
	return closeErr
}

func (l *listener) runCloseCleanup() error {
	if l.cancel != nil {
		l.cancel()
	}
	lease := l.clearLease("")
	l.drainCloseAccepted()
	if l.datagram != nil {
		l.datagram.Close("listener closed")
	}
	unregisterErr := l.unregisterCloseLease(lease)
	var tenantErr error
	if lease != nil && lease.tenantTLS != nil {
		tenantErr = lease.tenantTLS.Close()
		lease.certificateObserver.Close()
	}
	if l.api != nil {
		l.api.resetTransport()
	}
	return errors.Join(unregisterErr, tenantErr)
}

func (l *listener) drainCloseAccepted() {
	for {
		select {
		case conn := <-l.accepted:
			if conn != nil {
				_ = conn.Close()
			}
		default:
			return
		}
	}
}

func (l *listener) unregisterCloseLease(lease *listenerSnapshot) error {
	if lease != nil && lease.hostname != "" && l.identity.Key() != "" && lease.accessToken != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return l.api.unregister(ctx, lease.accessToken)
	}
	return nil
}

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
			// Registration has no local certificate report. Publish already
			// usable material now; pending issuance will signal its own change.
			if endpoint.local.Ready() {
				renew <- struct{}{}
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				l.runCertificateStatus(leaseCtx, endpoint.local, renew)
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

// runCertificateStatus publishes installation and expiry without waiting for
// network renewal, then asks the token-owning renewal loop to report remotely.
func (l *listener) runCertificateStatus(ctx context.Context, client *localtls.Client, renew chan<- struct{}) {
	for {
		var expiry <-chan time.Time
		var timer *time.Timer
		if until := time.Until(client.CertificateExpiry()); until > 0 {
			timer = time.NewTimer(until)
			expiry = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-client.CertificateChanges():
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

func (l *listener) runDatagramLoop(ctx context.Context) error {
	if l.datagram == nil {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			l.datagram.Clear("lease stopped")
			return nil
		default:
		}

		conn, err := l.openQUICBackhaulSession(ctx)
		if err != nil {
			done, dialErr := l.runDatagramLoopDialFailed(ctx, err)
			if done {
				return dialErr
			}
			continue
		}

		if done, serveErr := l.runDatagramLoopServeSession(ctx, conn); done {
			return serveErr
		}
	}
}

func (l *listener) runDatagramLoopDialFailed(ctx context.Context, err error) (bool, error) {
	if staleLeaseError(err) {
		l.datagram.Clear("lease refresh required")
		return true, errLeaseRefreshRequired
	}
	log.Info().
		Err(err).
		Str("component", "sdk-quic-backhaul").
		Str("address", l.identity.Address).
		Msg("quic backhaul unavailable; retrying")
	if !utils.SleepOrDone(ctx, 2*time.Second) {
		l.datagram.Clear("lease stopped")
		return true, nil
	}
	return false, nil
}

func (l *listener) runDatagramLoopServeSession(ctx context.Context, conn *quic.Conn) (bool, error) {
	log.Info().
		Str("component", "sdk-quic-backhaul").
		Str("address", l.identity.Address).
		Str("remote_addr", conn.RemoteAddr().String()).
		Msg("quic backhaul connected")

	recvDone, done, err := l.bindBackhaulSession(ctx, conn)
	if done {
		return true, err
	}
	if recvDone == nil {
		return false, nil
	}
	l.reportAvailable()

	if done := l.awaitBackhaulResult(ctx, recvDone); done {
		return true, nil
	}
	return false, nil
}

func (l *listener) bindBackhaulSession(ctx context.Context, conn *quic.Conn) (<-chan error, bool, error) {
	recvDone, err := l.datagram.Bind(conn)
	if err == nil {
		return recvDone, false, nil
	}
	if ctx.Err() != nil {
		return nil, true, ctx.Err()
	}
	log.Info().
		Err(err).
		Str("component", "sdk-quic-backhaul").
		Str("address", l.identity.Address).
		Msg("quic backhaul did not bind cleanly; retrying")
	if !utils.SleepOrDone(ctx, time.Second) {
		return nil, true, nil
	}
	return nil, false, nil
}

func (l *listener) awaitBackhaulResult(ctx context.Context, recvDone <-chan error) bool {
	select {
	case <-ctx.Done():
		l.datagram.Clear("lease stopped")
		return true
	case err := <-recvDone:
		if err != nil {
			log.Info().
				Err(err).
				Str("component", "sdk-quic-backhaul").
				Str("address", l.identity.Address).
				Msg("quic backhaul disconnected; waiting to reconnect")
			l.reportAvailable()
		}
	}

	return !utils.SleepOrDone(ctx, time.Second)
}

func (l *listener) openQUICBackhaulSession(ctx context.Context) (*quic.Conn, error) {
	lease, ok := l.leaseSnapshot()
	if !ok || lease.accessToken == "" {
		return nil, errAccessTokenIsNotAvailable
	}
	tlsCfg := l.api.tlsConfigClone()
	if tlsCfg == nil {
		return nil, errRelayTLSConfigIsUnavailable
	}
	dialAddr := relayAuthority(l.api.relayURL, "")
	if dialAddr == "" {
		return nil, errRelayAuthorityIsUnavailable
	}
	return transport.DialQUICBackhaul(ctx, dialAddr, tlsCfg, lease.accessToken)
}

func (l *listener) runRenewLoop(ctx context.Context, renew <-chan struct{}) error {
	const wakeThreshold = 10 * time.Second

	for {
		interval, err := l.renewDelay(time.Now())
		if err != nil {
			return err
		}

		before := time.Now().Round(0)
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-renew:
		case <-timer.C:
		}
		timer.Stop()
		elapsed := time.Since(before)

		if elapsed > interval+wakeThreshold {
			log.Info().
				Dur("expected", interval).
				Dur("actual", elapsed).
				Str("address", l.identity.Address).
				Msg("system sleep/wake detected; resetting transport and re-registering")
			return errLeaseRefreshRequired
		}

		if err := l.renewLeaseWithRetry(ctx); err != nil {
			return err
		}
		l.reportAvailable()
	}
}

func (l *listener) renewLeaseWithRetry(ctx context.Context) error {
	var retries int
	for {
		err := l.renewLease(ctx)
		if err == nil {
			return nil
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

func (l *listener) renewDelay(now time.Time) (time.Duration, error) {
	lease, ok := l.leaseSnapshot()
	if !ok || lease.accessToken == "" || !now.Before(lease.expiresAt) {
		return 0, errLeaseRefreshRequired
	}

	renewAt := lease.expiresAt.Add(-defaultRenewBefore)
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

	resp, err := l.requestLeaseRenewal(requestCtx, lease)
	if err != nil {
		return err
	}

	if err := l.validateReverseEndpointTransport(resp.ReverseEndpoint); err != nil {
		return err
	}
	if l.lease == nil {
		return errLeaseRefreshRequired
	}
	return l.applyRenewedLease(ctx, lease, resp)
}

func (l *listener) requestLeaseRenewal(requestCtx context.Context, lease listenerSnapshot) (types.RenewResponse, error) {
	var localTLSNotAfter time.Time
	if endpoint, ok := lease.tenantTLS.(*namespaceTLS); ok && endpoint.local.Ready() {
		localTLSNotAfter = endpoint.local.CertificateExpiry()
	}
	resp, err := l.api.renew(requestCtx, types.RenewRequest{
		LocalTLSNotAfter: localTLSNotAfter,
		AccessToken:      lease.accessToken,
		TTL:              int(defaultLeaseTTL / time.Second),
		ReportedIP:       utils.ResolvePublicIP(requestCtx),
		Metadata:         l.metadataSnapshot(),
		RepinsChain:      true,
	})
	if err != nil {
		if staleLeaseError(err) {
			return types.RenewResponse{}, errLeaseRefreshRequired
		}
		return types.RenewResponse{}, err
	}
	return resp, nil
}

func (l *listener) applyRenewedLease(ctx context.Context, lease listenerSnapshot, resp types.RenewResponse) error {
	_, updated := l.lease.UpdateIf(func(current listenerSnapshot) (listenerSnapshot, bool) {
		if current.accessToken != lease.accessToken {
			return current, false
		}
		next := current
		next.accessToken = resp.AccessToken
		next.reverse = resp.ReverseEndpoint
		next.expiresAt = resp.ExpiresAt
		return next, true
	})
	if !updated {
		return errLeaseRefreshRequired
	}
	if lease.tenantTLS != nil {
		lease.tenantTLS.SetAccessToken(resp.AccessToken)
		if !time.Now().Before(lease.chainCheckedAt.Add(defaultChainCheckInterval)) && l.refreshTenantChain(ctx, lease.tenantTLS) {
			checkedAt := time.Now()
			_, _ = l.lease.UpdateIf(func(current listenerSnapshot) (listenerSnapshot, bool) {
				if current.tenantTLS != lease.tenantTLS {
					return current, false
				}
				current.chainCheckedAt = checkedAt
				return current, true
			})
		}
	}
	return nil
}

func (l *listener) refreshTenantChain(ctx context.Context, tenantTLS tenantTLSClient) bool {
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	changed, err := tenantTLS.RefreshChain(checkCtx)
	switch {
	case err != nil:
		if ctx.Err() == nil {
			log.Warn().
				Err(err).
				Str("relay_url", l.api.relayURL.String()).
				Str("address", l.identity.Address).
				Msg("tenant certificate check failed; keeping the pinned chain")
		}
		return false
	case changed:
		log.Info().
			Str("relay_url", l.api.relayURL.String()).
			Str("address", l.identity.Address).
			Msg("tenant certificate renewed; presenting the new chain")
	}
	return true
}

func (l *listener) registerAndConfigure(ctx context.Context) error {
	registerReq := types.RegisterChallengeRequest{
		AllowCanonicalFallback: true,
		Identity:               l.identity,
		Metadata:               l.metadataSnapshot(),
		Overlay:                l.overlay,
		TTL:                    int(defaultLeaseTTL / time.Second),
		UDPEnabled:             l.udpEnabled,
		TCPEnabled:             l.tcpEnabled,
		StartedAt:              l.startedAt,
	}
	if l.tlsStateDir != "" || l.tlsCertFile != "" {
		registerReq.Namespace = types.LocalTLSNamespaceV1
	}
	l.cache.ConfigureRegistration(&registerReq)
	resp, err := l.api.register(ctx, registerReq, utils.ResolvePublicIP(ctx))
	if err != nil {
		return err
	}
	if resp.Namespace != types.LocalTLSNamespaceV1 && (l.tlsRequireLocal || l.tlsCertFile != "") {
		_ = l.api.unregister(context.Background(), resp.AccessToken)
		return fmt.Errorf("%w: relay does not support the required Local TLS namespace", errRelayIncompatible)
	}
	if err := l.confirmNewRegistration(resp); err != nil {
		return err
	}
	var observer *certmonitor.CertificateObserver
	if l.certificateMonitor != nil {
		observer, err = certmonitor.StartCertificateObserver(resp.CanonicalHostname, *l.certificateMonitor)
		if err != nil {
			_ = l.api.unregister(context.Background(), resp.AccessToken)
			return err
		}
	}
	tenantTLS, err := l.dialRegistrationTLS(ctx, resp, observer)
	if err != nil {
		observer.Close()
		return err
	}
	return l.storeRegistrationLease(ctx, resp, tenantTLS, observer)
}

func (l *listener) confirmNewRegistration(resp types.RegisterResponse) error {
	if err := l.validateReverseEndpointTransport(resp.ReverseEndpoint); err != nil {
		_ = l.api.unregister(context.Background(), resp.AccessToken)
		return err
	}
	if l.udpEnabled && !resp.UDPEnabled {
		_ = l.api.unregister(context.Background(), resp.AccessToken)
		return &types.APIRequestError{
			Code:    types.APIErrorCodeFeatureUnavailable,
			Message: "relay did not enable required udp support",
		}
	}
	return nil
}

func (l *listener) dialRegistrationTLS(ctx context.Context, resp types.RegisterResponse, observer *certmonitor.CertificateObserver) (tenantTLSClient, error) {
	legacyHostname := resp.CanonicalHostname
	if resp.Namespace == types.LocalTLSNamespaceV1 {
		legacyHostname = resp.LegacyCanonicalHostname
	}
	legacy, err := keyless.NewClient(ctx, keyless.ClientConfig{
		RelayURL:    l.api.relayURL.String(),
		Hostname:    legacyHostname,
		AccessToken: resp.AccessToken,
	})
	if err != nil {
		_ = l.api.unregister(context.Background(), resp.AccessToken)
		return nil, err
	}
	var tenantTLS tenantTLSClient = legacy
	if resp.Namespace == types.LocalTLSNamespaceV1 {
		l.api.mu.RLock()
		issuanceDisabled := l.api.issuanceDisabled
		l.api.mu.RUnlock()
		local, localErr := localtls.NewClient(ctx, localtls.ClientConfig{
			RelayURL: l.api.relayURL.String(), Hostname: resp.CanonicalHostname,
			AccessToken: resp.AccessToken, CertificateDir: l.tlsStateDir, IssuanceDisabled: issuanceDisabled,
			CertFile: l.tlsCertFile, KeyFile: l.tlsKeyFile,
			InstalledCertificates: observer.Events(),
		})
		if localErr != nil {
			_ = legacy.Close()
			_ = l.api.unregister(context.Background(), resp.AccessToken)
			return nil, localErr
		}
		if l.http2Enabled.Load() {
			local.SetNextProtos([]string{"h2", "http/1.1"})
		}
		tenantTLS = &namespaceTLS{local: local, legacy: legacy, hostname: resp.CanonicalHostname, legacyHostname: legacyHostname, aliasHostname: resp.Hostname}
	}
	if ctx.Err() != nil {
		_ = l.api.unregister(context.Background(), resp.AccessToken)
		_ = tenantTLS.Close()
		return nil, ctx.Err()
	}
	return tenantTLS, nil
}

func (l *listener) storeRegistrationLease(ctx context.Context, resp types.RegisterResponse, tenantTLS tenantTLSClient, observer *certmonitor.CertificateObserver) error {
	next := listenerSnapshot{
		hostname:            resp.CanonicalHostname,
		legacyHostname:      resp.LegacyCanonicalHostname,
		aliasHostname:       resp.Hostname,
		udpAddr:             resp.UDPAddr,
		tcpAddr:             resp.TCPAddr,
		accessToken:         resp.AccessToken,
		reverse:             resp.ReverseEndpoint,
		expiresAt:           resp.ExpiresAt,
		tenantTLS:           tenantTLS,
		certificateObserver: observer,
		chainCheckedAt:      time.Now(),
	}
	oldLease := l.lease.Swap(next)
	if l.http2Enabled.Load() {
		l.enableHTTP2()
	}
	if oldLease.tenantTLS != nil {
		_ = oldLease.tenantTLS.Close()
		oldLease.certificateObserver.Close()
	}
	if err := ctx.Err(); err != nil {
		lease := l.clearLease("registration canceled")
		if lease != nil {
			if lease.accessToken != "" {
				_ = l.api.unregister(context.Background(), lease.accessToken)
			}
			if lease.tenantTLS != nil {
				_ = lease.tenantTLS.Close()
				lease.certificateObserver.Close()
			}
		}
		return err
	}
	if l.udpEnabled && l.datagram != nil {
		l.datagram.Clear("lease updated")
	}
	return nil
}
func (l *listener) waitRetry(ctx context.Context, operation string, err error, retries, reverseSessionSlot int) bool {
	if ctx.Err() != nil {
		return false
	}

	retryWait := defaultRetryWait
	if apiErr, ok := errors.AsType[*types.APIRequestError](err); ok {
		retryWait = max(retryWait, apiErr.RetryAfter)
	}

	if relayApprovalFromError(err) != "" {
		return utils.SleepOrDone(ctx, retryWait)
	}
	relayURL := ""
	if l.api != nil && l.api.relayURL != nil {
		relayURL = l.api.relayURL.String()
	}
	logger := log.With().
		Str("relay_url", relayURL).
		Str("operation", operation).
		Str("address", l.identity.Address).
		Logger()
	if reverseSessionSlot > 0 {
		return waitRetryLogAndSleep(ctx, logger.With().Int("reverse_session_slot", reverseSessionSlot).Logger(), err, retries, retryWait)
	}
	return waitRetryLogAndSleep(ctx, logger, err, retries, retryWait)
}

func waitRetryLogAndSleep(ctx context.Context, logger zerolog.Logger, err error, retries int, retryWait time.Duration) bool {
	if retries == 1 {
		if transport := waitRetryExhaustedTransport(err); transport != "" {
			logger.Warn().
				Err(err).
				Str("transport", transport).
				Dur("retry_wait", retryWait).
				Msg("raw transport port pool exhausted; waiting for a port")
			return utils.SleepOrDone(ctx, retryWait)
		}
		logger.Warn().
			Err(err).
			Dur("retry_wait", retryWait).
			Msg("operation failed; retrying")
		return utils.SleepOrDone(ctx, retryWait)
	}

	logger.Debug().
		Err(err).
		Int("retry_attempt", retries).
		Dur("retry_wait", retryWait).
		Msg("operation failed; retrying")

	return utils.SleepOrDone(ctx, retryWait)
}

func waitRetryExhaustedTransport(err error) string {
	switch {
	case errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeTCPPortExhausted}):
		return "tcp"
	case errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeUDPPortExhausted}):
		return "udp"
	default:
		return ""
	}
}

type bufferedConn struct {
	net.Conn
	reader *bytes.Reader
}

func (c *bufferedConn) ConnectionState() tls.ConnectionState {
	if conn, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return conn.ConnectionState()
	}
	return tls.ConnectionState{}
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

func (c *bufferedConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func (l *listener) reverseTarget() (*url.URL, string, error) {
	lease, ok := l.leaseSnapshot()
	if !ok || lease.reverse.Capability == "" {
		return nil, "", errReverseCapabilityIsNotAvailable
	}
	if !lease.reverse.ExpiresAt.After(time.Now().UTC()) {
		return nil, "", errLeaseRefreshRequired
	}

	if err := l.validateReverseEndpointTransport(lease.reverse); err != nil {
		return nil, "", fmt.Errorf("reverse endpoint is not authorized: %w", err)
	}
	if l.api.tlsConfigClone() == nil {
		return nil, "", errRelayTLSConfigIsUnavailable
	}

	reverseURL, err := url.Parse(lease.reverse.URL)
	if err != nil {
		return nil, "", fmt.Errorf("parse reverse endpoint: %w", err)
	}
	return reverseURL, lease.reverse.Capability, nil
}

func (l *listener) reverseTLSConfig(ctx context.Context, endpoint *url.URL) (*tls.Config, error) {
	if endpoint == nil || endpoint.Hostname() == "" {
		return nil, errReverseEndpointHostnameIsUnavailable
	}

	if l.isAlternateReverseEndpoint(endpoint.String()) {
		if err := validatePublicReverseHostname(endpoint.Hostname()); err != nil {
			return nil, err
		}
	}
	if strings.EqualFold(endpoint.Host, l.api.relayURL.Host) {
		return l.api.tlsConfigClone(), nil
	}
	key := strings.ToLower(endpoint.Scheme + "://" + endpoint.Host)
	l.reverseTLSMu.Lock()
	defer l.reverseTLSMu.Unlock()
	if l.reverseTLS != nil && l.reverseTLSURL == key {
		return l.reverseTLS.Clone(), nil
	}
	tlsConfig, _, transport, err := utils.NewHTTPTLSClient(ctx, endpoint, defaultDialTimeout)
	if err != nil {
		return nil, err
	}
	transport.CloseIdleConnections()
	l.reverseTLSURL = key
	l.reverseTLS = tlsConfig.Clone()
	return tlsConfig, nil
}

func (l *listener) clearReverseTLSCache() {
	l.reverseTLSMu.Lock()
	defer l.reverseTLSMu.Unlock()
	l.reverseTLS = nil
	l.reverseTLSURL = ""
}

func (l *listener) refreshReverseEndpointAfterFailure(ctx context.Context, failedCapability string) error {
	l.reverseMu.Lock()
	defer l.reverseMu.Unlock()
	lease, ok := l.leaseSnapshot()
	if !ok || lease.accessToken == "" || failedCapability == "" {
		return nil
	}
	if lease.reverse.Capability != failedCapability {
		return nil
	}
	endpoint, err := url.Parse(lease.reverse.URL)
	if err != nil || strings.EqualFold(endpoint.Host, l.api.relayURL.Host) {
		return nil
	}
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	next, err := l.api.requestReverseEndpoint(requestCtx, lease.accessToken, lease.reverse.URL, lease.expiresAt)
	if err != nil {
		if staleLeaseError(err) {
			return errLeaseRefreshRequired
		}
		return nil
	}
	if err := l.validateReverseEndpointTransport(next); err != nil {
		log.Debug().
			Err(err).
			Str("relay_url", l.api.relayURL.String()).
			Str("reverse_url", next.URL).
			Msg("relay returned unusable reverse endpoint; keeping current endpoint")
		return nil
	}
	if l.lease == nil {
		return nil
	}
	_, _ = l.lease.UpdateIf(func(current listenerSnapshot) (listenerSnapshot, bool) {
		if current.accessToken != lease.accessToken || current.reverse.Capability != failedCapability {
			return current, false
		}
		current.reverse = next
		return current, true
	})
	return nil
}
