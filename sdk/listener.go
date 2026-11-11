package sdk

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/cache"
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
	CertificateMonitor *keyless.MonitorConfig
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
	state     RelayState
	failure   RelayFailure
	approval  RelayApproval
	err       error
	publicURL string
	legacyURL string
	aliasURL  string
	udpAddr   string
	tcpAddr   string
	version   string
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
	certificateMonitor *keyless.MonitorConfig
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
	if l.readySessions.Load() > 0 && l.publicURLForLease(lease) != "" {
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
		publicURL: l.publicURLForLease(lease),
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
