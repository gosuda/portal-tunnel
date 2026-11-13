package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/certmonitor"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/localtls"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

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

func (l *listener) runRenewLoop(ctx context.Context) error {
	const wakeThreshold = 10 * time.Second

	for {
		interval, err := l.renewDelay(time.Now())
		if err != nil {
			return err
		}

		elapsed, err := sleepUntilRenew(ctx, interval)
		if err != nil {
			return err
		}

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

func sleepUntilRenew(ctx context.Context, interval time.Duration) (time.Duration, error) {
	before := time.Now().Round(0)
	if interval > 0 {
		if !utils.SleepOrDone(ctx, interval) {
			return 0, ctx.Err()
		}
	}
	return time.Since(before), nil
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
	resp, err := l.api.renew(requestCtx, types.RenewRequest{
		AccessToken: lease.accessToken,
		TTL:         int(defaultLeaseTTL / time.Second),
		ReportedIP:  utils.ResolvePublicIP(requestCtx),
		Metadata:    l.metadataSnapshot(),
		RepinsChain: true,
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
