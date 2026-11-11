package sdk

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

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
