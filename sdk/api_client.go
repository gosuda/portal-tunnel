package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultDialTimeout         = 5 * time.Second
	defaultRequestTimeout      = 15 * time.Second
	defaultHandshakeTimeout    = 15 * time.Second
	defaultLeaseTTL            = 30 * time.Second
	defaultRenewBefore         = 30 * time.Second
	defaultReadyTarget         = 2
	defaultRetryWait           = 3 * time.Second
	defaultHTTPShutdownTimeout = 5 * time.Second
)

var errRelayIncompatible = errors.New("relay is incompatible")

// resetTransport tears down the cached HTTP client and TLS config so the next
// API call creates fresh TCP connections. Call this after detecting a system
// sleep/wake cycle where pooled connections are almost certainly dead.
func (l *listener) resetTransport() {
	if l.httpClient != nil {
		if transport, ok := l.httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
	l.httpClient = nil
	l.tlsConfig = nil
}

func (l *listener) initHTTPTransport(ctx context.Context) error {
	if l.httpClient != nil {
		return nil
	}

	bootstrapCtx, cancel := context.WithTimeout(ctx, defaultDialTimeout+defaultHandshakeTimeout)
	defer cancel()

	tlsConfig, httpClient, err := utils.NewHTTPTLSClient(bootstrapCtx, l.relayURL, l.requestTimeout)
	if err != nil {
		return err
	}

	var domainResp types.DomainResponse
	if err := utils.HTTPDoAPIPath(ctx, httpClient, l.relayURL, http.MethodGet, types.PathSDKDomain, nil, nil, &domainResp); err != nil {
		if transport, ok := httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
		err = fmt.Errorf("check relay compatibility: %w", err)
		var netErr net.Error
		var apiErr *types.APIRequestError
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) {
			return err
		}
		if errors.As(err, &apiErr) && apiErr.StatusCode >= 500 {
			return err
		}
		return fmt.Errorf("%w: %w", errRelayIncompatible, err)
	}
	protocolVersion := strings.TrimSpace(domainResp.ProtocolVersion)
	if protocolVersion != types.SDKVersion {
		if transport, ok := httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
		return fmt.Errorf("%w: relay sdk protocol version mismatch: relay=%q client=%q", errRelayIncompatible, protocolVersion, types.SDKVersion)
	}

	l.httpClient = httpClient
	l.tlsConfig = tlsConfig
	return nil
}

func (l *listener) registerLease(ctx context.Context, ttl time.Duration, udpEnabled, tcpEnabled bool) (types.RegisterResponse, error) {
	var challenge types.RegisterChallengeResponse
	if err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{
		Identity:   l.identity,
		Metadata:   l.metadata,
		TTL:        int(ttl / time.Second),
		UDPEnabled: udpEnabled,
		TCPEnabled: tcpEnabled,
	}, nil, &challenge); err != nil {
		return types.RegisterResponse{}, err
	}

	signature, err := utils.SignEthereumPersonalMessage(challenge.SIWEMessage, l.identity.PrivateKey)
	if err != nil {
		return types.RegisterResponse{}, err
	}

	var resp types.RegisterResponse
	if err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{
		ChallengeID:   challenge.ChallengeID,
		SIWEMessage:   challenge.SIWEMessage,
		SIWESignature: signature,
		ReportedIP:    utils.ResolvePublicIP(ctx),
	}, nil, &resp); err != nil {
		return types.RegisterResponse{}, err
	}
	return resp, nil
}

func (l *listener) renewRegisteredLease(ctx context.Context, ttl time.Duration, accessToken string) (types.RenewResponse, error) {
	var resp types.RenewResponse
	if err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKRenew, types.RenewRequest{
		AccessToken: accessToken,
		TTL:         int(ttl / time.Second),
		ReportedIP:  utils.ResolvePublicIP(ctx),
	}, nil, &resp); err != nil {
		return types.RenewResponse{}, err
	}
	return resp, nil
}

func (l *listener) unregisterLease(ctx context.Context, accessToken string) error {
	return utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKUnregister, types.UnregisterRequest{
		AccessToken: accessToken,
	}, nil, nil)
}
