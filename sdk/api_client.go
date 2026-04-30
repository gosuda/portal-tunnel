package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
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

func (l *listener) registerLease(ctx context.Context, ttl time.Duration, udpEnabled, tcpEnabled bool) (types.RegisterResponse, []types.HopRoute, error) {
	var exitHopToken string
	var publicHostname string
	var keylessURL string
	var hopRoutes []types.HopRoute
	if len(l.multiHop) > 0 {
		if len(l.multiHop) < 2 {
			return types.RegisterResponse{}, nil, errors.New("multi-hop requires at least entry and exit relay urls")
		}
		if l.relaySet == nil {
			return types.RegisterResponse{}, nil, errors.New("multi-hop relay set is unavailable")
		}

		now := time.Now().UTC()
		hopPath := make([]types.RelayDescriptor, 0, len(l.multiHop))
		for i, relayURL := range l.multiHop {
			desc, ok := l.relaySet.OverlayRelayDescriptor(relayURL, now)
			if !ok {
				return types.RegisterResponse{}, nil, fmt.Errorf("multi-hop relay %d descriptor is unavailable", i)
			}
			hopPath = append(hopPath, desc)
		}

		var err error
		publicHostname, err = utils.LeaseHostname(l.identity.Name, utils.PortalRootHost(hopPath[0].APIHTTPSAddr))
		if err != nil {
			return types.RegisterResponse{}, nil, err
		}
		keylessURL = hopPath[0].APIHTTPSAddr

		hopRoutes = make([]types.HopRoute, 0, len(hopPath)-1)
		var previousHopToken string
		for i := 0; i < len(hopPath)-1; i++ {
			token, err := l.identity.DeriveToken(
				"hop-token",
				publicHostname,
				strconv.Itoa(i),
				hopPath[i].APIHTTPSAddr,
				hopPath[i+1].APIHTTPSAddr,
			)
			if err != nil {
				return types.RegisterResponse{}, nil, err
			}
			forwardToken := "hpt_" + token
			route := types.HopRoute{
				RelayURL:     hopPath[i].APIHTTPSAddr,
				ForwardRelay: hopPath[i+1],
				ForwardToken: forwardToken,
			}
			if i == 0 {
				route.MatchHostname = publicHostname
				route.Metadata = l.metadata
			} else {
				route.MatchToken = previousHopToken
			}
			hopRoutes = append(hopRoutes, route)
			previousHopToken = forwardToken
		}
		exitHopToken = previousHopToken
	}

	var challenge types.RegisterChallengeResponse
	if err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{
		Identity:   l.identity,
		Metadata:   l.metadata,
		TTL:        int(ttl / time.Second),
		UDPEnabled: udpEnabled,
		TCPEnabled: tcpEnabled,
		HopToken:   exitHopToken,
	}, nil, &challenge); err != nil {
		return types.RegisterResponse{}, nil, err
	}

	signature, err := utils.SignEthereumPersonalMessage(challenge.SIWEMessage, l.identity.PrivateKey)
	if err != nil {
		return types.RegisterResponse{}, nil, err
	}

	var resp types.RegisterResponse
	if err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{
		ChallengeID:   challenge.ChallengeID,
		SIWEMessage:   challenge.SIWEMessage,
		SIWESignature: signature,
		ReportedIP:    utils.ResolvePublicIP(ctx),
	}, nil, &resp); err != nil {
		return types.RegisterResponse{}, nil, err
	}
	if len(hopRoutes) > 0 {
		if err := l.syncHopRoutes(ctx, http.MethodPost, resp.ExpiresAt, hopRoutes); err != nil {
			_ = l.unregisterLease(context.Background(), resp.AccessToken, hopRoutes)
			return types.RegisterResponse{}, nil, err
		}
		resp.Hostname = publicHostname
		resp.KeylessURL = keylessURL
	}
	return resp, hopRoutes, nil
}

func (l *listener) renewRegisteredLease(ctx context.Context, ttl time.Duration, accessToken string, hopRoutes []types.HopRoute) (types.RenewResponse, error) {
	var resp types.RenewResponse
	if err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKRenew, types.RenewRequest{
		AccessToken: accessToken,
		TTL:         int(ttl / time.Second),
		ReportedIP:  utils.ResolvePublicIP(ctx),
	}, nil, &resp); err != nil {
		return types.RenewResponse{}, err
	}
	if err := l.syncHopRoutes(ctx, http.MethodPost, resp.ExpiresAt, hopRoutes); err != nil {
		return types.RenewResponse{}, err
	}
	return resp, nil
}

func (l *listener) unregisterLease(ctx context.Context, accessToken string, hopRoutes []types.HopRoute) error {
	var unregisterErr error
	if err := l.syncHopRoutes(ctx, http.MethodDelete, time.Time{}, hopRoutes); err != nil {
		unregisterErr = errors.Join(unregisterErr, err)
	}
	err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKUnregister, types.UnregisterRequest{
		AccessToken: accessToken,
	}, nil, nil)
	return errors.Join(unregisterErr, err)
}

func (l *listener) syncHopRoutes(ctx context.Context, method string, expiresAt time.Time, routes []types.HopRoute) error {
	if len(routes) == 0 {
		return nil
	}

	orderedRoutes := routes
	if method == http.MethodPost {
		if l.relaySet == nil {
			return errors.New("multi-hop relay set is unavailable")
		}
		orderedRoutes = append([]types.HopRoute(nil), routes...)
		now := time.Now().UTC()
		for i := range orderedRoutes {
			desc, ok := l.relaySet.OverlayRelayDescriptor(orderedRoutes[i].ForwardRelay.APIHTTPSAddr, now)
			if !ok {
				return fmt.Errorf("multi-hop forward relay %d descriptor is unavailable", i)
			}
			orderedRoutes[i].ForwardRelay = desc
		}
		slices.Reverse(orderedRoutes)
	}

	var syncErr error
	for _, unsignedRoute := range orderedRoutes {
		unsignedRoute.FirstSeenAt = expiresAt.Add(-30 * time.Second)
		route, err := auth.SignHopRoute(method, unsignedRoute, l.identity, expiresAt)
		if err != nil {
			if method == http.MethodDelete {
				syncErr = errors.Join(syncErr, err)
				continue
			}
			return err
		}
		relayURL, err := url.Parse(route.RelayURL)
		if err != nil {
			err = fmt.Errorf("parse hop route relay url: %w", err)
			if method == http.MethodDelete {
				syncErr = errors.Join(syncErr, err)
				continue
			}
			return err
		}

		bootstrapCtx, cancel := context.WithTimeout(ctx, defaultDialTimeout+defaultHandshakeTimeout)
		_, client, err := utils.NewHTTPTLSClient(bootstrapCtx, relayURL, l.requestTimeout)
		cancel()
		if err != nil {
			if method == http.MethodDelete {
				syncErr = errors.Join(syncErr, err)
				continue
			}
			return err
		}
		transport, _ := client.Transport.(*http.Transport)
		err = utils.HTTPDoAPIPath(ctx, client, relayURL, method, types.PathSDKHop, route, nil, nil)
		if transport != nil {
			transport.CloseIdleConnections()
		}
		if err != nil {
			if method == http.MethodDelete {
				syncErr = errors.Join(syncErr, err)
				continue
			}
			return err
		}
	}
	return syncErr
}
