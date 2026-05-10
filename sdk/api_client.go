package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
	defaultLeaseTTL            = 2 * time.Minute
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
	if l.httpTransport != nil {
		l.httpTransport.CloseIdleConnections()
	}
	l.httpClient = nil
	l.httpTransport = nil
	l.tlsConfig = nil
}

func (l *listener) initHTTPTransport(ctx context.Context) error {
	if l.httpClient != nil {
		return nil
	}

	bootstrapCtx, cancel := context.WithTimeout(ctx, defaultDialTimeout+defaultHandshakeTimeout)
	defer cancel()

	tlsConfig, httpClient, httpTransport, err := utils.NewHTTPTLSClient(bootstrapCtx, l.relayURL, l.requestTimeout)
	if err != nil {
		return err
	}

	var domainResp types.DomainResponse
	if err := utils.HTTPDoAPIPath(ctx, httpClient, l.relayURL, http.MethodGet, types.PathSDKDomain, nil, nil, &domainResp); err != nil {
		httpTransport.CloseIdleConnections()
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
		httpTransport.CloseIdleConnections()
		return fmt.Errorf("%w: relay sdk protocol version mismatch: relay=%q client=%q", errRelayIncompatible, protocolVersion, types.SDKVersion)
	}

	l.httpClient = httpClient
	l.httpTransport = httpTransport
	l.tlsConfig = tlsConfig
	return nil
}

func (l *listener) registerLease(ctx context.Context, ttl time.Duration, udpEnabled, tcpEnabled bool) (types.RegisterResponse, []types.HopRoute, string, string, error) {
	var exitHopToken string
	var publicHostname string
	var routeHostname string
	var rootHostname string
	var hopRoutes []types.HopRoute
	var hopPath []types.RelayDescriptor
	streamLease := !udpEnabled && !tcpEnabled
	registerIdentity := l.identity
	if len(l.multiHop) > 0 {
		if !streamLease {
			return types.RegisterResponse{}, nil, "", "", errors.New("multi-hop requires stream lease")
		}
		if len(l.multiHop) < 2 {
			return types.RegisterResponse{}, nil, "", "", errors.New("multi-hop requires at least entry and exit relay urls")
		}
		if l.relaySet == nil {
			return types.RegisterResponse{}, nil, "", "", errors.New("multi-hop relay set is unavailable")
		}

		now := time.Now().UTC()
		hopPath = make([]types.RelayDescriptor, 0, len(l.multiHop))
		for i, relayURL := range l.multiHop {
			desc, ok := l.relaySet.OverlayRelayDescriptor(relayURL, now)
			if !ok {
				return types.RegisterResponse{}, nil, "", "", fmt.Errorf("multi-hop relay %d descriptor is unavailable", i)
			}
			hopPath = append(hopPath, desc)
		}

		rootHostname = utils.PortalRootHost(hopPath[0].APIHTTPSAddr)
	} else {
		rootHostname = utils.PortalRootHost(l.relayURL.String())
	}

	var err error
	publicHostname, err = utils.LeaseHostname(l.identity.Name, rootHostname)
	if err != nil {
		return types.RegisterResponse{}, nil, "", "", err
	}
	if streamLease {
		routeToken, err := l.identity.DeriveToken("ech-route", publicHostname, rootHostname)
		if err != nil {
			return types.RegisterResponse{}, nil, "", "", err
		}
		routeSum := sha256.Sum256([]byte(routeToken))
		routeLabel := "ech-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(routeSum[:20]))
		routeHostname, err = utils.LeaseHostname(routeLabel, rootHostname)
		if err != nil {
			return types.RegisterResponse{}, nil, "", "", err
		}
	}
	var echConfigList []byte
	if streamLease {
		_, echConfigList, err = l.tenantECHMaterials(publicHostname, routeHostname)
		if err != nil {
			return types.RegisterResponse{}, nil, "", "", err
		}
	}

	if len(l.multiHop) > 0 {
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
				return types.RegisterResponse{}, nil, "", "", err
			}
			forwardToken := "hpt_" + token
			route := types.HopRoute{
				RelayURL:     hopPath[i].APIHTTPSAddr,
				ForwardRelay: hopPath[i+1],
				ForwardToken: forwardToken,
			}
			if i == 0 {
				route.PublicHostname = publicHostname
				route.RouteHostname = routeHostname
				route.HostnameHash = utils.HostnameHash(publicHostname)
				route.ECHConfigList = bytes.Clone(echConfigList)
				route.Metadata = l.metadata.Copy()
				route.Metadata.Hide = true
				hopRoutes = append(hopRoutes, route)
			} else {
				route.MatchToken = previousHopToken
				hopRoutes = append(hopRoutes, route)
			}
			previousHopToken = forwardToken
		}
		exitHopToken = previousHopToken
	}

	registerReq := types.RegisterChallengeRequest{
		Identity:   registerIdentity,
		Metadata:   l.metadata,
		TTL:        int(ttl / time.Second),
		UDPEnabled: udpEnabled,
		TCPEnabled: tcpEnabled,
		HopToken:   exitHopToken,
	}
	if streamLease && len(l.multiHop) == 0 {
		registerReq.RouteHostname = routeHostname
		registerReq.HostnameHash = utils.HostnameHash(publicHostname)
		registerReq.ECHConfigList = bytes.Clone(echConfigList)
	}

	var challenge types.RegisterChallengeResponse
	if err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKRegisterChallenge, registerReq, nil, &challenge); err != nil {
		return types.RegisterResponse{}, nil, "", "", err
	}

	signature, err := utils.SignEthereumPersonalMessage(challenge.SIWEMessage, l.identity.PrivateKey)
	if err != nil {
		return types.RegisterResponse{}, nil, "", "", err
	}

	var resp types.RegisterResponse
	if err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{
		ChallengeID:   challenge.ChallengeID,
		SIWEMessage:   challenge.SIWEMessage,
		SIWESignature: signature,
		ReportedIP:    utils.ResolvePublicIP(ctx),
	}, nil, &resp); err != nil {
		return types.RegisterResponse{}, nil, "", "", err
	}
	registeredIdentity, err := utils.NormalizeIdentity(resp.Identity)
	if err != nil {
		_ = l.unregisterLease(context.Background(), resp.AccessToken, hopRoutes)
		return types.RegisterResponse{}, nil, "", "", err
	}
	if registeredIdentity.Key() != registerIdentity.Key() {
		_ = l.unregisterLease(context.Background(), resp.AccessToken, hopRoutes)
		return types.RegisterResponse{}, nil, "", "", errors.New("relay returned mismatched lease identity")
	}
	return resp, hopRoutes, publicHostname, routeHostname, nil
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

func (l *listener) unregisterLease(ctx context.Context, accessToken string, hopRoutes []types.HopRoute) error {
	hopErr := l.unregisterHopRoutes(ctx, hopRoutes)
	err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKUnregister, types.UnregisterRequest{
		AccessToken: accessToken,
	}, nil, nil)
	return errors.Join(hopErr, err)
}

func (l *listener) registerHopRoutes(ctx context.Context, expiresAt time.Time, routes []types.HopRoute) (string, int, error) {
	if l.relaySet == nil {
		return "", 0, errors.New("multi-hop relay set is unavailable")
	}

	now := time.Now().UTC()
	for i := len(routes) - 1; i >= 0; i-- {
		route := routes[i]
		desc, ok := l.relaySet.OverlayRelayDescriptor(route.ForwardRelay.APIHTTPSAddr, now)
		if !ok {
			return "", 0, fmt.Errorf("multi-hop forward relay %d descriptor is unavailable", i)
		}
		route.ForwardRelay = desc
		route.FirstSeenAt = expiresAt.Add(-30 * time.Second)
		route, err := auth.SignHopRoute(http.MethodPost, route, l.identity, expiresAt)
		if err != nil {
			return "", 0, err
		}
		relayURL, err := url.Parse(route.RelayURL)
		if err != nil {
			return "", 0, fmt.Errorf("parse hop route relay url: %w", err)
		}

		bootstrapCtx, cancel := context.WithTimeout(ctx, defaultDialTimeout+defaultHandshakeTimeout)
		_, client, transport, err := utils.NewHTTPTLSClient(bootstrapCtx, relayURL, l.requestTimeout)
		cancel()
		if err != nil {
			return "", 0, err
		}
		var hopResp types.HopRouteResponse
		err = utils.HTTPDoAPIPath(ctx, client, relayURL, http.MethodPost, types.PathSDKHop, route, nil, &hopResp)
		transport.CloseIdleConnections()
		if err != nil {
			return "", 0, err
		}
		if route.MatchToken != "" || route.RouteHostname == "" {
			continue
		}
		if hopResp.AccessToken == "" {
			return "", 0, errors.New("entry relay did not return access token")
		}
		if hopResp.SNIPort <= 0 {
			return "", 0, errors.New("entry relay did not return sni port")
		}
		return hopResp.AccessToken, hopResp.SNIPort, nil
	}
	return "", 0, errors.New("entry hop route did not return access token")
}

func (l *listener) unregisterHopRoutes(ctx context.Context, routes []types.HopRoute) error {
	var unregisterErr error
	for _, route := range routes {
		route, err := auth.SignHopRoute(http.MethodDelete, route, l.identity, time.Time{})
		if err != nil {
			unregisterErr = errors.Join(unregisterErr, err)
			continue
		}
		relayURL, err := url.Parse(route.RelayURL)
		if err != nil {
			unregisterErr = errors.Join(unregisterErr, fmt.Errorf("parse hop route relay url: %w", err))
			continue
		}

		bootstrapCtx, cancel := context.WithTimeout(ctx, defaultDialTimeout+defaultHandshakeTimeout)
		_, client, transport, err := utils.NewHTTPTLSClient(bootstrapCtx, relayURL, l.requestTimeout)
		cancel()
		if err != nil {
			unregisterErr = errors.Join(unregisterErr, err)
			continue
		}
		err = utils.HTTPDoAPIPath(ctx, client, relayURL, http.MethodDelete, types.PathSDKHop, route, nil, nil)
		transport.CloseIdleConnections()
		if err != nil {
			unregisterErr = errors.Join(unregisterErr, err)
		}
	}
	return unregisterErr
}
