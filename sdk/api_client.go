package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultDialTimeout         = 15 * time.Second
	defaultRequestTimeout      = 30 * time.Second
	defaultHandshakeTimeout    = 30 * time.Second
	defaultLeaseTTL            = 2 * time.Minute
	defaultRenewBefore         = 30 * time.Second
	defaultReadyTarget         = 2
	defaultRetryWait           = 3 * time.Second
	defaultHTTPShutdownTimeout = 5 * time.Second
	defaultIdleTimeout         = 90 * time.Second
)

var errRelayIncompatible = errors.New("relay is incompatible")

// relayEndpointError records the exact relay that rejected an operation
// operation.
type relayEndpointError struct {
	relayURL string
	err      error
}

func (err *relayEndpointError) Error() string {
	return fmt.Sprintf("relay endpoint %s: %v", err.relayURL, err.err)
}

func (err *relayEndpointError) Unwrap() error {
	return err.err
}

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
	l.gatewayTLS = nil
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
		return fmt.Errorf("check relay compatibility: %w", err)
	}
	protocolVersion := strings.TrimSpace(domainResp.ProtocolVersion)
	if protocolVersion != types.SDKVersion {
		httpTransport.CloseIdleConnections()
		return fmt.Errorf("%w: relay sdk protocol version mismatch: relay=%q client=%q", errRelayIncompatible, protocolVersion, types.SDKVersion)
	}

	l.releaseVersion = strings.TrimSpace(domainResp.ReleaseVersion)
	if l.route.GatewayURL != "" {
		gatewayURL, err := url.Parse(l.route.GatewayURL)
		if err != nil {
			httpTransport.CloseIdleConnections()
			return err
		}
		gatewayTLS, _, gatewayTransport, err := utils.NewHTTPTLSClient(bootstrapCtx, gatewayURL, l.requestTimeout)
		if err != nil {
			httpTransport.CloseIdleConnections()
			return &relayEndpointError{relayURL: l.route.GatewayURL, err: err}
		}
		gatewayTransport.CloseIdleConnections()
		l.gatewayTLS = gatewayTLS
	}

	l.httpClient = httpClient
	l.httpTransport = httpTransport
	l.tlsConfig = tlsConfig
	return nil
}

func (l *listener) registerLease(ctx context.Context, ttl time.Duration, udpEnabled, tcpEnabled bool) (types.RegisterResponse, string, string, error) {
	rootHostname := utils.PortalRootHost(l.relayURL.String())
	var routeHostname string
	publicHostname, err := utils.LeaseHostname(l.identity.Name, rootHostname)
	if err != nil {
		return types.RegisterResponse{}, "", "", err
	}
	if l.echEnabled {
		routeToken, err := identity.DeriveToken(l.identity, "ech-route", publicHostname, rootHostname)
		if err != nil {
			return types.RegisterResponse{}, "", "", err
		}
		routeSum := sha256.Sum256([]byte(routeToken))
		routeLabel := "ech-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(routeSum[:20]))
		routeHostname, err = utils.LeaseHostname(routeLabel, rootHostname)
		if err != nil {
			return types.RegisterResponse{}, "", "", err
		}
	}
	var echConfigList []byte
	if l.echEnabled {
		_, echConfigList, err = l.tenantECHMaterials(publicHostname, routeHostname)
		if err != nil {
			return types.RegisterResponse{}, "", "", err
		}
	}

	registerReq := types.RegisterChallengeRequest{
		Identity:   l.identity,
		Metadata:   l.metadataSnapshot(),
		TTL:        int(ttl / time.Second),
		UDPEnabled: udpEnabled,
		TCPEnabled: tcpEnabled,
	}
	if l.echEnabled {
		registerReq.RouteHostname = routeHostname
		registerReq.HostnameHash = utils.HostnameHash(publicHostname)
		registerReq.ECHConfigList = bytes.Clone(echConfigList)
	}

	var challenge types.RegisterChallengeResponse
	if err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKRegisterChallenge, registerReq, nil, &challenge); err != nil {
		return types.RegisterResponse{}, "", "", err
	}

	authority, err := identity.NewLocalAuthority(l.identity)
	if err != nil {
		return types.RegisterResponse{}, "", "", err
	}
	signature, err := authority.SignEthereumPersonalMessage(challenge.SIWEMessage)
	if err != nil {
		return types.RegisterResponse{}, "", "", err
	}

	var resp types.RegisterResponse
	if err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{
		ChallengeID:   challenge.ChallengeID,
		SIWEMessage:   challenge.SIWEMessage,
		SIWESignature: signature,
		ReportedIP:    utils.ResolvePublicIP(ctx),
	}, nil, &resp); err != nil {
		return types.RegisterResponse{}, "", "", err
	}
	registeredIdentity, err := identity.NormalizeIdentity(resp.Identity)
	if err != nil {
		_ = l.unregisterLease(context.Background(), resp.AccessToken)
		return types.RegisterResponse{}, "", "", err
	}
	if registeredIdentity.Key() != l.identity.Key() {
		_ = l.unregisterLease(context.Background(), resp.AccessToken)
		return types.RegisterResponse{}, "", "", errors.New("relay returned mismatched lease identity")
	}
	return resp, publicHostname, routeHostname, nil
}

func (l *listener) renewRegisteredLease(ctx context.Context, ttl time.Duration, accessToken string) (types.RenewResponse, error) {
	var resp types.RenewResponse
	req := newRenewRequest(ttl, accessToken, utils.ResolvePublicIP(ctx), l.metadataSnapshot())
	if err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKRenew, req, nil, &resp); err != nil {
		return types.RenewResponse{}, err
	}
	return resp, nil
}

func newRenewRequest(ttl time.Duration, accessToken, reportedIP string, metadata types.LeaseMetadata) types.RenewRequest {
	return types.RenewRequest{
		AccessToken: accessToken,
		TTL:         int(ttl / time.Second),
		ReportedIP:  reportedIP,
		Metadata:    metadata.Copy(),
	}
}

func (l *listener) unregisterLease(ctx context.Context, accessToken string) error {
	err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKUnregister, types.UnregisterRequest{
		AccessToken: accessToken,
	}, nil, nil)
	return err
}
