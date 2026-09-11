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

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/internal/identity"
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

// relayRegistrationError records the exact relay that rejected a registration
// operation.
type relayRegistrationError struct {
	relayURL string
	err      error
}

func (err *relayRegistrationError) Error() string {
	return fmt.Sprintf("register relay at %s: %v", err.relayURL, err.err)
}

func (err *relayRegistrationError) Unwrap() error {
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
		Overlay:    l.overlay,
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
	reverseEndpoint, err := validateReverseEndpoint(resp.ReverseEndpoint, resp.ExpiresAt)
	if err != nil {
		_ = l.unregisterLease(context.Background(), resp.AccessToken)
		return types.RegisterResponse{}, "", "", err
	}
	if err := l.validateReverseEndpointTransport(reverseEndpoint); err != nil {
		_ = l.unregisterLease(context.Background(), resp.AccessToken)
		return types.RegisterResponse{}, "", "", err
	}
	resp.ReverseEndpoint = reverseEndpoint
	return resp, publicHostname, routeHostname, nil
}

func (l *listener) renewRegisteredLease(ctx context.Context, ttl time.Duration, accessToken string) (types.RenewResponse, error) {
	var resp types.RenewResponse
	req := newRenewRequest(ttl, accessToken, utils.ResolvePublicIP(ctx), l.metadataSnapshot())
	if err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKRenew, req, nil, &resp); err != nil {
		return types.RenewResponse{}, err
	}
	reverseEndpoint, err := validateReverseEndpoint(resp.ReverseEndpoint, resp.ExpiresAt)
	if err != nil {
		return types.RenewResponse{}, err
	}
	if err := l.validateReverseEndpointTransport(reverseEndpoint); err != nil {
		return types.RenewResponse{}, err
	}
	resp.ReverseEndpoint = reverseEndpoint
	return resp, nil
}

func (l *listener) requestReverseEndpoint(ctx context.Context, accessToken, failedURL string, leaseExpiresAt time.Time) (types.ReverseEndpoint, error) {
	var endpoint types.ReverseEndpoint
	req := types.ReverseEndpointRequest{AccessToken: accessToken, FailedURL: failedURL}
	if err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKReverse, req, nil, &endpoint); err != nil {
		return types.ReverseEndpoint{}, err
	}
	endpoint, err := validateReverseEndpoint(endpoint, leaseExpiresAt)
	if err != nil {
		return types.ReverseEndpoint{}, err
	}
	if err := l.validateReverseEndpointTransport(endpoint); err != nil {
		return types.ReverseEndpoint{}, err
	}
	return endpoint, nil
}

func (l *listener) validateReverseEndpointTransport(endpoint types.ReverseEndpoint) error {
	if !l.overlay {
		if endpoint.Overlay {
			return errors.New("relay returned an overlay reverse endpoint but overlay is disabled")
		}
		if l.isAlternateReverseEndpoint(endpoint.URL) {
			return fmt.Errorf("relay reverse endpoint %s does not match the relay URL; align the relay's PORTAL_URL with the address clients dial", endpoint.URL)
		}
		return nil
	}
	if !endpoint.Overlay && !l.isAlternateReverseEndpoint(endpoint.URL) {
		l.warnOverlayDirect.Do(func() {
			log.Warn().
				Str("relay_url", l.route.RelayURL).
				Msg("overlay requested but the relay serves a direct reverse endpoint; continuing without overlay forwarding")
		})
	}
	return nil
}

func validateReverseEndpoint(endpoint types.ReverseEndpoint, leaseExpiresAt time.Time) (types.ReverseEndpoint, error) {
	endpoint.URL = strings.TrimSpace(endpoint.URL)
	endpoint.Capability = strings.TrimSpace(endpoint.Capability)
	if endpoint.URL == "" || endpoint.Capability == "" {
		return types.ReverseEndpoint{}, errors.New("relay returned incomplete reverse endpoint")
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil || parsed.Host == "" || !strings.EqualFold(parsed.Scheme, "https") {
		return types.ReverseEndpoint{}, errors.New("relay returned invalid reverse endpoint URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.EscapedPath() != types.PathSDKConnect {
		return types.ReverseEndpoint{}, errors.New("relay returned invalid reverse endpoint target")
	}
	if !endpoint.ExpiresAt.After(time.Now().UTC()) || endpoint.ExpiresAt.After(leaseExpiresAt) {
		return types.ReverseEndpoint{}, errors.New("relay returned invalid reverse endpoint expiry")
	}
	endpoint.URL = parsed.String()
	return endpoint, nil
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
