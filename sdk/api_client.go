package sdk

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errRelayDidNotReturnAccessToken              = errors.New("relay did not return access token")
	errRelayReturnedMismatchedLeaseIdentity      = errors.New("relay returned mismatched lease identity")
	errRelayDidNotReturnCanonicalHostname        = errors.New("relay did not return canonical hostname")
	errRelayDidNotReturnRenewedAccess            = errors.New("relay did not return renewed access token")
	errRelayReturnedIncompleteReverseEndpoint    = errors.New("relay returned incomplete reverse endpoint")
	errRelayReturnedInvalidReverseEndpointURL    = errors.New("relay returned invalid reverse endpoint URL")
	errRelayReturnedInvalidReverseEndpointTarget = errors.New("relay returned invalid reverse endpoint target")
	errRelayReturnedInvalidReverseEndpointExpiry = errors.New("relay returned invalid reverse endpoint expiry")
)

const (
	defaultAPIBootstrapTimeout = 45 * time.Second
	defaultAPIRequestTimeout   = 30 * time.Second
)

var errRelayIncompatible = errors.New("relay is incompatible")

type apiClient struct {
	relayURL *url.URL

	mu             sync.RWMutex
	http           *http.Client
	transport      *http.Transport
	tls            *tls.Config
	releaseVersion string
	cache          *types.StaticCacheLimits
}

func (c *apiClient) resetTransport() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	c.http = nil
	c.transport = nil
	c.tls = nil
	c.cache = nil
}

func (c *apiClient) initHTTPTransport(ctx context.Context) error {
	c.mu.RLock()
	if c.http != nil {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()

	bootstrapCtx, cancel := context.WithTimeout(ctx, defaultAPIBootstrapTimeout)
	defer cancel()

	tlsConfig, httpClient, httpTransport, err := utils.NewHTTPTLSClient(bootstrapCtx, c.relayURL, defaultAPIRequestTimeout)
	if err != nil {
		return err
	}

	var domainResp types.DomainResponse
	if err := utils.HTTPDoAPIPath(ctx, httpClient, c.relayURL, http.MethodGet, types.PathSDKDomain, nil, nil, &domainResp); err != nil {
		httpTransport.CloseIdleConnections()
		return fmt.Errorf("check relay compatibility: %w", err)
	}
	protocolVersion := strings.TrimSpace(domainResp.ProtocolVersion)
	if protocolVersion != types.SDKVersion {
		httpTransport.CloseIdleConnections()
		return fmt.Errorf("%w: relay sdk protocol version mismatch: relay=%q client=%q", errRelayIncompatible, protocolVersion, types.SDKVersion)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.http != nil {
		httpTransport.CloseIdleConnections()
		return nil
	}
	c.releaseVersion = strings.TrimSpace(domainResp.ReleaseVersion)
	c.cache = domainResp.Cache
	c.http = httpClient
	c.transport = httpTransport
	c.tls = tlsConfig
	return nil
}

func (c *apiClient) httpClient() *http.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.http
}

func (c *apiClient) tlsConfigClone() *tls.Config {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.tls == nil {
		return nil
	}
	return c.tls.Clone()
}

func (c *apiClient) relayReleaseVersion() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.releaseVersion
}

func (c *apiClient) cacheLimits() (types.StaticCacheLimits, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cache == nil {
		return types.StaticCacheLimits{}, false
	}
	return *c.cache, true
}

func (c *apiClient) register(ctx context.Context, registerReq types.RegisterChallengeRequest, reportedIP string) (types.RegisterResponse, error) {
	if err := c.initHTTPTransport(ctx); err != nil {
		return types.RegisterResponse{}, err
	}
	resp, err := c.exchangeRegister(ctx, registerReq, reportedIP)
	if err != nil {
		return types.RegisterResponse{}, err
	}
	return c.confirmRegisterResponse(resp, registerReq)
}

func (c *apiClient) exchangeRegister(ctx context.Context, registerReq types.RegisterChallengeRequest, reportedIP string) (types.RegisterResponse, error) {
	var challenge types.RegisterChallengeResponse
	var request types.RegisterRequest
	var resp types.RegisterResponse
	for {
		if request.ChallengeID == "" || !time.Now().Before(challenge.ExpiresAt) {
			if err := c.reloadRegisterChallenge(ctx, registerReq, reportedIP, &challenge, &request); err != nil {
				return types.RegisterResponse{}, err
			}
			continue
		}
		submitErr := utils.HTTPDoAPIPath(ctx, c.httpClient(), c.relayURL, http.MethodPost, types.PathSDKRegister, request, nil, &resp)
		if submitErr == nil {
			return resp, nil
		}
		if pauseErr := pauseRegisterRetry(ctx, submitErr); pauseErr != nil {
			return types.RegisterResponse{}, pauseErr
		}
	}
}

func (c *apiClient) reloadRegisterChallenge(ctx context.Context, registerReq types.RegisterChallengeRequest, reportedIP string, challenge *types.RegisterChallengeResponse, request *types.RegisterRequest) error {
	if err := utils.HTTPDoAPIPath(ctx, c.httpClient(), c.relayURL, http.MethodPost, types.PathSDKRegisterChallenge, registerReq, nil, challenge); err != nil {
		return pauseRegisterRetry(ctx, err)
	}
	signed, err := signRegisterChallenge(*challenge, c.relayURL, registerReq, reportedIP)
	if err != nil {
		return err
	}
	*request = signed
	return nil
}

func pauseRegisterRetry(ctx context.Context, err error) error {
	delay, ok := registerRetryDelay(err)
	if !ok {
		return err
	}
	if !utils.SleepOrDone(ctx, delay) {
		return ctx.Err()
	}
	return nil
}

func signRegisterChallenge(challenge types.RegisterChallengeResponse, relayURL *url.URL, registerReq types.RegisterChallengeRequest, reportedIP string) (types.RegisterRequest, error) {
	if err := identity.ValidateRegisterSIWEChallenge(challenge, relayURL, registerReq.Identity.Address, time.Now()); err != nil {
		return types.RegisterRequest{}, err
	}
	signature, err := identity.NewLocalAuthority(registerReq.Identity).SignEthereumPersonalMessage(challenge.SIWEMessage)
	if err != nil {
		return types.RegisterRequest{}, err
	}
	return types.RegisterRequest{ChallengeID: challenge.ChallengeID, SIWEMessage: challenge.SIWEMessage, SIWESignature: signature, ReportedIP: reportedIP}, nil
}

func registerRetryDelay(err error) (time.Duration, bool) {
	apiErr, ok := errors.AsType[*types.APIRequestError](err)
	if !ok || !apiErr.IsRateLimited() {
		return 0, false
	}
	delay := apiErr.RetryAfter
	if delay <= 0 {
		delay = defaultRetryWait
	}
	return delay, true
}

func (c *apiClient) confirmRegisterResponse(resp types.RegisterResponse, registerReq types.RegisterChallengeRequest) (types.RegisterResponse, error) {
	resp.AccessToken = strings.TrimSpace(resp.AccessToken)
	if resp.AccessToken == "" {
		return types.RegisterResponse{}, errRelayDidNotReturnAccessToken
	}
	if resp.Identity.Key() != registerReq.Identity.Key() {
		_ = c.unregister(context.Background(), resp.AccessToken)
		return types.RegisterResponse{}, errRelayReturnedMismatchedLeaseIdentity
	}
	resp.Hostname = utils.NormalizeHostname(resp.Hostname)
	resp.CanonicalHostname = utils.NormalizeHostname(resp.CanonicalHostname)
	if resp.CanonicalHostname == "" {
		_ = c.unregister(context.Background(), resp.AccessToken)
		return types.RegisterResponse{}, errRelayDidNotReturnCanonicalHostname
	}
	if !aliasHostnameMatches(resp.Hostname, registerReq.Identity.Name, resp.CanonicalHostname) {
		resp.Hostname = ""
	}
	reverseEndpoint, err := validateReverseEndpoint(resp.ReverseEndpoint, resp.ExpiresAt)
	if err != nil {
		_ = c.unregister(context.Background(), resp.AccessToken)
		return types.RegisterResponse{}, err
	}
	resp.ReverseEndpoint = reverseEndpoint
	return resp, nil
}

func aliasHostnameMatches(hostname, name, canonicalHostname string) bool {
	if hostname == "" {
		return true
	}
	label, err := utils.NormalizeDNSLabel(name)
	if err != nil || label == "" {
		return false
	}
	_, root, ok := strings.Cut(canonicalHostname, ".")
	return ok && hostname == label+"."+root
}

func (c *apiClient) renew(ctx context.Context, req types.RenewRequest) (types.RenewResponse, error) {
	var resp types.RenewResponse
	if err := utils.HTTPDoAPIPath(ctx, c.httpClient(), c.relayURL, http.MethodPost, types.PathSDKRenew, req, nil, &resp); err != nil {
		return types.RenewResponse{}, err
	}
	resp.AccessToken = strings.TrimSpace(resp.AccessToken)
	if resp.AccessToken == "" {
		return types.RenewResponse{}, errRelayDidNotReturnRenewedAccess
	}
	reverseEndpoint, err := validateReverseEndpoint(resp.ReverseEndpoint, resp.ExpiresAt)
	if err != nil {
		return types.RenewResponse{}, err
	}
	resp.ReverseEndpoint = reverseEndpoint
	return resp, nil
}

func (c *apiClient) requestReverseEndpoint(ctx context.Context, accessToken, failedURL string, leaseExpiresAt time.Time) (types.ReverseEndpoint, error) {
	var endpoint types.ReverseEndpoint
	req := types.ReverseEndpointRequest{AccessToken: accessToken, FailedURL: failedURL}
	if err := utils.HTTPDoAPIPath(ctx, c.httpClient(), c.relayURL, http.MethodPost, types.PathSDKReverse, req, nil, &endpoint); err != nil {
		return types.ReverseEndpoint{}, err
	}
	endpoint, err := validateReverseEndpoint(endpoint, leaseExpiresAt)
	if err != nil {
		return types.ReverseEndpoint{}, err
	}
	return endpoint, nil
}

func validateReverseEndpoint(endpoint types.ReverseEndpoint, leaseExpiresAt time.Time) (types.ReverseEndpoint, error) {
	endpoint.URL = strings.TrimSpace(endpoint.URL)
	endpoint.Capability = strings.TrimSpace(endpoint.Capability)
	if endpoint.URL == "" || endpoint.Capability == "" {
		return types.ReverseEndpoint{}, errRelayReturnedIncompleteReverseEndpoint
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil {
		return types.ReverseEndpoint{}, fmt.Errorf("%w: %w", errRelayReturnedInvalidReverseEndpointURL, err)
	}
	if parsed.Host == "" || !strings.EqualFold(parsed.Scheme, "https") {
		return types.ReverseEndpoint{}, errRelayReturnedInvalidReverseEndpointURL
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.EscapedPath() != types.PathSDKConnect {
		return types.ReverseEndpoint{}, errRelayReturnedInvalidReverseEndpointTarget
	}
	if !endpoint.ExpiresAt.After(time.Now().UTC()) || endpoint.ExpiresAt.After(leaseExpiresAt) {
		return types.ReverseEndpoint{}, errRelayReturnedInvalidReverseEndpointExpiry
	}
	endpoint.URL = parsed.String()
	return endpoint, nil
}

func (c *apiClient) unregister(ctx context.Context, accessToken string) error {
	err := utils.HTTPDoAPIPath(ctx, c.httpClient(), c.relayURL, http.MethodPost, types.PathSDKUnregister, types.UnregisterRequest{
		AccessToken: accessToken,
	}, nil, nil)
	return err
}
