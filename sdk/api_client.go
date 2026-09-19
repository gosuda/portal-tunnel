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

// resetTransport tears down the cached HTTP client and TLS config so the next
// API call creates fresh TCP connections. Call this after detecting a system
// sleep/wake cycle where pooled connections are almost certainly dead.
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

// httpClient returns the cached HTTP client under the transport lock.
// Callers must not mutate the returned client.
func (c *apiClient) httpClient() *http.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.http
}

// tlsConfigClone returns a cloned copy of the relay TLS config under
// the transport lock, or nil if the transport has not been initialized.
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

// register only performs the challenge and registration wire exchange.
// The caller prepares lease metadata and capability flags beforehand.
func (c *apiClient) register(ctx context.Context, registerReq types.RegisterChallengeRequest, reportedIP string) (types.RegisterResponse, error) {
	if err := c.initHTTPTransport(ctx); err != nil {
		return types.RegisterResponse{}, err
	}

	var challenge types.RegisterChallengeResponse
	var request types.RegisterRequest
	var resp types.RegisterResponse
	for {
		var err error
		if request.ChallengeID == "" || !time.Now().Before(challenge.ExpiresAt) {
			err = utils.HTTPDoAPIPath(ctx, c.httpClient(), c.relayURL, http.MethodPost, types.PathSDKRegisterChallenge, registerReq, nil, &challenge)
			if err == nil {
				if challenge.ChallengeID == "" || !time.Now().Before(challenge.ExpiresAt) {
					return types.RegisterResponse{}, errors.New("relay returned an invalid or expired registration challenge")
				}
				signature, err := identity.NewLocalAuthority(registerReq.Identity).SignEthereumPersonalMessage(challenge.SIWEMessage)
				if err != nil {
					return types.RegisterResponse{}, err
				}
				request = types.RegisterRequest{ChallengeID: challenge.ChallengeID, SIWEMessage: challenge.SIWEMessage, SIWESignature: signature, ReportedIP: reportedIP}
				// Challenge issuance succeeded; keep this signed request until admission
				// succeeds or the challenge expires. A 429 must not buy another challenge.
				continue
			}
		} else {
			err = utils.HTTPDoAPIPath(ctx, c.httpClient(), c.relayURL, http.MethodPost, types.PathSDKRegister, request, nil, &resp)
			if err == nil {
				break
			}
		}
		apiErr, ok := errors.AsType[*types.APIRequestError](err)
		if !ok || !apiErr.IsRateLimited() {
			return types.RegisterResponse{}, err
		}
		delay := apiErr.RetryAfter
		if delay <= 0 {
			delay = defaultRetryWait
		}
		if !utils.SleepOrDone(ctx, delay) {
			return types.RegisterResponse{}, ctx.Err()
		}
	}
	resp.AccessToken = strings.TrimSpace(resp.AccessToken)
	if resp.AccessToken == "" {
		return types.RegisterResponse{}, errors.New("relay did not return access token")
	}
	if resp.Identity.Key() != registerReq.Identity.Key() {
		_ = c.unregister(context.Background(), resp.AccessToken)
		return types.RegisterResponse{}, errors.New("relay returned mismatched lease identity")
	}
	reverseEndpoint, err := validateReverseEndpoint(resp.ReverseEndpoint, resp.ExpiresAt)
	if err != nil {
		_ = c.unregister(context.Background(), resp.AccessToken)
		return types.RegisterResponse{}, err
	}
	resp.ReverseEndpoint = reverseEndpoint
	return resp, nil
}

func (c *apiClient) renew(ctx context.Context, req types.RenewRequest) (types.RenewResponse, error) {
	var resp types.RenewResponse
	if err := utils.HTTPDoAPIPath(ctx, c.httpClient(), c.relayURL, http.MethodPost, types.PathSDKRenew, req, nil, &resp); err != nil {
		return types.RenewResponse{}, err
	}
	resp.AccessToken = strings.TrimSpace(resp.AccessToken)
	if resp.AccessToken == "" {
		return types.RenewResponse{}, errors.New("relay did not return renewed access token")
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

func (c *apiClient) unregister(ctx context.Context, accessToken string) error {
	err := utils.HTTPDoAPIPath(ctx, c.httpClient(), c.relayURL, http.MethodPost, types.PathSDKUnregister, types.UnregisterRequest{
		AccessToken: accessToken,
	}, nil, nil)
	return err
}
