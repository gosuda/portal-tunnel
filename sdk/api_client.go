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

	"github.com/rs/zerolog/log"

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

// relayRegistrationError records the exact relay that rejected a registration
// operation.
type relayRegistrationError struct {
	relayURL string
	err      error
}

type apiClient struct {
	relayURL       *url.URL
	requestTimeout time.Duration

	mu             sync.RWMutex
	http           *http.Client
	transport      *http.Transport
	tls            *tls.Config
	releaseVersion string
}

func newAPIClient(relayURL *url.URL, requestTimeout time.Duration) *apiClient {
	return &apiClient{relayURL: relayURL, requestTimeout: requestTimeout}
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
func (c *apiClient) resetTransport() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	c.http = nil
	c.transport = nil
	c.tls = nil
}

func (c *apiClient) initHTTPTransport(ctx context.Context) error {
	c.mu.RLock()
	if c.http != nil {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()

	bootstrapCtx, cancel := context.WithTimeout(ctx, defaultDialTimeout+defaultHandshakeTimeout)
	defer cancel()

	tlsConfig, httpClient, httpTransport, err := utils.NewHTTPTLSClient(bootstrapCtx, c.relayURL, c.requestTimeout)
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

// register only performs the challenge and registration wire exchange.
// The caller prepares ECH feature inputs beforehand.
func (c *apiClient) register(ctx context.Context, registerReq types.RegisterChallengeRequest, reportedIP string) (types.RegisterResponse, error) {
	var challenge types.RegisterChallengeResponse
	if err := utils.HTTPDoAPIPath(ctx, c.httpClient(), c.relayURL, http.MethodPost, types.PathSDKRegisterChallenge, registerReq, nil, &challenge); err != nil {
		return types.RegisterResponse{}, err
	}

	authority := identity.NewLocalAuthority(registerReq.Identity)
	signature, err := authority.SignEthereumPersonalMessage(challenge.SIWEMessage)
	if err != nil {
		return types.RegisterResponse{}, err
	}

	var resp types.RegisterResponse
	if err := utils.HTTPDoAPIPath(ctx, c.httpClient(), c.relayURL, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{
		ChallengeID:   challenge.ChallengeID,
		SIWEMessage:   challenge.SIWEMessage,
		SIWESignature: signature,
		ReportedIP:    reportedIP,
	}, nil, &resp); err != nil {
		return types.RegisterResponse{}, err
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
				Str("relay_url", l.relayURL.String()).
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

func (c *apiClient) unregister(ctx context.Context, accessToken string) error {
	err := utils.HTTPDoAPIPath(ctx, c.httpClient(), c.relayURL, http.MethodPost, types.PathSDKUnregister, types.UnregisterRequest{
		AccessToken: accessToken,
	}, nil, nil)
	return err
}
