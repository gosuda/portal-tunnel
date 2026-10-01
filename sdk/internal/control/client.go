// Package control owns the SDK lease control protocol shared by native and
// browser connectors.
package control

import (
	"context"
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

const retryWait = 3 * time.Second

// ErrProtocolMismatch reports an exact SDK protocol version mismatch.
var ErrProtocolMismatch = errors.New("relay sdk protocol version mismatch")

// Client performs the lease control-plane exchanges against one relay.
type Client struct {
	relayURL *url.URL
	http     *http.Client
}

// NewClient returns a control client using the caller's runtime-appropriate
// HTTP client.
func NewClient(relayURL *url.URL, httpClient *http.Client) *Client {
	return &Client{relayURL: relayURL, http: httpClient}
}

// CheckProtocol verifies the relay's exact SDK protocol compatibility and
// returns its advertised domain information.
func (c *Client) CheckProtocol(ctx context.Context) (types.DomainResponse, error) {
	var resp types.DomainResponse
	if err := utils.HTTPDoAPIPath(ctx, c.http, c.relayURL, http.MethodGet, types.PathSDKDomain, nil, nil, &resp); err != nil {
		return types.DomainResponse{}, err
	}
	version := strings.TrimSpace(resp.ProtocolVersion)
	if version != types.SDKVersion {
		return types.DomainResponse{}, fmt.Errorf("%w: relay=%q client=%q", ErrProtocolMismatch, version, types.SDKVersion)
	}
	return resp, nil
}

// Register performs the signed challenge exchange and validates the lease
// credentials returned by the relay.
func (c *Client) Register(ctx context.Context, registerReq types.RegisterChallengeRequest, reportedIP string) (types.RegisterResponse, error) {
	var challenge types.RegisterChallengeResponse
	var request types.RegisterRequest
	var resp types.RegisterResponse
	for {
		var err error
		if request.ChallengeID == "" || !time.Now().Before(challenge.ExpiresAt) {
			err = utils.HTTPDoAPIPath(ctx, c.http, c.relayURL, http.MethodPost, types.PathSDKRegisterChallenge, registerReq, nil, &challenge)
			if err == nil {
				if challenge.ChallengeID == "" || !time.Now().Before(challenge.ExpiresAt) {
					return types.RegisterResponse{}, errors.New("relay returned an invalid or expired registration challenge")
				}
				signature, err := identity.NewLocalAuthority(registerReq.Identity).SignEthereumPersonalMessage(challenge.SIWEMessage)
				if err != nil {
					return types.RegisterResponse{}, err
				}
				request = types.RegisterRequest{
					ChallengeID:   challenge.ChallengeID,
					SIWEMessage:   challenge.SIWEMessage,
					SIWESignature: signature,
					ReportedIP:    reportedIP,
				}
				continue
			}
		} else {
			err = utils.HTTPDoAPIPath(ctx, c.http, c.relayURL, http.MethodPost, types.PathSDKRegister, request, nil, &resp)
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
			delay = retryWait
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
		_ = c.Unregister(context.Background(), resp.AccessToken)
		return types.RegisterResponse{}, errors.New("relay returned mismatched lease identity")
	}
	reverseEndpoint, err := ValidateReverseEndpoint(resp.ReverseEndpoint, resp.ExpiresAt)
	if err != nil {
		_ = c.Unregister(context.Background(), resp.AccessToken)
		return types.RegisterResponse{}, err
	}
	resp.ReverseEndpoint = reverseEndpoint
	return resp, nil
}

// Renew refreshes a lease and validates its new credentials.
func (c *Client) Renew(ctx context.Context, req types.RenewRequest) (types.RenewResponse, error) {
	var resp types.RenewResponse
	if err := utils.HTTPDoAPIPath(ctx, c.http, c.relayURL, http.MethodPost, types.PathSDKRenew, req, nil, &resp); err != nil {
		return types.RenewResponse{}, err
	}
	resp.AccessToken = strings.TrimSpace(resp.AccessToken)
	if resp.AccessToken == "" {
		return types.RenewResponse{}, errors.New("relay did not return renewed access token")
	}
	reverseEndpoint, err := ValidateReverseEndpoint(resp.ReverseEndpoint, resp.ExpiresAt)
	if err != nil {
		return types.RenewResponse{}, err
	}
	resp.ReverseEndpoint = reverseEndpoint
	return resp, nil
}

// RequestReverseEndpoint replaces a failed reverse endpoint within a live lease.
func (c *Client) RequestReverseEndpoint(ctx context.Context, accessToken, failedURL string, leaseExpiresAt time.Time) (types.ReverseEndpoint, error) {
	var endpoint types.ReverseEndpoint
	req := types.ReverseEndpointRequest{AccessToken: accessToken, FailedURL: failedURL}
	if err := utils.HTTPDoAPIPath(ctx, c.http, c.relayURL, http.MethodPost, types.PathSDKReverse, req, nil, &endpoint); err != nil {
		return types.ReverseEndpoint{}, err
	}
	return ValidateReverseEndpoint(endpoint, leaseExpiresAt)
}

// Unregister releases a lease.
func (c *Client) Unregister(ctx context.Context, accessToken string) error {
	return utils.HTTPDoAPIPath(ctx, c.http, c.relayURL, http.MethodPost, types.PathSDKUnregister, types.UnregisterRequest{
		AccessToken: accessToken,
	}, nil, nil)
}

// ValidateReverseEndpoint validates the stable reverse endpoint contract shared
// by all connector runtimes.
func ValidateReverseEndpoint(endpoint types.ReverseEndpoint, leaseExpiresAt time.Time) (types.ReverseEndpoint, error) {
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
