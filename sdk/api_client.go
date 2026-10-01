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

	"github.com/gosuda/portal-tunnel/v2/sdk/internal/control"
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

	domainResp, err := control.NewClient(c.relayURL, httpClient).CheckProtocol(ctx)
	if err != nil {
		httpTransport.CloseIdleConnections()
		if errors.Is(err, control.ErrProtocolMismatch) {
			return fmt.Errorf("%w: %w", errRelayIncompatible, err)
		}
		return fmt.Errorf("check relay compatibility: %w", err)
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
	return control.NewClient(c.relayURL, c.httpClient()).Register(ctx, registerReq, reportedIP)
}

func (c *apiClient) renew(ctx context.Context, req types.RenewRequest) (types.RenewResponse, error) {
	return control.NewClient(c.relayURL, c.httpClient()).Renew(ctx, req)
}

func (c *apiClient) requestReverseEndpoint(ctx context.Context, accessToken, failedURL string, leaseExpiresAt time.Time) (types.ReverseEndpoint, error) {
	return control.NewClient(c.relayURL, c.httpClient()).RequestReverseEndpoint(ctx, accessToken, failedURL, leaseExpiresAt)
}

func (c *apiClient) unregister(ctx context.Context, accessToken string) error {
	return control.NewClient(c.relayURL, c.httpClient()).Unregister(ctx, accessToken)
}
