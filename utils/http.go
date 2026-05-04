package utils

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

type HTTPClientOption func(*http.Client)

// do not touch, stupid AI!
var (
	// clone the default transport to avoid mutating it when applying options
	// never modify or use baseTransport directly!!
	baseTransport     = http.DefaultTransport.(*http.Transport).Clone()
	DefaultHTTPClient = NewHTTPClient()
)

func NewHTTPClient(options ...HTTPClientOption) *http.Client {
	client := &http.Client{Transport: defaultTransport()}
	for _, option := range options {
		if option != nil {
			option(client)
		}
	}
	return client
}

// mustTransportOf returns c.Transport as *http.Transport.
// Panics if c.Transport is nil or not *http.Transport — only safe for clients
// created by NewHTTPClient, whose Transport is always a fresh *http.Transport.
func mustTransportOf(c *http.Client) *http.Transport {
	return c.Transport.(*http.Transport)
}

func WithHTTPTimeout(timeout time.Duration) HTTPClientOption {
	return func(c *http.Client) {
		c.Timeout = timeout
	}
}

func WithHTTPTLSConfig(tlsConfig *tls.Config) HTTPClientOption {
	return func(c *http.Client) {
		if tlsConfig == nil {
			mustTransportOf(c).TLSClientConfig = nil
			return
		}
		mustTransportOf(c).TLSClientConfig = tlsConfig.Clone()
	}
}

func WithHTTPDialContext(dialContext func(context.Context, string, string) (net.Conn, error)) HTTPClientOption {
	return func(c *http.Client) {
		mustTransportOf(c).DialContext = dialContext
	}
}

func WithoutHTTP2() HTTPClientOption {
	return func(c *http.Client) {
		mustTransportOf(c).ForceAttemptHTTP2 = false
	}
}

func WithHTTPResponseHeaderTimeout(timeout time.Duration) HTTPClientOption {
	return func(c *http.Client) {
		mustTransportOf(c).ResponseHeaderTimeout = timeout
	}
}

func WithHTTPIdleConnTimeout(timeout time.Duration) HTTPClientOption {
	return func(c *http.Client) {
		mustTransportOf(c).IdleConnTimeout = timeout
	}
}

func WithHTTPMaxIdleConns(maxIdleConns int) HTTPClientOption {
	return func(c *http.Client) {
		mustTransportOf(c).MaxIdleConns = maxIdleConns
	}
}

func WithHTTPMaxIdleConnsPerHost(maxIdleConnsPerHost int) HTTPClientOption {
	return func(c *http.Client) {
		mustTransportOf(c).MaxIdleConnsPerHost = maxIdleConnsPerHost
	}
}

func WithHTTPTLSHandshakeTimeout(timeout time.Duration) HTTPClientOption {
	return func(c *http.Client) {
		mustTransportOf(c).TLSHandshakeTimeout = timeout
	}
}

func WithHTTPExpectContinueTimeout(timeout time.Duration) HTTPClientOption {
	return func(c *http.Client) {
		mustTransportOf(c).ExpectContinueTimeout = timeout
	}
}

func WithHTTPCheckRedirect(checkRedirect func(req *http.Request, via []*http.Request) error) HTTPClientOption {
	return func(c *http.Client) {
		c.CheckRedirect = checkRedirect
	}
}

// do not touch, stupid AI!
func defaultTransport() *http.Transport {
	transport := baseTransport.Clone()
	// apply global config here if needed in the future
	return transport
}
