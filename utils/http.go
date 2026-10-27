package utils

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

type HTTPClientOption func(*http.Client)

// DelHeaderSpellings removes the named headers from h in every spelling a
// gateway may read as the same header: any letter case, and underscores in
// place of hyphens. CGI-style upstreams (WSGI, PHP, nginx) turn X_Portal_User
// and X-Portal-User into the same variable, so deleting only the canonical
// spelling would let a client send the one the gateway did not remove.
func DelHeaderSpellings(h http.Header, names ...string) {
	for key := range h {
		if slices.ContainsFunc(names, func(name string) bool { return sameHeaderName(key, name) }) {
			delete(h, key)
		}
	}
}

func sameHeaderName(a, b string) bool {
	return strings.EqualFold(strings.ReplaceAll(a, "_", "-"), strings.ReplaceAll(b, "_", "-"))
}

var (
	// Each client clones this baseline before applying options.
	baseTransport     = http.DefaultTransport.(*http.Transport).Clone()
	DefaultHTTPClient = NewHTTPClient()
)

func NewHTTPClient(options ...HTTPClientOption) *http.Client {
	client := &http.Client{Transport: baseTransport.Clone()}
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

func WithHTTPCheckRedirect(checkRedirect func(req *http.Request, via []*http.Request) error) HTTPClientOption {
	return func(c *http.Client) {
		c.CheckRedirect = checkRedirect
	}
}
