package sdk

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"

	"github.com/gosuda/keyless_tls/relay/l4"

	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/localtls"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var errTLSNameOutsideLease = errors.New("TLS server name is outside this service lease")

// tenantTLSClient is the lease lifecycle shared by the legacy Keyless engine
// and the independently owned canonical Local TLS endpoint.
type tenantTLSClient interface {
	TerminateConn(context.Context, net.Conn, []byte) (net.Conn, error)
	RefreshChain(context.Context) (bool, error)
	TenantTLSConfig() *tls.Config
	TenantCertPool() *x509.CertPool
	SetAccessToken(string)
	Close() error
}

type namespaceTLS struct {
	local          *localtls.Client
	legacy         *keyless.Client
	hostname       string
	legacyHostname string
	aliasHostname  string
}

func (c *namespaceTLS) TerminateConn(ctx context.Context, conn net.Conn, binding []byte) (net.Conn, error) {
	hello, buffered, err := l4.InspectClientHello(conn, defaultHandshakeTimeout)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	hostname := utils.NormalizeHostname(hello.ServerName)
	if hostname == c.hostname {
		return c.local.TerminateConn(ctx, buffered, binding)
	}
	if hostname == "" || (hostname != c.legacyHostname && hostname != c.aliasHostname) {
		_ = buffered.Close()
		return nil, errTLSNameOutsideLease
	}
	return c.legacy.TerminateConn(ctx, buffered, binding)
}

func (c *namespaceTLS) TenantTLSConfig() *tls.Config   { return c.local.TenantTLSConfig() }
func (c *namespaceTLS) TenantCertPool() *x509.CertPool { return c.local.TenantCertPool() }
func (c *namespaceTLS) SetAccessToken(token string) {
	c.legacy.SetAccessToken(token)
	c.local.SetAccessToken(token)
}
func (c *namespaceTLS) RefreshChain(ctx context.Context) (bool, error) {
	a, aerr := c.legacy.RefreshChain(ctx)
	b, berr := c.local.RefreshChain(ctx)
	return a || b, errors.Join(aerr, berr)
}
func (c *namespaceTLS) Close() error { return errors.Join(c.local.Close(), c.legacy.Close()) }

// enableHTTP2 is called by the HTTP consumer, never by the raw stream API.
func (e *Exposure) enableHTTP2() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.http2Enabled = true
	for _, listener := range e.relayListeners {
		listener.enableHTTP2()
	}
}

func (l *listener) enableHTTP2() {
	l.http2Enabled.Store(true)
	if lease, ok := l.leaseSnapshot(); ok {
		if endpoint, ok := lease.tenantTLS.(*namespaceTLS); ok {
			endpoint.local.SetNextProtos([]string{"h2", "http/1.1"})
		}
	}
}
