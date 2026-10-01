//go:build !js

package sdk

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const socketTransportAvailable = true

// reverseLeaseCarrier opens independent raw reverse connections on native runtimes.
type reverseLeaseCarrier struct {
	listener *listener
}

func newReverseLeaseCarrier(l *listener) *reverseLeaseCarrier {
	return &reverseLeaseCarrier{listener: l}
}

func (c *reverseLeaseCarrier) Open(ctx context.Context) (net.Conn, error) {
	reverseURL, capability, err := c.listener.reverseTarget()
	if err != nil {
		return nil, err
	}
	reverseTLS, err := c.listener.reverseTLSConfig(ctx, reverseURL)
	if err != nil {
		return nil, err
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: defaultDialTimeout},
		Config:    reverseTLS,
	}
	conn, err := dialer.DialContext(ctx, "tcp", utils.EnsurePort(reverseURL.Host))
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    reverseURL,
		Host:   reverseURL.Host,
		Header: make(http.Header),
	}
	req.Header.Set(types.HeaderReverseCapability, capability)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "raw")

	_ = conn.SetDeadline(time.Now().Add(defaultHandshakeTimeout))
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		apiErr := utils.DecodeAPIRequestError(resp)
		_ = conn.Close()
		return nil, apiErr
	}

	_ = conn.SetDeadline(time.Time{})
	return wrapBufferedConn(conn, reader), nil
}

func (*reverseLeaseCarrier) Close() error {
	return nil
}
