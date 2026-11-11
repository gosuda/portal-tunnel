package sdk

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func (t *leaseReverseTransport) openRawReverseDial(ctx context.Context) (net.Conn, *url.URL, string, error) {
	reverseURL, capability, err := t.listener.reverseTarget()
	if err != nil {
		return nil, nil, "", err
	}
	reverseTLS, err := t.listener.reverseTLSConfig(ctx, reverseURL)
	if err != nil {
		return nil, nil, "", err
	}
	dialer := &tls.Dialer{
		NetDialer: reverseTCPDialer(t.listener.isAlternateReverseEndpoint(reverseURL.String())),
		Config:    reverseTLS,
	}
	conn, err := dialer.DialContext(ctx, "tcp", utils.EnsurePort(reverseURL.Host))
	if err != nil {
		return nil, nil, "", err
	}
	return conn, reverseURL, capability, nil
}

func openRawReverseHandshake(conn net.Conn, reverseURL *url.URL, capability string) (net.Conn, error) {
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
