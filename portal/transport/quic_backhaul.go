package transport

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	quicBackhaulALPN             = "portal-tunnel"
	quicBackhaulControlTimeout   = 10 * time.Second
	quicBackhaulControlBodyLimit = 4096
)

type quicBackhaulControlMessage struct {
	AccessToken string `json:"access_token"`
}

type quicBackhaulControlResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type QUICBackhaulControl struct {
	AccessToken string
	conn        *quic.Conn
	stream      *quic.Stream
}

func ListenQUICBackhaul(addr string, cert tls.Certificate) (*quic.Listener, error) {
	listener, err := quic.ListenAddr(addr, quicBackhaulServerTLSConfig(cert), quicBackhaulConfig())
	if err != nil {
		return nil, fmt.Errorf("listen quic backhaul: %w", err)
	}
	return listener, nil
}

func DialQUICBackhaul(ctx context.Context, addr string, tlsConfig *tls.Config, accessToken string) (*quic.Conn, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, errors.New("quic backhaul access token is required")
	}

	conn, err := dialQUICBackhaulConnection(ctx, addr, quicBackhaulClientTLSConfig(tlsConfig))
	if err != nil {
		return nil, fmt.Errorf("dial quic backhaul: %w", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(1, "control stream open failed")
		return nil, fmt.Errorf("open quic backhaul control stream: %w", err)
	}

	_ = stream.SetDeadline(time.Now().Add(quicBackhaulControlTimeout))
	if err := json.NewEncoder(stream).Encode(quicBackhaulControlMessage{AccessToken: accessToken}); err != nil {
		_ = conn.CloseWithError(1, "control write failed")
		return nil, fmt.Errorf("write quic backhaul control message: %w", err)
	}

	var resp quicBackhaulControlResponse
	if err := json.NewDecoder(io.LimitReader(stream, quicBackhaulControlBodyLimit)).Decode(&resp); err != nil {
		_ = conn.CloseWithError(1, "control response read failed")
		return nil, fmt.Errorf("read quic backhaul control response: %w", err)
	}
	_ = stream.SetDeadline(time.Time{})
	_ = stream.Close()

	if !resp.OK {
		errText := strings.TrimSpace(resp.Error)
		errText = cmp.Or(errText, "rejected")
		_ = conn.CloseWithError(1, errText)
		if code := backhaulRejectionCode(errText); code != "" {
			return nil, fmt.Errorf("quic backhaul rejected: %w", &types.APIRequestError{Code: code})
		}
		return nil, fmt.Errorf("quic backhaul rejected: %s", errText)
	}
	return conn, nil
}

// dialQUICBackhaulConnection preserves resolver address ordering and races the
// other address family after the same 300 ms head start as Go's TCP dialer.
// quic.DialAddr otherwise resolves only one address and prefers IPv4.
func dialQUICBackhaulConnection(ctx context.Context, addr string, tlsConfig *tls.Config) (*quic.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, &net.DNSError{Err: "no addresses found", Name: host, IsNotFound: true}
	}
	if tlsConfig.ServerName == "" {
		// Numeric dial targets must still authenticate the requested hostname.
		tlsConfig.ServerName = host
	}

	var primary, fallback []net.IPAddr
	primaryIPv4 := addresses[0].IP.To4() != nil
	for _, address := range addresses {
		if (address.IP.To4() != nil) == primaryIPv4 {
			primary = append(primary, address)
		} else {
			fallback = append(fallback, address)
		}
	}
	dial := func(ctx context.Context, addresses []net.IPAddr) (*quic.Conn, error) {
		var firstErr error
		for i, address := range addresses {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			attemptCtx := ctx
			cancel := func() {}
			if deadline, ok := ctx.Deadline(); ok {
				// Leave later addresses a share of the caller's remaining budget.
				attemptCtx, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(addresses)-i))
			}
			conn, err := quic.DialAddr(attemptCtx, net.JoinHostPort(address.String(), port), tlsConfig, quicBackhaulConfig())
			cancel()
			if err == nil {
				return conn, nil
			}
			if firstErr == nil {
				firstErr = err
			}
		}
		return nil, firstErr
	}
	if len(fallback) == 0 {
		return dial(ctx, primary)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	returned := make(chan struct{})
	defer close(returned)
	type result struct {
		conn *quic.Conn
		err  error
	}
	results := make(chan result)
	race := func(addresses []net.IPAddr) {
		conn, err := dial(ctx, addresses)
		select {
		case results <- result{conn: conn, err: err}:
		case <-returned:
			if conn != nil {
				_ = conn.CloseWithError(0, "another relay address connected")
			}
		}
	}
	go race(primary)
	timer := time.NewTimer(300 * time.Millisecond)
	defer timer.Stop()
	fallbackStarted := false
	var firstErr error
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			fallbackStarted = true
			go race(fallback)
		case result := <-results:
			if result.err == nil {
				return result.conn, nil
			}
			if firstErr != nil {
				return nil, errors.Join(firstErr, result.err)
			}
			firstErr = result.err
			if !fallbackStarted {
				timer.Stop()
				fallbackStarted = true
				go race(fallback)
			}
		}
	}
}

// backhaulRejectionCode maps a backhaul control rejection reason back to
// its relay API error code so callers classify rejections with errors.Is
// against types.APIRequestError like every other relay response.
func backhaulRejectionCode(errText string) string {
	switch errText {
	case types.APIErrorCodeUnauthorized,
		types.APIErrorCodeLeaseNotFound,
		types.APIErrorCodeLeaseRejected,
		types.APIErrorCodeTransportMismatch,
		types.APIErrorCodeInvalidRequest:
		return errText
	}
	return ""
}

func AcceptQUICBackhaulControl(ctx context.Context, conn *quic.Conn) (*QUICBackhaulControl, error) {
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("accept quic backhaul control stream: %w", err)
	}

	_ = stream.SetReadDeadline(time.Now().Add(quicBackhaulControlTimeout))
	var msg quicBackhaulControlMessage
	if err := json.NewDecoder(io.LimitReader(stream, quicBackhaulControlBodyLimit)).Decode(&msg); err != nil {
		return nil, fmt.Errorf("read quic backhaul control message: %w", err)
	}
	_ = stream.SetReadDeadline(time.Time{})

	accessToken := strings.TrimSpace(msg.AccessToken)
	if accessToken == "" {
		return nil, errors.New("quic backhaul access token is required")
	}

	return &QUICBackhaulControl{
		AccessToken: accessToken,
		conn:        conn,
		stream:      stream,
	}, nil
}

func (c *QUICBackhaulControl) Accept() error {
	if c == nil || c.stream == nil {
		return nil
	}
	err := json.NewEncoder(c.stream).Encode(quicBackhaulControlResponse{OK: true})
	return errors.Join(err, c.stream.Close())
}

func (c *QUICBackhaulControl) Reject(code, reason string) error {
	if c == nil || c.conn == nil {
		return nil
	}
	code = strings.TrimSpace(code)
	code = cmp.Or(code, "rejected")
	reason = strings.TrimSpace(reason)
	reason = cmp.Or(reason, code)

	var err error
	if c.stream != nil {
		err = errors.Join(
			json.NewEncoder(c.stream).Encode(quicBackhaulControlResponse{OK: false, Error: code}),
			c.stream.Close(),
		)
	}
	return errors.Join(err, c.conn.CloseWithError(1, reason))
}

func quicBackhaulServerTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{quicBackhaulALPN},
		MinVersion:   tls.VersionTLS13,
	}
}

func quicBackhaulClientTLSConfig(base *tls.Config) *tls.Config {
	if base == nil {
		return &tls.Config{
			NextProtos: []string{quicBackhaulALPN},
			MinVersion: tls.VersionTLS13,
		}
	}

	cfg := base.Clone()
	cfg.NextProtos = []string{quicBackhaulALPN}
	if cfg.MinVersion == 0 || cfg.MinVersion < tls.VersionTLS13 {
		cfg.MinVersion = tls.VersionTLS13
	}
	return cfg
}

func quicBackhaulConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:    true,
		KeepAlivePeriod:    15 * time.Second,
		MaxIdleTimeout:     60 * time.Second,
		MaxIncomingStreams: 16,
	}
}
