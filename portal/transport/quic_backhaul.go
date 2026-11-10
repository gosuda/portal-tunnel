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

var errQUICBackhaulAccessTokenRequired = errors.New("quic backhaul access token is required")

const (
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

func ListenQUICBackhaul(addr string, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) (*quic.Listener, error) {
	listener, err := quic.ListenAddr(addr, quicBackhaulServerTLSConfig(getCertificate), quicBackhaulConfig())
	if err != nil {
		return nil, fmt.Errorf("listen quic backhaul: %w", err)
	}
	return listener, nil
}

func DialQUICBackhaul(ctx context.Context, addr string, tlsConfig *tls.Config, accessToken string) (*quic.Conn, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, errQUICBackhaulAccessTokenRequired
	}

	conn, err := dialQUICBackhaulConnection(ctx, addr, quicBackhaulClientTLSConfig(tlsConfig))
	if err != nil {
		return nil, fmt.Errorf("dial quic backhaul: %w", err)
	}
	if err := authorizeBackhaulControl(ctx, conn, accessToken); err != nil {
		return nil, err
	}
	return conn, nil
}

func authorizeBackhaulControl(ctx context.Context, conn *quic.Conn, accessToken string) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(1, "control stream open failed")
		return fmt.Errorf("open quic backhaul control stream: %w", err)
	}
	_ = stream.SetDeadline(time.Now().Add(quicBackhaulControlTimeout))
	if err := json.NewEncoder(stream).Encode(quicBackhaulControlMessage{AccessToken: accessToken}); err != nil {
		_ = conn.CloseWithError(1, "control write failed")
		return fmt.Errorf("write quic backhaul control message: %w", err)
	}
	var resp quicBackhaulControlResponse
	if err := json.NewDecoder(io.LimitReader(stream, quicBackhaulControlBodyLimit)).Decode(&resp); err != nil {
		_ = conn.CloseWithError(1, "control response read failed")
		return fmt.Errorf("read quic backhaul control response: %w", err)
	}
	_ = stream.SetDeadline(time.Time{})
	_ = stream.Close()
	if !resp.OK {
		errText := strings.TrimSpace(resp.Error)
		errText = cmp.Or(errText, "rejected")
		_ = conn.CloseWithError(1, errText)
		if code := backhaulRejectionCode(errText); code != "" {
			return fmt.Errorf("quic backhaul rejected: %w", &types.APIRequestError{Code: code})
		}
		return fmt.Errorf("quic backhaul rejected: %s", errText)
	}
	return nil
}

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
		tlsConfig.ServerName = host
	}

	primary, fallback := splitBackhaulAddresses(addresses)
	if len(fallback) == 0 {
		return dialBackhaulAddresses(ctx, primary, port, tlsConfig)
	}
	return raceBackhaulDial(ctx, primary, fallback, port, tlsConfig)
}

func splitBackhaulAddresses(addresses []net.IPAddr) (primary, fallback []net.IPAddr) {
	primaryIPv4 := addresses[0].IP.To4() != nil
	for _, address := range addresses {
		if (address.IP.To4() != nil) == primaryIPv4 {
			primary = append(primary, address)
		} else {
			fallback = append(fallback, address)
		}
	}
	return primary, fallback
}

func dialBackhaulAddresses(ctx context.Context, addresses []net.IPAddr, port string, tlsConfig *tls.Config) (*quic.Conn, error) {
	var firstErr error
	for i, address := range addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attemptCtx := ctx
		cancel := func() {}
		if deadline, ok := ctx.Deadline(); ok {
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

func raceBackhaulDial(ctx context.Context, primary, fallback []net.IPAddr, port string, tlsConfig *tls.Config) (*quic.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	returned := make(chan struct{})
	defer close(returned)
	results := make(chan backhaulRaceResult)
	delivery := backhaulRaceDelivery{results: results, returned: returned}
	go raceBackhaulAddresses(ctx, primary, port, tlsConfig, delivery)
	timer := time.NewTimer(300 * time.Millisecond)
	defer timer.Stop()
	startFallback := func() {
		go raceBackhaulAddresses(ctx, fallback, port, tlsConfig, delivery)
	}
	return awaitBackhaulRace(ctx, timer, results, startFallback)
}

type backhaulRaceResult struct {
	conn *quic.Conn
	err  error
}

type backhaulRaceDelivery struct {
	results  chan backhaulRaceResult
	returned chan struct{}
}

func raceBackhaulAddresses(ctx context.Context, addresses []net.IPAddr, port string, tlsConfig *tls.Config, delivery backhaulRaceDelivery) {
	conn, err := dialBackhaulAddresses(ctx, addresses, port, tlsConfig)
	select {
	case delivery.results <- backhaulRaceResult{conn: conn, err: err}:
	case <-delivery.returned:
		if conn != nil {
			_ = conn.CloseWithError(0, "another relay address connected")
		}
	}
}

func awaitBackhaulRace(ctx context.Context, timer *time.Timer, results <-chan backhaulRaceResult, startFallback func()) (*quic.Conn, error) {
	fallbackStarted := false
	var firstErr error
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			fallbackStarted = true
			startFallback()
		case result := <-results:
			nextFirstErr, retConn, retErr, done := settleBackhaulResult(firstErr, result)
			if done {
				return retConn, retErr
			}
			firstErr = nextFirstErr
			if !fallbackStarted {
				fallbackStarted = true
				timer.Stop()
				startFallback()
			}
		}
	}
}

func settleBackhaulResult(firstErr error, result backhaulRaceResult) (error, *quic.Conn, error, bool) {
	if result.err == nil {
		return firstErr, result.conn, nil, true
	}
	if firstErr != nil {
		return firstErr, nil, errors.Join(firstErr, result.err), true
	}
	return result.err, nil, nil, false
}

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
	ctx, cancel := context.WithTimeout(ctx, quicBackhaulControlTimeout)
	defer cancel()
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("accept quic backhaul control stream: %w", err)
	}

	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(1)
		close(canceled)
	})
	defer func() {
		if !stop() {
			<-canceled
		}
	}()
	var msg quicBackhaulControlMessage
	if err := json.NewDecoder(io.LimitReader(stream, quicBackhaulControlBodyLimit)).Decode(&msg); err != nil {
		return nil, fmt.Errorf("read quic backhaul control message: %w", err)
	}

	accessToken := strings.TrimSpace(msg.AccessToken)
	if accessToken == "" {
		return nil, errQUICBackhaulAccessTokenRequired
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

func quicBackhaulServerTLSConfig(getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		GetCertificate: getCertificate,
		NextProtos:     []string{types.QUICBackhaulALPN},
		MinVersion:     tls.VersionTLS13,
	}
}

func quicBackhaulClientTLSConfig(base *tls.Config) *tls.Config {
	if base == nil {
		return &tls.Config{
			NextProtos: []string{types.QUICBackhaulALPN},
			MinVersion: tls.VersionTLS13,
		}
	}

	cfg := base.Clone()
	cfg.NextProtos = []string{types.QUICBackhaulALPN}
	if cfg.MinVersion == 0 || cfg.MinVersion < tls.VersionTLS13 {
		cfg.MinVersion = tls.VersionTLS13
	}
	return cfg
}

func quicBackhaulConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:    true,
		InitialPacketSize:  types.QUICInitialPacketSize,
		KeepAlivePeriod:    15 * time.Second,
		MaxIdleTimeout:     60 * time.Second,
		MaxIncomingStreams: 16,
	}
}
