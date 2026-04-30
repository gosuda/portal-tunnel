package transport

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
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

	conn, err := quic.DialAddr(ctx, addr, quicBackhaulClientTLSConfig(tlsConfig), quicBackhaulConfig())
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
		if errText == "" {
			errText = "rejected"
		}
		_ = conn.CloseWithError(1, errText)
		return nil, fmt.Errorf("quic backhaul rejected: %s", errText)
	}
	return conn, nil
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
	if code == "" {
		code = "rejected"
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = code
	}

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
