package sdk

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultDialTimeout         = 5 * time.Second
	defaultRequestTimeout      = 15 * time.Second
	defaultHandshakeTimeout    = 15 * time.Second
	defaultLeaseTTL            = 30 * time.Second
	defaultRenewBefore         = 30 * time.Second
	defaultReadyTarget         = 2
	defaultRetryWait           = 3 * time.Second
	defaultHTTPShutdownTimeout = 5 * time.Second
)

var errRelayIncompatible = errors.New("relay is incompatible")

type apiClient struct {
	mu               sync.RWMutex
	baseURL          *url.URL
	httpClient       *http.Client
	rawTLSConfig     *tls.Config
	dialTimeout      time.Duration
	requestTimeout   time.Duration
	rootCAPEM        []byte
	identity         types.Identity
	accessToken      string
	metadata         types.LeaseMetadata
	resolvedPublicIP string
	sniPort          int
}

func newApiClient(relayURL string, cfg ListenerConfig) (*apiClient, error) {
	normalizedRelayURL, err := utils.NormalizeRelayURL(relayURL)
	if err != nil {
		return nil, err
	}
	baseURL, err := url.Parse(normalizedRelayURL)
	if err != nil {
		return nil, fmt.Errorf("parse relay url: %w", err)
	}

	dialTimeout := utils.DurationOrDefault(cfg.DialTimeout, defaultDialTimeout)
	requestTimeout := utils.DurationOrDefault(cfg.RequestTimeout, defaultRequestTimeout)

	return &apiClient{
		baseURL:        baseURL,
		dialTimeout:    dialTimeout,
		requestTimeout: requestTimeout,
		rootCAPEM:      append([]byte(nil), cfg.RootCAPEM...),
		identity:       cfg.Identity.Copy(),
		metadata:       cfg.Metadata.Copy(),
	}, nil
}

func (a *apiClient) close() {
	if a == nil || a.httpClient == nil {
		return
	}
	if transport, ok := a.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (a *apiClient) registerLease(ctx context.Context, ttl time.Duration, udpEnabled, tcpEnabled bool) (types.RegisterResponse, error) {
	if err := a.ensureHTTPClient(ctx); err != nil {
		return types.RegisterResponse{}, err
	}

	var challenge types.RegisterChallengeResponse
	challengeReq := types.RegisterChallengeRequest{
		Identity:   a.identity.Copy(),
		Metadata:   a.metadata.Copy(),
		TTL:        int(ttl / time.Second),
		UDPEnabled: udpEnabled,
		TCPEnabled: tcpEnabled,
	}
	if err := utils.HTTPDoAPIPath(ctx, a.httpClient, a.baseURL, http.MethodPost, types.PathSDKRegisterChallenge, challengeReq, nil, &challenge); err != nil {
		return types.RegisterResponse{}, err
	}

	signature, err := utils.SignEthereumPersonalMessage(challenge.SIWEMessage, a.identity.PrivateKey)
	if err != nil {
		return types.RegisterResponse{}, err
	}

	var resp types.RegisterResponse
	if err := utils.HTTPDoAPIPath(ctx, a.httpClient, a.baseURL, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{
		ChallengeID:   challenge.ChallengeID,
		SIWEMessage:   challenge.SIWEMessage,
		SIWESignature: signature,
		ReportedIP:    a.reportedIP(ctx),
	}, nil, &resp); err != nil {
		return types.RegisterResponse{}, err
	}
	resp.AccessToken = strings.TrimSpace(resp.AccessToken)
	if resp.AccessToken == "" {
		return types.RegisterResponse{}, errors.New("relay did not return access token")
	}
	registeredIdentity, err := utils.NormalizeIdentity(resp.Identity)
	if err != nil {
		return types.RegisterResponse{}, err
	}
	if registeredIdentity.Key() != a.identity.Key() {
		return types.RegisterResponse{}, errors.New("relay returned mismatched lease identity")
	}
	resp.Identity = registeredIdentity

	sniPort := 0
	if udpEnabled {
		if resp.SNIPort <= 0 {
			return types.RegisterResponse{}, errors.New("relay did not return sni port for udp transport")
		}
		sniPort = resp.SNIPort
	}

	a.mu.Lock()
	a.accessToken = resp.AccessToken
	a.sniPort = sniPort
	a.mu.Unlock()
	return resp, nil
}

func (a *apiClient) ensureHTTPClient(ctx context.Context) error {
	if a.httpClient != nil && a.rawTLSConfig != nil {
		return nil
	}

	bootstrapCtx, cancel := context.WithTimeout(ctx, defaultDialTimeout+defaultHandshakeTimeout)
	defer cancel()

	rawTLSConfig, httpClient, err := keyless.NewRelayHTTPClient(bootstrapCtx, a.baseURL, a.rootCAPEM, a.requestTimeout)
	if err != nil {
		return err
	}
	if err := a.ensureCompatible(ctx, httpClient); err != nil {
		if transport, ok := httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
		a.close()
		return err
	}

	a.close()
	a.httpClient = httpClient
	a.rawTLSConfig = rawTLSConfig

	return nil
}

func (a *apiClient) reportedIP(ctx context.Context) string {
	if a.resolvedPublicIP == "" {
		a.resolvedPublicIP = utils.ResolvePublicIP(ctx)
	}
	return a.resolvedPublicIP
}

func (a *apiClient) ensureCompatible(ctx context.Context, httpClient *http.Client) error {
	var resp types.DomainResponse
	if err := utils.HTTPDoAPIPath(ctx, httpClient, a.baseURL, http.MethodGet, types.PathSDKDomain, nil, nil, &resp); err != nil {
		err = fmt.Errorf("check relay compatibility: %w", err)
		var netErr net.Error
		var apiErr *types.APIRequestError
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) {
			return err
		}
		if errors.As(err, &apiErr) && apiErr.StatusCode >= 500 {
			return err
		}
		return fmt.Errorf("%w: %w", errRelayIncompatible, err)
	}
	protocolVersion := strings.TrimSpace(resp.ProtocolVersion)
	if protocolVersion != types.ProtocolVersion {
		return fmt.Errorf("%w: relay protocol version mismatch: relay=%q client=%q", errRelayIncompatible, protocolVersion, types.ProtocolVersion)
	}
	return nil
}

func (a *apiClient) renewLease(ctx context.Context, ttl time.Duration) error {
	if err := a.ensureHTTPClient(ctx); err != nil {
		return err
	}

	a.mu.RLock()
	accessToken := a.accessToken
	a.mu.RUnlock()
	if strings.TrimSpace(accessToken) == "" {
		return errors.New("access token is not available")
	}

	var resp types.RenewResponse
	if err := utils.HTTPDoAPIPath(ctx, a.httpClient, a.baseURL, http.MethodPost, types.PathSDKRenew, types.RenewRequest{
		AccessToken: accessToken,
		TTL:         int(ttl / time.Second),
		ReportedIP:  a.reportedIP(ctx),
	}, nil, &resp); err != nil {
		return err
	}
	resp.AccessToken = strings.TrimSpace(resp.AccessToken)
	if resp.AccessToken == "" {
		return errors.New("relay did not return renewed access token")
	}

	a.mu.Lock()
	if a.accessToken == accessToken {
		a.accessToken = resp.AccessToken
	}
	a.mu.Unlock()
	return nil
}

func (a *apiClient) unregisterLease(ctx context.Context) error {
	a.mu.RLock()
	accessToken := a.accessToken
	a.mu.RUnlock()
	return utils.HTTPDoAPIPath(ctx, a.httpClient, a.baseURL, http.MethodPost, types.PathSDKUnregister, types.UnregisterRequest{
		AccessToken: accessToken,
	}, nil, nil)
}

func (a *apiClient) openReverseSession(ctx context.Context) (net.Conn, error) {
	if err := a.ensureHTTPClient(ctx); err != nil {
		return nil, err
	}
	tlsConn, err := a.dialTLS(ctx)
	if err != nil {
		return nil, err
	}
	conn := tlsConn

	req := &http.Request{
		Method: http.MethodGet,
		URL:    utils.ResolveAPIURL(a.baseURL, types.PathSDKConnect),
		Host:   a.baseURL.Host,
		Header: make(http.Header),
	}
	a.mu.RLock()
	accessToken := a.accessToken
	a.mu.RUnlock()
	req.Header.Set(types.HeaderAccessToken, accessToken)
	req.Header.Set("Connection", "keep-alive")

	if writeErr := req.Write(conn); writeErr != nil {
		_ = conn.Close()
		return nil, writeErr
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		apiErr := utils.DecodeAPIRequestError(resp)
		_ = conn.Close()
		return nil, apiErr
	}

	return wrapBufferedConn(conn, reader), nil
}

func (a *apiClient) dialTLS(ctx context.Context) (net.Conn, error) {
	rawConn, err := a.dialRelayConn(ctx)
	if err != nil {
		return nil, err
	}
	tlsConf := a.rawTLSConfig.Clone()
	conn := tls.Client(rawConn, tlsConf)
	if err := conn.HandshakeContext(ctx); err != nil {
		closeErr := conn.Close()
		if closeErr != nil {
			return nil, errors.Join(fmt.Errorf("tls handshake failed: %w", err), fmt.Errorf("close tls conn: %w", closeErr))
		}
		return nil, fmt.Errorf("tls handshake failed: %w", err)
	}
	return conn, nil
}

func (a *apiClient) dialRelayConn(ctx context.Context) (net.Conn, error) {
	targetAddr := utils.EnsurePort(a.baseURL.Host)
	dialer := &net.Dialer{Timeout: a.dialTimeout}
	return dialer.DialContext(ctx, "tcp", targetAddr)
}

type bufferedConn struct {
	net.Conn
	reader *bytes.Reader
}

func wrapBufferedConn(conn net.Conn, reader *bufio.Reader) net.Conn {
	if reader == nil || reader.Buffered() == 0 {
		return conn
	}
	buf := make([]byte, reader.Buffered())
	if _, err := io.ReadFull(reader, buf); err != nil {
		return conn
	}
	return &bufferedConn{Conn: conn, reader: bytes.NewReader(buf)}
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if c.reader != nil && c.reader.Len() > 0 {
		return c.reader.Read(p)
	}
	return c.Conn.Read(p)
}

// openQUICSession opens a QUIC connection to the relay for datagram transport.
func (a *apiClient) openQUICSession(ctx context.Context, accessToken string) (*quic.Conn, error) {
	if err := a.ensureHTTPClient(ctx); err != nil {
		return nil, err
	}

	tlsConf := a.rawTLSConfig.Clone()
	tlsConf.NextProtos = []string{"portal-tunnel"}

	quicConf := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 15 * time.Second,
		MaxIdleTimeout:  60 * time.Second,
	}

	a.mu.RLock()
	sniPort := a.sniPort
	a.mu.RUnlock()

	if sniPort <= 0 {
		return nil, errors.New("sni port is not available")
	}
	host := strings.TrimSpace(a.baseURL.Hostname())
	if host == "" {
		host = strings.TrimSpace(a.baseURL.Host)
	}
	dialAddr := net.JoinHostPort(host, fmt.Sprintf("%d", sniPort))
	conn, err := quic.DialAddr(ctx, dialAddr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(1, "stream open failed")
		return nil, fmt.Errorf("open control stream: %w", err)
	}

	controlMsg := types.QUICControlMessage{
		AccessToken: accessToken,
	}
	if err := json.NewEncoder(stream).Encode(controlMsg); err != nil {
		_ = conn.CloseWithError(1, "control write failed")
		return nil, fmt.Errorf("write control: %w", err)
	}

	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	var resp types.QUICControlResponse
	if err := json.NewDecoder(io.LimitReader(stream, 4096)).Decode(&resp); err != nil {
		_ = conn.CloseWithError(1, "control read failed")
		return nil, fmt.Errorf("read control response: %w", err)
	}
	if !resp.OK {
		_ = conn.CloseWithError(1, resp.Error)
		return nil, fmt.Errorf("quic connect rejected: %s", resp.Error)
	}

	return conn, nil
}
