package overlay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	DefaultMTU                 = 1420
	DefaultListenPort          = 51820
	DefaultPeerAPIHTTPPort     = 7777
	DefaultPeerYamuxPort       = 7778
	DefaultPersistentKeepalive = 25

	maxHopTokenBytes    = 256
	defaultTokenTimeout = 2 * time.Second
)

type Config struct {
	PrivateKey string
	PublicKey  string
	ListenPort int
}

func (c Config) Copy() Config {
	return Config{
		PrivateKey: c.PrivateKey,
		PublicKey:  c.PublicKey,
		ListenPort: c.ListenPort,
	}
}

func NormalizeConfig(cfg Config) (Config, error) {
	configured := strings.TrimSpace(cfg.PrivateKey) != "" ||
		strings.TrimSpace(cfg.PublicKey) != "" ||
		cfg.ListenPort != 0
	if !configured {
		return cfg, nil
	}

	if strings.TrimSpace(cfg.PrivateKey) == "" {
		return Config{}, errors.New("wireguard private key is required when relay overlay is enabled")
	}

	privateKey, err := identity.NormalizeWireGuardPrivateKey(cfg.PrivateKey)
	if err != nil {
		return Config{}, fmt.Errorf("normalize wireguard private key: %w", err)
	}
	publicKey, err := identity.WireGuardPublicKeyFromPrivate(privateKey)
	if err != nil {
		return Config{}, fmt.Errorf("derive wireguard public key: %w", err)
	}
	if configuredPublicKey := strings.TrimSpace(cfg.PublicKey); configuredPublicKey != "" && configuredPublicKey != publicKey {
		return Config{}, errors.New("wireguard public key does not match private key")
	}

	cfg.PrivateKey = privateKey
	cfg.PublicKey = publicKey
	if cfg.ListenPort == 0 {
		cfg.ListenPort = DefaultListenPort
	}
	if cfg.ListenPort < 0 || cfg.ListenPort > 65535 {
		return Config{}, errors.New("wireguard listen port is invalid")
	}
	return cfg, nil
}

type HopStream struct {
	Conn       net.Conn
	Token      string
	RemoteAddr string
}

type StreamHandler func(ctx context.Context, stream HopStream)
type Overlay struct {
	cfg      Config
	stack    *stack
	listener net.Listener
	server   *http.Server
	client   *http.Client

	hopListener   net.Listener
	streamHandler atomic.Pointer[StreamHandler]
	hopOutbound   sync.Map
	hopDone       chan struct{}
}

func NewOverlay(cfg Config, handler http.Handler, streamHandler StreamHandler) (*Overlay, error) {
	cfg, err := NormalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	publicKey := strings.TrimSpace(cfg.PublicKey)
	if publicKey == "" {
		return nil, errors.New("wireguard public key is required")
	}

	stack, err := newStack(cfg)
	if err != nil {
		return nil, err
	}

	listener, err := stack.ListenTCP(DefaultPeerAPIHTTPPort)
	if err != nil {
		_ = stack.Close()
		return nil, err
	}

	hopListener, err := stack.ListenTCP(DefaultPeerYamuxPort)
	if err != nil {
		_ = listener.Close()
		_ = stack.Close()
		return nil, err
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	client := utils.NewHTTPClient(
		utils.WithHTTPDialContext(stack.DialContext),
		utils.WithHTTPTLSHandshakeTimeout(10*time.Second),
		utils.WithHTTPMaxIdleConns(100),
		utils.WithHTTPIdleConnTimeout(90*time.Second),
		utils.WithHTTPResponseHeaderTimeout(30*time.Second),
		utils.WithHTTPExpectContinueTimeout(1*time.Second),
		utils.WithoutHTTP2(),
	)

	publicCfg := cfg.Copy()
	publicCfg.PrivateKey = ""
	ov := &Overlay{
		cfg:         publicCfg,
		stack:       stack,
		listener:    listener,
		server:      server,
		client:      client,
		hopListener: hopListener,
		hopDone:     make(chan struct{}),
	}
	if streamHandler != nil {
		ov.streamHandler.Store(&streamHandler)
	}
	return ov, nil
}

func (o *Overlay) Config() Config {
	if o == nil {
		return Config{}
	}
	return o.cfg.Copy()
}

func (o *Overlay) Serve(ctx context.Context) error {
	if o == nil {
		return nil
	}

	if o.server != nil && o.listener != nil {
		go func() {
			err := o.server.Serve(o.listener)
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				log.Error().Err(err).Msg("overlay peer api server exited")
			}
		}()
	}

	if o.hopListener != nil {
		go func() {
			<-ctx.Done()
			_ = o.hopListener.Close()
		}()

		for {
			conn, err := o.hopListener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
					return err
				}
				return fmt.Errorf("accept hop mux connection: %w", err)
			}
			go o.serveHopSession(ctx, conn)
		}
	}

	<-ctx.Done()
	return nil
}

func (o *Overlay) SetStreamHandler(handler StreamHandler) {
	if handler != nil {
		o.streamHandler.Store(&handler)
	} else {
		o.streamHandler.Store(nil)
	}
}

func (o *Overlay) OpenHopStream(ctx context.Context, overlayIPv4, token string) (net.Conn, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("next hop token is required")
	}
	overlayIPv4 = strings.TrimSpace(overlayIPv4)
	if overlayIPv4 == "" {
		return nil, errors.New("next hop overlay ipv4 is required")
	}

	var next *yamux.Stream
	var lastErr error
	for {
		session, err := o.getHopSession(ctx, overlayIPv4)
		if err != nil {
			return nil, err
		}

		type openResult struct {
			stream *yamux.Stream
			err    error
		}
		resCh := make(chan openResult, 1)
		go func() {
			s, openErr := session.OpenStream()
			resCh <- openResult{s, openErr}
		}()

		select {
		case res := <-resCh:
			if res.err != nil {
				_ = session.Close()
				lastErr = res.err
			} else {
				next = res.stream
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		if next != nil {
			break
		}
		if errors.Is(lastErr, net.ErrClosed) {
			return nil, fmt.Errorf("open next hop stream: %w", lastErr)
		}
		if !utils.SleepOrDone(ctx, 250*time.Millisecond) {
			return nil, fmt.Errorf("open next hop stream within timeout: %w", errors.Join(lastErr, ctx.Err()))
		}
	}

	payload := []byte(token)
	if len(payload) > maxHopTokenBytes {
		_ = next.Close()
		return nil, errors.New("next hop token is too large")
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	if _, err := next.Write(frame); err != nil {
		_ = next.Close()
		return nil, err
	}
	return next, nil
}

func (o *Overlay) getHopSession(ctx context.Context, overlayIPv4 string) (*yamux.Session, error) {
	select {
	case <-o.hopDone:
		return nil, net.ErrClosed
	default:
	}

	if val, ok := o.hopOutbound.Load(overlayIPv4); ok {
		session := val.(*yamux.Session)
		if !session.IsClosed() {
			return session, nil
		}
		o.hopOutbound.Delete(overlayIPv4)
	}

	addr := net.JoinHostPort(overlayIPv4, fmt.Sprintf("%d", DefaultPeerYamuxPort))
	conn, err := o.stack.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	session, err := yamux.Client(conn, hopYamuxConfig())
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	select {
	case <-o.hopDone:
		_ = session.Close()
		return nil, net.ErrClosed
	default:
	}

	if actual, loaded := o.hopOutbound.LoadOrStore(overlayIPv4, session); loaded {
		current := actual.(*yamux.Session)
		if !current.IsClosed() {
			_ = session.Close()
			return current, nil
		}
		// the existing one is closed, replace it
		o.hopOutbound.Store(overlayIPv4, session)
	}

	// Background cleanup to prevent memory leaks for dead sessions.
	go func(ip string, s *yamux.Session) {
		select {
		case <-s.CloseChan():
		case <-o.hopDone:
			return
		}
		o.hopOutbound.CompareAndDelete(ip, s)
	}(overlayIPv4, session)

	return session, nil
}

func (o *Overlay) serveHopSession(ctx context.Context, conn net.Conn) {
	session, err := yamux.Server(conn, hopYamuxConfig())
	if err != nil {
		_ = conn.Close()
		return
	}

	select {
	case <-o.hopDone:
		_ = session.Close()
		return
	default:
	}

	go func() {
		select {
		case <-ctx.Done():
		case <-o.hopDone:
		}
		_ = session.Close()
	}()

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}
		go func(stream *yamux.Stream) {
			_ = stream.SetReadDeadline(time.Now().Add(defaultTokenTimeout))
			var size [4]byte
			if _, err := io.ReadFull(stream, size[:]); err != nil {
				_ = stream.Close()
				return
			}
			n := binary.BigEndian.Uint32(size[:])
			if n == 0 || n > uint32(maxHopTokenBytes) {
				_ = stream.Close()
				return
			}
			payload := make([]byte, n)
			if _, err := io.ReadFull(stream, payload); err != nil {
				_ = stream.Close()
				return
			}
			_ = stream.SetReadDeadline(time.Time{})

			token := strings.TrimSpace(string(payload))
			if token == "" {
				_ = stream.Close()
				return
			}
			remoteAddr := ""
			if stream.RemoteAddr() != nil {
				remoteAddr = stream.RemoteAddr().String()
			}
			hopStream := HopStream{
				Conn:       stream,
				Token:      token,
				RemoteAddr: remoteAddr,
			}
			handlerPtr := o.streamHandler.Load()
			if handlerPtr != nil && *handlerPtr != nil {
				(*handlerPtr)(ctx, hopStream)
			} else {
				_ = stream.Close()
			}
		}(stream)
	}
}

func (o *Overlay) Shutdown(ctx context.Context) error {
	if o == nil {
		return nil
	}

	select {
	case <-o.hopDone:
	default:
		close(o.hopDone)
	}

	var shutdownErr error
	if o.server != nil {
		err := o.server.Shutdown(ctx)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			shutdownErr = errors.Join(shutdownErr, err)
		}
	}
	if o.client != nil {
		o.client.CloseIdleConnections()
	}
	if o.listener != nil {
		err := o.listener.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			shutdownErr = errors.Join(shutdownErr, err)
		}
	}
	if o.hopListener != nil {
		err := o.hopListener.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			shutdownErr = errors.Join(shutdownErr, err)
		}
	}

	o.hopOutbound.Range(func(key, value any) bool {
		session := value.(*yamux.Session)
		shutdownErr = errors.Join(shutdownErr, session.Close())
		o.hopOutbound.Delete(key)
		return true
	})

	if o.stack != nil {
		shutdownErr = errors.Join(shutdownErr, o.stack.Close())
	}
	return shutdownErr
}

func (o *Overlay) Client() *http.Client {
	if o == nil || o.stack == nil {
		return nil
	}
	return o.client
}

func (o *Overlay) DiscoverRelay(ctx context.Context, relay types.RelayDescriptor) (types.DiscoveryResponse, error) {
	if o == nil || o.stack == nil {
		return types.DiscoveryResponse{}, errors.New("overlay is not initialized")
	}
	if !relay.HasOverlayPeer() {
		return types.DiscoveryResponse{}, errors.New("relay wireguard overlay metadata is required")
	}
	overlayIPv4, err := identity.DeriveWireGuardOverlayIPv4(relay.WireGuardPublicKey)
	if err != nil {
		return types.DiscoveryResponse{}, err
	}

	var resp types.DiscoveryResponse
	baseURL := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(overlayIPv4, fmt.Sprintf("%d", DefaultPeerAPIHTTPPort)),
	}
	if err := utils.HTTPDoAPIPath(ctx, o.Client(), baseURL, http.MethodGet, types.PathDiscovery, nil, nil, &resp); err != nil {
		return types.DiscoveryResponse{}, err
	}
	return resp, nil
}

func (o *Overlay) Sync(relays []types.RelayDescriptor) error {
	if o == nil || o.stack == nil {
		return nil
	}

	peers := make([]types.RelayDescriptor, 0, len(relays))
	for _, desc := range relays {
		if !desc.HasOverlayPeer() {
			continue
		}
		if desc.WireGuardPublicKey == o.cfg.PublicKey {
			continue
		}
		peers = append(peers, desc)
	}
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].WireGuardPublicKey < peers[j].WireGuardPublicKey
	})
	return o.stack.ApplyPeers(peers)
}

func hopYamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.Logger = nil
	cfg.MaxStreamWindowSize = 16 * 1024 * 1024
	return cfg
}
