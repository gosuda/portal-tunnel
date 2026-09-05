package overlay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	DefaultMTU                 = 1420
	DefaultListenPort          = 51820
	DefaultPeerAPIHTTPPort     = 7777
	DefaultPersistentKeepalive = 25
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

type Overlay struct {
	cfg      Config
	stack    *stack
	listener net.Listener
	server   *http.Server
	client   *http.Client
}

func NewOverlay(cfg Config, handler http.Handler) (*Overlay, error) {
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
		cfg:      publicCfg,
		stack:    stack,
		listener: listener,
		server:   server,
		client:   client,
	}
	return ov, nil
}

func (o *Overlay) Config() Config {
	if o == nil {
		return Config{}
	}
	return o.cfg.Copy()
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

func (o *Overlay) Serve(ctx context.Context) error {
	go func() { <-ctx.Done(); _ = o.server.Close() }()
	err := o.server.Serve(o.listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
func (o *Overlay) Shutdown(ctx context.Context) error {
	if o == nil {
		return nil
	}
	err := o.server.Shutdown(ctx)
	o.client.CloseIdleConnections()
	return errors.Join(err, o.stack.Close())
}
