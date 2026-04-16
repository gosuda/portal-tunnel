package overlay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type desiredPeer struct {
	wireGuardPublicKey string
	wireGuardEndpoint  string
	allowedIPs         []string
}

type Config struct {
	PrivateKey   string
	PublicKey    string
	Endpoint     string
	OverlayIPv4  string
	OverlayCIDRs []string
}

func (c Config) Copy() Config {
	return Config{
		PrivateKey:   c.PrivateKey,
		PublicKey:    c.PublicKey,
		Endpoint:     c.Endpoint,
		OverlayIPv4:  c.OverlayIPv4,
		OverlayCIDRs: append([]string(nil), c.OverlayCIDRs...),
	}
}

func NormalizeConfig(rootHost string, cfg Config) (Config, error) {
	configured := strings.TrimSpace(cfg.PrivateKey) != "" ||
		strings.TrimSpace(cfg.PublicKey) != "" ||
		strings.TrimSpace(cfg.Endpoint) != "" ||
		strings.TrimSpace(cfg.OverlayIPv4) != "" ||
		len(cfg.OverlayCIDRs) > 0
	if !configured {
		return cfg, nil
	}

	if strings.TrimSpace(cfg.PrivateKey) == "" {
		return Config{}, errors.New("wireguard private key is required when relay overlay is enabled")
	}

	privateKey, err := utils.NormalizeWireGuardPrivateKey(cfg.PrivateKey)
	if err != nil {
		return Config{}, fmt.Errorf("normalize wireguard private key: %w", err)
	}
	publicKey, err := utils.WireGuardPublicKeyFromPrivate(privateKey)
	if err != nil {
		return Config{}, fmt.Errorf("derive wireguard public key: %w", err)
	}
	if configuredPublicKey := strings.TrimSpace(cfg.PublicKey); configuredPublicKey != "" && configuredPublicKey != publicKey {
		return Config{}, errors.New("wireguard public key does not match private key")
	}

	cfg.PrivateKey = privateKey
	cfg.PublicKey = publicKey
	if len(cfg.OverlayCIDRs) > 0 {
		cfg.OverlayCIDRs, err = utils.NormalizeOverlayCIDRs(cfg.OverlayCIDRs)
		if err != nil {
			return Config{}, fmt.Errorf("normalize overlay cidrs: %w", err)
		}
	}
	if strings.TrimSpace(cfg.Endpoint) == "" {
		cfg.Endpoint = net.JoinHostPort(rootHost, fmt.Sprintf("%d", DefaultListenPort))
	}
	if strings.TrimSpace(cfg.OverlayIPv4) == "" {
		cfg.OverlayIPv4, err = utils.DeriveWireGuardOverlayIPv4(cfg.PublicKey)
		if err != nil {
			return Config{}, fmt.Errorf("derive overlay ipv4: %w", err)
		}
	}
	if err := utils.ValidateWireGuardEndpoint(cfg.Endpoint); err != nil {
		return Config{}, err
	}
	if err := utils.ValidateOverlayIPv4(cfg.OverlayIPv4); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

type Overlay struct {
	cfg      Config
	stack    *stack
	listener net.Listener
	server   *http.Server
}

func NewOverlay(rootHost string, cfg Config, handler http.Handler) (*Overlay, error) {
	cfg, err := NormalizeConfig(rootHost, cfg)
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

	listener, err := stack.ListenTCP(types.DefaultPeerAPIHTTPPort)
	if err != nil {
		_ = stack.Close()
		return nil, err
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	publicCfg := cfg.Copy()
	publicCfg.PrivateKey = ""
	return &Overlay{
		cfg:      publicCfg,
		stack:    stack,
		listener: listener,
		server:   server,
	}, nil
}

func (o *Overlay) Config() Config {
	if o == nil {
		return Config{}
	}
	return o.cfg.Copy()
}

func (o *Overlay) Serve() error {
	if o == nil || o.server == nil || o.listener == nil {
		return nil
	}

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

	var shutdownErr error
	if o.server != nil {
		err := o.server.Shutdown(ctx)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			shutdownErr = errors.Join(shutdownErr, err)
		}
	}
	if o.listener != nil {
		err := o.listener.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			shutdownErr = errors.Join(shutdownErr, err)
		}
	}
	if o.stack != nil {
		shutdownErr = errors.Join(shutdownErr, o.stack.Close())
	}
	return shutdownErr
}

func (o *Overlay) Client() *http.Client {
	if o == nil || o.stack == nil {
		return nil
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext:       o.stack.DialContext,
			ForceAttemptHTTP2: false,
		},
	}
}

func (o *Overlay) Dial(ctx context.Context, overlayIP string, port int) (net.Conn, error) {
	if o == nil || o.stack == nil {
		return nil, errors.New("overlay is not initialized")
	}
	return o.stack.DialContext(ctx, "tcp", net.JoinHostPort(overlayIP, strconv.Itoa(port)))
}

func (o *Overlay) DiscoverRelay(ctx context.Context, relay types.RelayDescriptor) (types.DiscoveryResponse, error) {
	if o == nil || o.stack == nil {
		return types.DiscoveryResponse{}, errors.New("overlay is not initialized")
	}
	if strings.TrimSpace(relay.OverlayIPv4) == "" {
		return types.DiscoveryResponse{}, errors.New("relay overlay ipv4 is required")
	}

	var resp types.DiscoveryResponse
	baseURL := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(relay.OverlayIPv4, fmt.Sprintf("%d", types.DefaultPeerAPIHTTPPort)),
	}
	if err := utils.HTTPDoAPIPath(ctx, o.Client(), baseURL, http.MethodGet, types.PathDiscovery, nil, nil, &resp); err != nil {
		return types.DiscoveryResponse{}, err
	}
	return resp, nil
}

func (o *Overlay) Sync(relays []discovery.RelayState) error {
	if o == nil || o.stack == nil {
		return nil
	}
	return o.stack.ApplyPeers(peersForRelays(o.cfg.PublicKey, relays))
}

func peersForRelays(publicKey string, relays []discovery.RelayState) []desiredPeer {
	peers := make([]desiredPeer, 0, len(relays))
	for _, relay := range relays {
		if !relay.Descriptor.SupportsOverlayPeer {
			continue
		}

		desc := relay.Descriptor
		if desc.WireGuardPublicKey == publicKey {
			continue
		}

		allowedIPs := []string{desc.OverlayIPv4 + "/32"}
		allowedIPs = append(allowedIPs, desc.OverlayCIDRs...)
		peers = append(peers, desiredPeer{
			wireGuardPublicKey: desc.WireGuardPublicKey,
			wireGuardEndpoint:  desc.WireGuardEndpoint,
			allowedIPs:         allowedIPs,
		})
	}
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].wireGuardPublicKey < peers[j].wireGuardPublicKey
	})
	return peers
}
