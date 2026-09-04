//go:build !windows

package overlay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"gosuda.org/ivnp"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultIVNPDiscoveryPort  = 7777
	defaultIVNPHopPort        = 7778
	defaultIVNPRequestTimeout = 30 * time.Second
)

// IVNP carries Portal discovery and authenticated hop streams over one I2P
// application destination. Portal continues to own descriptor and route-token
// verification; IVNP owns peer reachability and the internal overlay path.
type IVNP struct {
	node        *ivnp.Node
	local       *ivnp.LocalDestination
	destination string
	handler     http.Handler
	hopHandler  StreamHandler

	mu                sync.Mutex
	endpoint          ivnp.DestinationEndpoint
	network           ivnp.StreamNetwork
	discoveryListener net.Listener
	hopListener       net.Listener
	discoveryServer   *http.Server
	client            *http.Client
	ready             atomic.Bool
	closed            atomic.Bool
}

func NewIVNP(configPath string, handler http.Handler, hopHandler StreamHandler) (*IVNP, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return nil, errors.New("ivnp config path is required")
	}
	cfg, err := ivnp.LoadOrCreateConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("load ivnp config: %w", err)
	}
	// Portal embeds IVNP directly and does not need the external SAM listener.
	cfg.SAM.Enabled = false
	node, err := ivnp.New(cfg, ivnp.Options{})
	if err != nil {
		return nil, fmt.Errorf("create ivnp node: %w", err)
	}
	local, err := loadOrCreateIVNPDestination(filepath.Join(filepath.Dir(configPath), "ivnp.destination"))
	if err != nil {
		_ = node.Close()
		return nil, fmt.Errorf("generate ivnp destination: %w", err)
	}
	return &IVNP{
		node:        node,
		local:       local,
		destination: local.B32(),
		handler:     handler,
		hopHandler:  hopHandler,
	}, nil
}

func loadOrCreateIVNPDestination(path string) (*ivnp.LocalDestination, error) {
	encoded, err := os.ReadFile(path)
	if err == nil {
		local, importErr := ivnp.ImportLocalDestination(encoded)
		clear(encoded)
		if importErr != nil {
			return nil, fmt.Errorf("import ivnp destination: %w", importErr)
		}
		return local, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read ivnp destination: %w", err)
	}
	local, err := ivnp.GenerateLegacyLocalDestination()
	if err != nil {
		return nil, err
	}
	encoded = make([]byte, local.PrivateEncodedLen())
	n, err := local.MarshalPrivateTo(encoded)
	if err != nil {
		local.ReleaseSensitive()
		clear(encoded)
		return nil, err
	}
	if err := utils.EnsureParentDir(path); err != nil {
		local.ReleaseSensitive()
		clear(encoded)
		return nil, err
	}
	err = utils.WriteFileAtomic(path, encoded[:n], 0o600)
	clear(encoded)
	if err != nil {
		local.ReleaseSensitive()
		return nil, fmt.Errorf("persist ivnp destination: %w", err)
	}
	return local, nil
}

func (o *IVNP) Destination() string {
	if o == nil || !o.ready.Load() {
		return ""
	}
	return o.destination
}

func (o *IVNP) Serve(ctx context.Context) error {
	if o == nil || o.node == nil {
		return errors.New("ivnp overlay is not initialized")
	}
	o.mu.Lock()
	if o.closed.Load() || o.local == nil {
		o.mu.Unlock()
		return net.ErrClosed
	}
	local := o.local
	o.local = nil
	o.mu.Unlock()
	defer local.ReleaseSensitive()
	if err := o.node.Start(ctx); err != nil {
		return fmt.Errorf("start ivnp node: %w", err)
	}
	endpoint, err := o.node.DestinationController().CreateDestination(ctx, ivnp.DestinationSpec{Local: local})
	if err != nil {
		return fmt.Errorf("create ivnp application destination: %w", err)
	}
	discoveryListener, err := endpoint.ListenI2P(ctx, fmt.Sprintf(":%d", defaultIVNPDiscoveryPort))
	if err != nil {
		_ = endpoint.Close()
		return fmt.Errorf("listen for ivnp discovery: %w", err)
	}
	hopListener, err := endpoint.ListenI2P(ctx, fmt.Sprintf(":%d", defaultIVNPHopPort))
	if err != nil {
		_ = discoveryListener.Close()
		_ = endpoint.Close()
		return fmt.Errorf("listen for ivnp hop streams: %w", err)
	}
	discoveryServer := &http.Server{Handler: o.handler, ReadHeaderTimeout: 10 * time.Second}
	client := utils.NewHTTPClient(
		utils.WithHTTPDialContext(func(dialCtx context.Context, _, address string) (net.Conn, error) {
			return endpoint.DialI2P(dialCtx, address)
		}),
		utils.WithoutHTTP2(),
		utils.WithHTTPTimeout(defaultIVNPRequestTimeout),
	)
	o.mu.Lock()
	if o.closed.Load() {
		o.mu.Unlock()
		_ = hopListener.Close()
		_ = discoveryListener.Close()
		_ = endpoint.Close()
		return nil
	}
	o.endpoint = endpoint
	o.network = endpoint
	o.discoveryListener = discoveryListener
	o.hopListener = hopListener
	o.discoveryServer = discoveryServer
	o.client = client
	o.mu.Unlock()

	go func() {
		if serveErr := discoveryServer.Serve(discoveryListener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
			log.Error().Err(serveErr).Msg("ivnp discovery server exited")
		}
	}()
	go func() {
		<-ctx.Done()
		_ = hopListener.Close()
	}()

	ready, ok := endpoint.(ivnp.ReadyDestinationEndpoint)
	if !ok {
		return errors.New("ivnp destination does not report readiness")
	}
	if err := ready.WaitReady(ctx); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("wait for ivnp destination: %w", err)
	}
	if o.closed.Load() {
		return nil
	}
	o.ready.Store(true)
	log.Info().Str("destination", o.destination).Msg("ivnp relay overlay ready")

	for {
		conn, err := hopListener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept ivnp hop stream: %w", err)
		}
		go o.handleHopStream(ctx, conn)
	}
}

func (o *IVNP) handleHopStream(ctx context.Context, conn net.Conn) {
	stream, err := readHopStream(conn)
	if err != nil || o.hopHandler == nil {
		_ = conn.Close()
		return
	}
	o.hopHandler(ctx, stream)
}

func normalizeIVNPDestination(destination string) (string, error) {
	destination = strings.ToLower(strings.TrimSpace(destination))
	if destination == "" {
		return "", errors.New("next hop ivnp destination is required")
	}
	return destination, nil
}

func (o *IVNP) OpenHopStream(ctx context.Context, destination, token string) (net.Conn, error) {
	if o == nil || !o.ready.Load() {
		return nil, errors.New("ivnp overlay is not ready")
	}
	destination, err := normalizeIVNPDestination(destination)
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	network := o.network
	o.mu.Unlock()
	if network == nil {
		return nil, net.ErrClosed
	}
	conn, err := network.DialI2P(ctx, net.JoinHostPort(destination, fmt.Sprintf("%d", defaultIVNPHopPort)))
	if err != nil {
		return nil, err
	}
	if err := writeHopToken(conn, token); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (o *IVNP) DiscoverRelay(ctx context.Context, relay types.RelayDescriptor) (types.DiscoveryResponse, error) {
	if o == nil || !o.ready.Load() {
		return types.DiscoveryResponse{}, errors.New("ivnp overlay is not ready")
	}
	if !relay.HasIVNPPeer() {
		return types.DiscoveryResponse{}, errors.New("relay ivnp destination is required")
	}
	o.mu.Lock()
	client := o.client
	o.mu.Unlock()
	if client == nil {
		return types.DiscoveryResponse{}, net.ErrClosed
	}
	var response types.DiscoveryResponse
	baseURL := &url.URL{Scheme: "http", Host: net.JoinHostPort(relay.IVNPDestination, fmt.Sprintf("%d", defaultIVNPDiscoveryPort))}
	if err := utils.HTTPDoAPIPath(ctx, client, baseURL, http.MethodGet, types.PathDiscovery, nil, nil, &response); err != nil {
		return types.DiscoveryResponse{}, err
	}
	return response, nil
}

func (o *IVNP) Sync([]types.RelayDescriptor) error { return nil }

func (o *IVNP) CanDiscover(relay types.RelayDescriptor) bool { return relay.HasIVNPPeer() }

func (o *IVNP) DiscoveryInterval() time.Duration { return 2 * time.Minute }

func (o *IVNP) MeasureDiscoveryRTT() bool { return false }

func (o *IVNP) RecordDiscoveryFailures() bool { return false }

func (o *IVNP) Shutdown(ctx context.Context) error {
	if o == nil || o.closed.Swap(true) {
		return nil
	}
	o.ready.Store(false)
	o.mu.Lock()
	endpoint := o.endpoint
	discoveryListener := o.discoveryListener
	hopListener := o.hopListener
	discoveryServer := o.discoveryServer
	client := o.client
	local := o.local
	o.local = nil
	o.network = nil
	o.mu.Unlock()
	var shutdownErr error
	if discoveryServer != nil {
		shutdownErr = errors.Join(shutdownErr, discoveryServer.Shutdown(ctx))
	}
	if client != nil {
		client.CloseIdleConnections()
	}
	if discoveryListener != nil {
		if err := discoveryListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			shutdownErr = errors.Join(shutdownErr, err)
		}
	}
	if hopListener != nil {
		if err := hopListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			shutdownErr = errors.Join(shutdownErr, err)
		}
	}
	if endpoint != nil {
		shutdownErr = errors.Join(shutdownErr, endpoint.Close())
	}
	if local != nil {
		local.ReleaseSensitive()
	}
	if o.node != nil {
		shutdownErr = errors.Join(shutdownErr, o.node.Close(), o.node.Wait())
	}
	return shutdownErr
}
