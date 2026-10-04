package agent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const managedTunnelRetryInterval = 30 * time.Second

type manager struct {
	controlAddr string

	configMu sync.Mutex

	mu sync.RWMutex
	// cfg is the normalized snapshot of the config document on disk, the
	// configuration authority: every mutation reloads and commits that
	// document before installing the new snapshot here.
	cfg     Config
	tunnels map[string]*managedTunnel
	rootCtx context.Context
}

func newManager(cfg Config, controlAddr string) *manager {
	manager := &manager{
		controlAddr: controlAddr,
		cfg:         cfg,
		tunnels:     make(map[string]*managedTunnel, len(cfg.Tunnels)),
	}
	for _, tunnelCfg := range cfg.Tunnels {
		manager.tunnels[tunnelCfg.ID] = newManagedTunnel(tunnelCfg)
	}
	return manager
}

func (m *manager) Start(ctx context.Context) {
	m.mu.Lock()
	m.rootCtx = ctx
	tunnels := make([]*managedTunnel, 0, len(m.tunnels))
	for _, tunnel := range m.tunnels {
		tunnels = append(tunnels, tunnel)
	}
	m.mu.Unlock()

	for _, tunnel := range tunnels {
		tunnel.Start(ctx)
	}
}

func (m *manager) Stop(ctx context.Context) error {
	m.mu.RLock()
	tunnels := make([]*managedTunnel, 0, len(m.tunnels))
	for _, tunnel := range m.tunnels {
		tunnels = append(tunnels, tunnel)
	}
	m.mu.RUnlock()

	var wg sync.WaitGroup
	wg.Add(len(tunnels))
	for _, tunnel := range tunnels {
		go func(t *managedTunnel) {
			defer wg.Done()
			if err := t.Stop(ctx); err != nil {
				t.mu.RLock()
				tunnelID := t.spec.ID
				t.mu.RUnlock()
				log.Warn().Err(err).Str("tunnel_id", tunnelID).Msg("stop tunnel")
			}
		}(tunnel)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *manager) ConnectRelay(id, relayURL string) error {
	id = strings.TrimSpace(id)
	if err := validateAgentPathComponent("tunnel id", id); err != nil {
		return err
	}

	m.mu.RLock()
	tunnel := m.tunnels[id]
	m.mu.RUnlock()
	if tunnel == nil {
		return fmt.Errorf("tunnel %q not found", id)
	}
	return tunnel.ConnectRelay(relayURL)
}

func (m *manager) DisconnectRelay(id, relayURL string) error {
	id = strings.TrimSpace(id)
	if err := validateAgentPathComponent("tunnel id", id); err != nil {
		return err
	}

	m.mu.RLock()
	tunnel := m.tunnels[id]
	m.mu.RUnlock()
	if tunnel == nil {
		return fmt.Errorf("tunnel %q not found", id)
	}
	return tunnel.DisconnectRelay(relayURL)
}

func (m *manager) UpdateTunnel(id string, req AgentTunnelUpdateRequest) error {
	if req.Empty() {
		return errors.New("tunnel update requires at least one field")
	}
	updateMetadata := req.Metadata != nil && !req.Metadata.Empty()
	updateMaxActiveRelays := req.MaxActiveRelays != nil
	if err := m.updateTunnelConfig(id, func(tunnel *TunnelConfig) error {
		if req.MaxActiveRelays != nil {
			if *req.MaxActiveRelays <= 0 {
				return errors.New("max_active_relays must be a positive integer")
			}
			tunnel.MaxActiveRelays = *req.MaxActiveRelays
		}
		if req.Metadata != nil {
			if req.Metadata.Description != nil {
				tunnel.Description = strings.TrimSpace(*req.Metadata.Description)
			}
			if req.Metadata.Owner != nil {
				tunnel.Owner = strings.TrimSpace(*req.Metadata.Owner)
			}
			if req.Metadata.Thumbnail != nil {
				tunnel.Thumbnail = strings.TrimSpace(*req.Metadata.Thumbnail)
			}
			if req.Metadata.Tags != nil {
				tunnel.Tags = normalizeAgentMetadataTags(*req.Metadata.Tags)
			}
			if req.Metadata.Hide != nil {
				tunnel.Hide = *req.Metadata.Hide
			}
		}
		return nil
	}); err != nil {
		return err
	}

	id = strings.TrimSpace(id)
	m.mu.RLock()
	tunnel := m.tunnels[id]
	m.mu.RUnlock()
	if tunnel == nil {
		return fmt.Errorf("tunnel %q not found", id)
	}
	return tunnel.UpdateSettings(updateMetadata, updateMaxActiveRelays)
}

func (m *manager) AddTunnel(req AgentTunnelRequest) error {
	m.configMu.Lock()
	defer m.configMu.Unlock()

	cfg, path, mode, err := m.loadConfigDocument()
	if err != nil {
		return err
	}
	id := strings.TrimSpace(req.ID)
	name := strings.TrimSpace(req.Name)
	id = cmp.Or(id, agentTunnelID(name))
	if id == "" {
		return errors.New("tunnel name is required")
	}
	if err := validateAgentPathComponent("tunnel id", id); err != nil {
		return err
	}
	target := strings.TrimSpace(req.TargetAddr)
	httpRoutes := make([]tunnel.HTTPRoute, 0, len(req.HTTPRoutes))
	for _, route := range req.HTTPRoutes {
		httpRoutes = append(httpRoutes, tunnel.HTTPRoute{
			Prefix:   strings.TrimSpace(route.Prefix),
			Upstream: strings.TrimSpace(route.Upstream),
			Methods:  normalizeAgentHTTPRouteMethods(route.Methods),
			Amount:   strings.TrimSpace(route.Amount),
		})
	}
	if target != "" && len(httpRoutes) > 0 {
		return errors.New("target cannot be combined with http_routes")
	}
	if target == "" && len(httpRoutes) == 0 {
		target = defaultTargetAddr
	}
	name = cmp.Or(name, id)
	relayURLs, err := utils.NormalizeRelayURLs(req.RelayURLs...)
	if err != nil {
		return err
	}
	discovery := true
	if req.Discovery != nil {
		discovery = *req.Discovery
	}
	if req.MaxActiveRelays < 0 {
		return errors.New("max_active_relays cannot be negative")
	}
	x402 := req.Copy()
	x402.PayTo = strings.TrimSpace(x402.PayTo)
	x402.Network = strings.ToLower(strings.TrimSpace(x402.Network))
	x402.Asset = strings.TrimSpace(x402.Asset)
	x402.Endpoints = compactStrings(x402.Endpoints)
	tunnelCfg := TunnelConfig{
		ID:                  id,
		Name:                name,
		TargetAddr:          target,
		HTTPRoutes:          httpRoutes,
		StripRequestHeaders: append([]string(nil), req.StripRequestHeaders...),
		RelayURLs:           relayURLs,
		Discovery:           &discovery,
		Overlay:             req.Overlay,
		MaxActiveRelays:     req.MaxActiveRelays,
		Auth:                strings.ToLower(strings.TrimSpace(req.Auth)),
		AuthAllowedWallets:  append([]string(nil), req.AuthAllowedWallets...),
		AuthIdentityHeaders: req.AuthIdentityHeaders,
		X402Config:          x402,
	}
	if slices.ContainsFunc(cfg.Tunnels, func(tunnel TunnelConfig) bool { return tunnel.ID == tunnelCfg.ID }) {
		return fmt.Errorf("tunnel %q already exists", tunnelCfg.ID)
	}
	cfg.Tunnels = append(cfg.Tunnels, tunnelCfg)
	return m.writeConfigAndApply(path, mode, cfg)
}

func agentTunnelID(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var out strings.Builder
	dash := false
	for _, r := range name {
		if invalidAgentPathComponentRune(r) {
			if out.Len() > 0 && !dash {
				out.WriteByte('-')
				dash = true
			}
			continue
		}
		out.WriteRune(r)
		dash = false
	}
	return strings.Trim(out.String(), "-")
}

func normalizeAgentHTTPRouteMethods(methods []string) []string {
	out := make([]string, 0, len(methods))
	for _, raw := range methods {
		method := strings.ToUpper(strings.TrimSpace(raw))
		if method != "" && !slices.Contains(out, method) {
			out = append(out, method)
		}
	}
	return out
}

func (m *manager) updateTunnelConfig(id string, update func(*TunnelConfig) error) error {
	id = strings.TrimSpace(id)
	if err := validateAgentPathComponent("tunnel id", id); err != nil {
		return err
	}

	m.configMu.Lock()
	defer m.configMu.Unlock()

	cfg, path, mode, err := m.loadConfigDocument()
	if err != nil {
		return err
	}
	index := slices.IndexFunc(cfg.Tunnels, func(tunnel TunnelConfig) bool { return tunnel.ID == id })
	if index < 0 {
		return fmt.Errorf("tunnel %q not found", id)
	}
	before := cfg.Tunnels[index]
	if err := update(&cfg.Tunnels[index]); err != nil {
		return err
	}
	if reflect.DeepEqual(before, cfg.Tunnels[index]) {
		return nil
	}
	cfg, err = commitConfig(path, mode, cfg)
	if err != nil {
		return err
	}

	nextTunnelCfg := cfg.Tunnels[index]
	m.mu.Lock()
	m.cfg = cfg
	if tunnel := m.tunnels[id]; tunnel != nil {
		tunnel.assign(nextTunnelCfg)
	}
	m.mu.Unlock()
	return nil
}

func (m *manager) DeleteTunnel(id string) error {
	m.configMu.Lock()
	defer m.configMu.Unlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("tunnel id is required")
	}
	cfg, path, mode, err := m.loadConfigDocument()
	if err != nil {
		return err
	}

	index := slices.IndexFunc(cfg.Tunnels, func(tunnel TunnelConfig) bool { return tunnel.ID == id })
	if index < 0 {
		return fmt.Errorf("tunnel %q not found", id)
	}
	next := cfg.Tunnels[:0]
	for i, tunnel := range cfg.Tunnels {
		if i == index {
			continue
		}
		next = append(next, tunnel)
	}
	cfg.Tunnels = next
	return m.writeConfigAndApply(path, mode, cfg)
}

func (m *manager) loadConfigDocument() (Config, string, os.FileMode, error) {
	m.mu.RLock()
	configPath := m.cfg.sourcePath
	m.mu.RUnlock()
	cfg, path, mode, err := loadConfigDocument(configPath)
	if err != nil {
		return Config{}, "", 0, err
	}
	return cfg, path, mode, nil
}

// commitConfig normalizes cfg for path, validates it, and persists it as the
// new configuration document. It is the single place that turns an edited
// Config into the on-disk authority and the normalized runtime snapshot.
func commitConfig(path string, mode os.FileMode, cfg Config) (Config, error) {
	cfg.sourcePath = path
	if err := cfg.ApplyDefaults(path); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	if err := writeConfigDocument(path, mode, cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (m *manager) writeConfigAndApply(path string, mode os.FileMode, cfg Config) error {
	cfg, err := commitConfig(path, mode, cfg)
	if err != nil {
		return err
	}
	return m.ApplyConfig(cfg)
}

func (m *manager) ApplyConfig(cfg Config) error {
	m.mu.Lock()
	m.cfg = cfg
	rootCtx := m.rootCtx
	next := make(map[string]TunnelConfig, len(cfg.Tunnels))
	for _, tunnelCfg := range cfg.Tunnels {
		next[tunnelCfg.ID] = tunnelCfg
	}
	toStop := make([]*managedTunnel, 0)
	toStart := make([]*managedTunnel, 0)
	toUpdate := make([]*managedTunnel, 0)
	for id, tunnel := range m.tunnels {
		tunnelCfg, ok := next[id]
		if !ok {
			toStop = append(toStop, tunnel)
			delete(m.tunnels, id)
			continue
		}
		tunnel.mu.RLock()
		previous := tunnel.spec
		tunnel.mu.RUnlock()
		if !reflect.DeepEqual(previous, tunnelCfg) {
			tunnel.assign(tunnelCfg)
			toUpdate = append(toUpdate, tunnel)
		}
		delete(next, id)
	}
	for _, tunnelCfg := range next {
		tunnel := newManagedTunnel(tunnelCfg)
		m.tunnels[tunnelCfg.ID] = tunnel
		toStart = append(toStart, tunnel)
	}
	m.mu.Unlock()

	for _, tunnel := range append(toStop, toUpdate...) {
		_ = tunnel.Stop(context.Background())
	}
	if rootCtx == nil {
		rootCtx = context.Background()
	}
	for _, tunnel := range append(toStart, toUpdate...) {
		tunnel.Start(rootCtx)
	}
	return nil
}

func (m *manager) Snapshot() AgentStatusResponse {
	m.mu.RLock()
	configPath := m.cfg.sourcePath
	tunnels := make([]*managedTunnel, 0, len(m.tunnels))
	for _, tunnel := range m.tunnels {
		tunnels = append(tunnels, tunnel)
	}
	m.mu.RUnlock()

	statuses := make([]AgentTunnelStatus, 0, len(tunnels))
	for _, tunnel := range tunnels {
		statuses = append(statuses, tunnel.Snapshot())
	}
	slices.SortFunc(statuses, func(a, b AgentTunnelStatus) int {
		return strings.Compare(a.ID, b.ID)
	})

	return AgentStatusResponse{
		ConfigPath:  configPath,
		ControlAddr: m.controlAddr,
		Tunnels:     statuses,
	}
}

type managedTunnel struct {
	mu sync.RWMutex
	// spec is the normalized tunnel configuration assigned as a whole by the
	// manager; the tunnel never edits it. The config document on disk is the
	// authority, and every manager assign comes from a freshly loaded and
	// normalized document.
	spec TunnelConfig
	// relayURLs is the runtime relay membership: the configured relays as
	// changed by connect/disconnect actions. It resets to the configured
	// relays whenever the manager assigns a new spec.
	relayURLs []string

	cancel    context.CancelFunc
	done      chan struct{}
	exposure  *sdk.Exposure
	lastError string
	address   string
	relays    []AgentRelayStatus
}

// assign installs the manager's normalized spec and resets runtime relay
// membership to the configured relays.
func (t *managedTunnel) assign(spec TunnelConfig) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.spec = spec
	t.relayURLs = append([]string(nil), spec.RelayURLs...)
}

func newManagedTunnel(spec TunnelConfig) *managedTunnel {
	tunnel := &managedTunnel{}
	tunnel.assign(spec)
	return tunnel
}

func (t *managedTunnel) Start(parent context.Context) {
	t.mu.Lock()
	if t.done != nil {
		t.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	t.cancel = cancel
	t.done = make(chan struct{})
	done := t.done
	t.mu.Unlock()

	go func() {
		defer close(done)
		t.runLoop(ctx)
	}()
}

func (t *managedTunnel) Stop(ctx context.Context) error {
	t.mu.Lock()
	cancel := t.cancel
	done := t.done
	t.cancel = nil
	t.done = nil
	if cancel != nil {
		cancel()
	}
	t.mu.Unlock()

	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *managedTunnel) ConnectRelay(relayURL string) error {
	relayURL, err := utils.NormalizeRelayURL(relayURL)
	if err != nil {
		return err
	}
	t.mu.Lock()
	if !slices.Contains(t.relayURLs, relayURL) {
		t.relayURLs = append(t.relayURLs, relayURL)
	}
	exposure := t.exposure
	t.mu.Unlock()
	if exposure == nil {
		return nil
	}
	return exposure.AddRelay(relayURL)
}

func (t *managedTunnel) DisconnectRelay(relayURL string) error {
	relayURL, err := utils.NormalizeRelayURL(relayURL)
	if err != nil {
		return err
	}
	t.mu.Lock()
	next := make([]string, 0, len(t.relayURLs))
	for _, existing := range t.relayURLs {
		if existing != relayURL {
			next = append(next, existing)
		}
	}
	t.relayURLs = next
	exposure := t.exposure
	t.mu.Unlock()
	if exposure == nil {
		return nil
	}
	return exposure.RemoveRelay(relayURL)
}

func (t *managedTunnel) UpdateSettings(updateMetadata, updateMaxActiveRelays bool) error {
	t.mu.RLock()
	exposure := t.exposure
	cfg := t.spec
	t.mu.RUnlock()
	if exposure == nil {
		return nil
	}
	var err error
	if updateMetadata {
		err = errors.Join(err, exposure.UpdateMetadata(metadataFromTunnelConfig(cfg)))
	}
	if updateMaxActiveRelays {
		err = errors.Join(err, exposure.SetMaxActiveRelays(cfg.MaxActiveRelays))
	}
	return err
}

func (t *managedTunnel) Snapshot() AgentTunnelStatus {
	t.mu.RLock()
	cfg := t.spec
	lastError := t.lastError
	exposure := t.exposure
	done := t.done
	address := t.address
	relays := append([]AgentRelayStatus(nil), t.relays...)
	t.mu.RUnlock()

	running := false
	if done != nil {
		select {
		case <-done:
		default:
			running = true
		}
	}

	state := "stopped"
	switch {
	case lastError != "":
		state = "error"
	case exposure != nil:
		state = "running"
	case running:
		state = "starting"
	}
	discovery := true
	if cfg.Discovery != nil {
		discovery = *cfg.Discovery
	}

	x402 := cfg.Copy()
	x402.PayTo = strings.TrimSpace(x402.PayTo)
	status := AgentTunnelStatus{
		ID:                  cfg.ID,
		Name:                cfg.Name,
		State:               state,
		TargetAddr:          cfg.TargetAddr,
		LastError:           lastError,
		Serve:               cfg.Serve,
		Discovery:           discovery,
		Overlay:             cfg.Overlay,
		MaxActiveRelays:     cfg.MaxActiveRelays,
		Metadata:            metadataFromTunnelConfig(cfg),
		Auth:                cfg.Auth,
		AuthIdentityHeaders: cfg.AuthIdentityHeaders,
		X402Config:          x402,
	}
	if len(cfg.HTTPRoutes) > 0 {
		status.HTTPRoutes = make([]tunnel.HTTPRoute, 0, len(cfg.HTTPRoutes))
		for _, route := range cfg.HTTPRoutes {
			status.HTTPRoutes = append(status.HTTPRoutes, tunnel.HTTPRoute{
				Prefix:   route.Prefix,
				Upstream: route.Upstream,
				Methods:  append([]string(nil), route.Methods...),
				Amount:   route.Amount,
			})
		}
	}
	if exposure == nil {
		status.Address = address
		status.Relays = relays
		return status
	}
	relays = agentRelayStatuses(exposure.Relays())
	t.mu.Lock()
	if t.exposure == exposure {
		t.relays = append([]AgentRelayStatus(nil), relays...)
	}
	address = t.address
	t.mu.Unlock()

	status.Address = address
	status.Relays = relays
	return status
}

func agentRelayStatuses(relays []sdk.RelayStatus) []AgentRelayStatus {
	statuses := make([]AgentRelayStatus, 0, len(relays))
	for _, relay := range relays {
		statuses = append(statuses, AgentRelayStatus{
			RelayURL:   relay.RelayURL,
			PublicURL:  relay.PublicURL,
			TCPAddr:    relay.TCPAddr,
			Version:    relay.Version,
			Connecting: relay.State == sdk.RelayConnecting,
		})
	}
	return statuses
}

func (t *managedTunnel) runLoop(ctx context.Context) {
	for {
		err := t.runOnce(ctx)
		t.mu.Lock()
		t.exposure = nil
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || err == nil {
			t.lastError = ""
		} else {
			t.lastError = err.Error()
		}
		t.mu.Unlock()

		if ctx.Err() != nil || errors.Is(err, context.Canceled) || err == nil {
			return
		}
		log.Warn().Err(err).Msg("managed tunnel stopped with error; retrying")
		if !utils.SleepOrDone(ctx, managedTunnelRetryInterval) {
			return
		}
	}
}

func (t *managedTunnel) runOnce(ctx context.Context) error {
	t.mu.Lock()
	cfg := t.spec
	cfg.RelayURLs = t.relayURLs
	t.lastError = ""
	t.mu.Unlock()

	spec := tunnelSpecFromConfig(cfg)
	runtime, err := tunnel.Start(ctx, spec)
	if err != nil {
		return err
	}
	exposure := runtime.Exposure
	t.mu.Lock()
	t.exposure = exposure
	t.address = runtime.Identity.Address
	t.relays = agentRelayStatuses(exposure.Relays())
	t.lastError = ""
	t.mu.Unlock()

	defer runtime.Close()
	err = runtime.Run(ctx)
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return ctx.Err()
	}
	return err
}
