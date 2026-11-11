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

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
)

var (
	errTunnelUpdateRequiresLeastOneField  = errors.New("tunnel update requires at least one field")
	errMaxActiveRelaysMustPositiveInteger = errors.New("max_active_relays must be a positive integer")
	errAuthEmptyWhichTurnsSignOff         = errors.New("auth is empty, which turns sign-in off: leave out the other auth fields")
	errTunnelNameIsRequired               = errors.New("tunnel name is required")
	errTargetCannotCombinedHTTPRoutes     = errors.New("target cannot be combined with http_routes")
	errMaxActiveRelaysCannotNegative      = errors.New("max_active_relays cannot be negative")
	errTunnelIDIsRequired                 = errors.New("tunnel id is required")
	errTunnelIsNotRunning                 = errors.New("tunnel is not running")
)

type manager struct {
	controlAddr string

	configMu sync.Mutex

	mu      sync.RWMutex
	cfg     Config
	tunnels map[string]*managedTunnel
	rootCtx context.Context
}

func newManager(cfg Config, controlAddr string) *manager {
	manager := &manager{
		controlAddr: controlAddr,
		cfg:         cfg,
		tunnels:     make(map[string]*managedTunnel, len(cfg.Tunnels)),
		rootCtx:     context.Background(),
	}
	for _, tunnelCfg := range cfg.Tunnels {
		manager.tunnels[tunnelCfg.ID] = &managedTunnel{cfg: tunnelCfg}
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
				tunnelID := t.cfg.ID
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
		return errTunnelUpdateRequiresLeastOneField
	}
	return m.updateTunnelConfig(id, func(tunnel *TunnelConfig) error {
		if err := applyTunnelMaxRelays(tunnel, req.MaxActiveRelays); err != nil {
			return err
		}
		if err := applyTunnelMetadata(tunnel, req.Metadata); err != nil {
			return err
		}
		return req.applyAuth(&tunnel.AuthConfig)
	})
}

func applyTunnelMaxRelays(tunnel *TunnelConfig, maxRelays *int) error {
	if maxRelays == nil {
		return nil
	}
	if *maxRelays <= 0 {
		return errMaxActiveRelaysMustPositiveInteger
	}
	tunnel.MaxActiveRelays = *maxRelays
	return nil
}

func applyTunnelMetadata(tunnel *TunnelConfig, metadata *AgentMetadataRequest) error {
	if metadata == nil {
		return nil
	}
	if metadata.Description != nil {
		tunnel.Description = *metadata.Description
	}
	if metadata.Owner != nil {
		tunnel.Owner = *metadata.Owner
	}
	if metadata.Thumbnail != nil {
		tunnel.Thumbnail = *metadata.Thumbnail
	}
	if metadata.Tags != nil {
		tunnel.Tags = *metadata.Tags
	}
	if metadata.Hide != nil {
		tunnel.Hide = *metadata.Hide
	}
	return nil
}

func (m *manager) AddTunnel(req AgentTunnelRequest) error {
	m.configMu.Lock()
	defer m.configMu.Unlock()

	cfg, path, mode, err := m.loadConfigDocument()
	if err != nil {
		return err
	}
	tunnelCfg, err := newTunnelConfig(req)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(cfg.Tunnels, func(tunnel TunnelConfig) bool { return tunnel.ID == tunnelCfg.ID }) {
		return fmt.Errorf("tunnel %q already exists", tunnelCfg.ID)
	}
	cfg.Tunnels = append(cfg.Tunnels, tunnelCfg)
	return m.writeConfigAndApply(path, mode, cfg)
}

func newTunnelConfig(req AgentTunnelRequest) (TunnelConfig, error) {
	id := strings.TrimSpace(req.ID)
	name := strings.TrimSpace(req.Name)
	id = cmp.Or(id, agentTunnelID(name))
	if id == "" {
		return TunnelConfig{}, errTunnelNameIsRequired
	}
	if err := validateAgentPathComponent("tunnel id", id); err != nil {
		return TunnelConfig{}, err
	}
	target := strings.TrimSpace(req.TargetAddr)
	if target != "" && len(req.HTTPRoutes) > 0 {
		return TunnelConfig{}, errTargetCannotCombinedHTTPRoutes
	}
	if target == "" && strings.TrimSpace(req.Serve) == "" && len(req.HTTPRoutes) == 0 {
		target = defaultTargetAddr
	}
	if req.MaxActiveRelays < 0 {
		return TunnelConfig{}, errMaxActiveRelaysCannotNegative
	}
	return TunnelConfig{ID: id, Config: tunnel.Config{
		Name:                cmp.Or(name, id),
		TargetAddr:          target,
		Serve:               req.Serve,
		HTTPRoutes:          req.HTTPRoutes,
		StripRequestHeaders: req.StripRequestHeaders,
		RelayURLs:           req.RelayURLs,
		Discovery:           req.Discovery,
		Overlay:             req.Overlay,
		MaxActiveRelays:     req.MaxActiveRelays,
		AuthConfig:          req.AuthConfig,
		X402Config:          req.X402Config,
	}}, nil
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
	return m.writeConfigAndApply(path, mode, cfg)
}

func (m *manager) DeleteTunnel(id string) error {
	m.configMu.Lock()
	defer m.configMu.Unlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return errTunnelIDIsRequired
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

func (m *manager) writeConfigAndApply(path string, mode os.FileMode, cfg Config) error {
	cfg.sourcePath = path
	if err := cfg.normalize(path); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := writeConfigDocument(path, mode, cfg); err != nil {
		return err
	}
	return m.applyConfig(cfg)
}

func (m *manager) applyConfig(cfg Config) error {
	m.mu.Lock()
	m.cfg = cfg
	rootCtx := m.rootCtx
	next := make(map[string]TunnelConfig, len(cfg.Tunnels))
	for _, tunnelCfg := range cfg.Tunnels {
		next[tunnelCfg.ID] = tunnelCfg
	}
	toStop, toStart, toUpdate := m.planTunnelUpdatesLocked(next)
	m.mu.Unlock()

	for _, tunnel := range toStop {
		_ = tunnel.Stop(context.Background())
	}
	for _, tunnel := range toStart {
		tunnel.Start(rootCtx)
	}
	var err error
	for _, tunnel := range toUpdate {
		err = errors.Join(err, tunnel.updateSettings())
	}
	return err
}

func (m *manager) planTunnelUpdatesLocked(next map[string]TunnelConfig) (toStop, toStart, toUpdate []*managedTunnel) {
	toStop = make([]*managedTunnel, 0)
	toStart = make([]*managedTunnel, 0)
	toUpdate = make([]*managedTunnel, 0)
	for id, tunnel := range m.tunnels {
		tunnelCfg, ok := next[id]
		if !ok {
			toStop = append(toStop, tunnel)
			delete(m.tunnels, id)
			continue
		}
		tunnel.mu.Lock()
		previous := tunnel.cfg
		if !reflect.DeepEqual(previous, tunnelCfg) {
			tunnel.cfg = tunnelCfg
			previous.LeaseMetadata = tunnelCfg.LeaseMetadata
			previous.MaxActiveRelays = tunnelCfg.MaxActiveRelays
			if reflect.DeepEqual(previous, tunnelCfg) {
				toUpdate = append(toUpdate, tunnel)
			} else {
				toStop = append(toStop, tunnel)
				toStart = append(toStart, tunnel)
			}
		}
		tunnel.mu.Unlock()
		delete(next, id)
	}
	for _, tunnelCfg := range next {
		tunnel := &managedTunnel{cfg: tunnelCfg}
		m.tunnels[tunnelCfg.ID] = tunnel
		toStart = append(toStart, tunnel)
	}
	return toStop, toStart, toUpdate
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
