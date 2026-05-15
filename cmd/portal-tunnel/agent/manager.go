package agent

import (
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

	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const managedTunnelRetryInterval = 30 * time.Second

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
	}
	for _, tunnelCfg := range cfg.Tunnels {
		manager.tunnels[tunnelCfg.ID] = newTunnel(tunnelCfg)
	}
	return manager
}

func (m *manager) Start(ctx context.Context) {
	m.mu.Lock()
	m.rootCtx = ctx
	m.mu.Unlock()

	m.mu.RLock()
	tunnels := make([]*managedTunnel, 0, len(m.tunnels))
	for _, tunnel := range m.tunnels {
		tunnels = append(tunnels, tunnel)
	}
	m.mu.RUnlock()

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

func (m *manager) SetMultiHop(id string, relayURLs []string) error {
	id = strings.TrimSpace(id)
	multiHop, err := utils.NormalizeRelayURLs(relayURLs...)
	if err != nil {
		return fmt.Errorf("normalize multi-hop relay url: %w", err)
	}
	if len(multiHop) != len(relayURLs) {
		return errors.New("multi-hop relay url repeated")
	}
	if len(multiHop) == 1 {
		return errors.New("multi-hop requires at least entry and exit relay urls")
	}
	if err := m.updateTunnelConfig(id, func(tunnel *TunnelConfig) error {
		tunnel.MultiHop = append([]string(nil), multiHop...)
		tunnel.MultiHopDepth = 0
		return nil
	}); err != nil {
		return err
	}

	m.mu.RLock()
	tunnel := m.tunnels[id]
	m.mu.RUnlock()
	if tunnel == nil {
		return fmt.Errorf("tunnel %q not found", id)
	}
	return tunnel.SetMultiHop(multiHop)
}

func (m *manager) UpdateTunnel(id string, req types.AgentTunnelUpdateRequest) error {
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

func (m *manager) AddTunnel(req types.AgentTunnelRequest) error {
	m.configMu.Lock()
	defer m.configMu.Unlock()

	cfg, path, mode, err := m.loadConfigDocument()
	if err != nil {
		return err
	}
	id := strings.TrimSpace(req.ID)
	name := strings.TrimSpace(req.Name)
	if id == "" {
		id = agentTunnelID(name)
	}
	if id == "" {
		return errors.New("tunnel name is required")
	}
	if err := validateAgentPathComponent("tunnel id", id); err != nil {
		return err
	}
	target := strings.TrimSpace(req.TargetAddr)
	if target == "" {
		target = defaultTargetAddr
	}
	if name == "" {
		name = id
	}
	relayURLs, err := utils.NormalizeRelayURLs(req.RelayURLs...)
	if err != nil {
		return err
	}
	discovery := true
	tunnelCfg := TunnelConfig{
		ID:         id,
		Name:       name,
		TargetAddr: target,
		RelayURLs:  relayURLs,
		Discovery:  &discovery,
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
	cfg.sourcePath = path
	if err := cfg.ApplyDefaults(path); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := writeConfigDocument(path, mode, cfg); err != nil {
		return err
	}

	nextTunnelCfg := cfg.Tunnels[index]
	m.mu.Lock()
	m.cfg = cfg
	if tunnel := m.tunnels[id]; tunnel != nil {
		tunnel.mu.Lock()
		tunnel.cfg = nextTunnelCfg
		tunnel.mu.Unlock()
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

func (m *manager) writeConfigAndApply(path string, mode os.FileMode, cfg Config) error {
	cfg.sourcePath = path
	if err := cfg.ApplyDefaults(path); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := writeConfigDocument(path, mode, cfg); err != nil {
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
		tunnel.mu.Lock()
		previous := tunnel.cfg
		if !reflect.DeepEqual(previous, tunnelCfg) {
			tunnel.cfg = tunnelCfg
			toUpdate = append(toUpdate, tunnel)
		}
		tunnel.mu.Unlock()
		delete(next, id)
	}
	for _, tunnelCfg := range next {
		tunnel := newTunnel(tunnelCfg)
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

func (m *manager) Snapshot() types.AgentStatusResponse {
	m.mu.RLock()
	tunnels := make([]*managedTunnel, 0, len(m.tunnels))
	for _, tunnel := range m.tunnels {
		tunnels = append(tunnels, tunnel)
	}
	m.mu.RUnlock()

	statuses := make([]types.AgentTunnelStatus, 0, len(tunnels))
	for _, tunnel := range tunnels {
		statuses = append(statuses, tunnel.Snapshot())
	}
	slices.SortFunc(statuses, func(a, b types.AgentTunnelStatus) int {
		return strings.Compare(a.ID, b.ID)
	})

	return types.AgentStatusResponse{
		ConfigPath:  m.cfg.sourcePath,
		ControlAddr: m.controlAddr,
		Tunnels:     statuses,
	}
}

type managedTunnel struct {
	mu  sync.RWMutex
	cfg TunnelConfig

	cancel    context.CancelFunc
	done      chan struct{}
	exposure  *sdk.Exposure
	lastError string
	runtime   types.AgentTunnelStatus
}

func newTunnel(cfg TunnelConfig) *managedTunnel {
	return &managedTunnel{
		cfg: cfg,
	}
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
	t.mu.RLock()
	exposure := t.exposure
	t.mu.RUnlock()
	if exposure == nil {
		return nil
	}
	return exposure.AddRelay(relayURL)
}

func (t *managedTunnel) DisconnectRelay(relayURL string) error {
	t.mu.RLock()
	exposure := t.exposure
	t.mu.RUnlock()
	if exposure == nil {
		return nil
	}
	return exposure.RemoveRelay(relayURL)
}

func (t *managedTunnel) SetMultiHop(relayURLs []string) error {
	t.mu.RLock()
	exposure := t.exposure
	t.mu.RUnlock()
	if exposure == nil {
		return nil
	}
	return exposure.SetMultiHop(relayURLs)
}

func (t *managedTunnel) UpdateSettings(updateMetadata, updateMaxActiveRelays bool) error {
	t.mu.RLock()
	cfg := t.cfg
	exposure := t.exposure
	t.mu.RUnlock()
	if exposure == nil {
		return nil
	}
	var err error
	if updateMetadata {
		err = errors.Join(err, exposure.UpdateMetadata(metadataFromTunnelConfig(cfg)))
	}
	if updateMaxActiveRelays {
		err = errors.Join(err, exposure.UpdateMaxActiveRelays(cfg.MaxActiveRelays))
	}
	return err
}

func (t *managedTunnel) Snapshot() types.AgentTunnelStatus {
	t.mu.RLock()
	cfg := t.cfg
	lastError := t.lastError
	exposure := t.exposure
	done := t.done
	runtime := t.runtime
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

	status := types.AgentTunnelStatus{
		ID:              cfg.ID,
		Name:            cfg.Name,
		State:           state,
		TargetAddr:      cfg.TargetAddr,
		LastError:       lastError,
		MaxActiveRelays: cfg.MaxActiveRelays,
		Metadata:        metadataFromTunnelConfig(cfg),
		MultiHop:        append([]string(nil), cfg.MultiHop...),
	}
	if exposure == nil {
		if strings.TrimSpace(runtime.Address) != "" {
			status.Address = runtime.Address
		}
		if strings.TrimSpace(runtime.TargetAddr) != "" {
			status.TargetAddr = runtime.TargetAddr
		}
		if cfg.MultiHopDepth > 1 && len(runtime.MultiHop) > 0 {
			status.MultiHop = append([]string(nil), runtime.MultiHop...)
		}
		status.Relays = append([]types.AgentRelayStatus(nil), runtime.Relays...)
		return status
	}
	snapshot := exposure.Snapshot()
	t.mu.Lock()
	if t.exposure == exposure {
		t.runtime = types.AgentTunnelStatus{
			Address:         snapshot.Address,
			TargetAddr:      snapshot.TargetAddr,
			MaxActiveRelays: snapshot.MaxActiveRelays,
			MultiHop:        append([]string(nil), snapshot.MultiHop...),
			Relays:          append([]types.AgentRelayStatus(nil), snapshot.Relays...),
		}
	}
	t.mu.Unlock()

	status.Address = snapshot.Address
	status.TargetAddr = snapshot.TargetAddr
	status.MultiHop = append([]string(nil), snapshot.MultiHop...)
	status.Relays = append([]types.AgentRelayStatus(nil), snapshot.Relays...)
	return status
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
	cfg := t.cfg
	t.lastError = ""
	t.mu.Unlock()

	discovery := true
	if cfg.Discovery != nil {
		discovery = *cfg.Discovery
	}
	banMITM := true
	if cfg.BanMITM != nil {
		banMITM = *cfg.BanMITM
	}
	exposure, err := sdk.Expose(ctx, sdk.ExposeConfig{
		RelayURLs:       append([]string(nil), cfg.RelayURLs...),
		Discovery:       discovery,
		Identity:        types.Identity{Name: cfg.Name},
		IdentityPath:    cfg.IdentityPath,
		IdentityJSON:    cfg.IdentityJSON,
		TargetAddr:      cfg.TargetAddr,
		UDPAddr:         cfg.UDPAddr,
		UDPEnabled:      cfg.UDPEnabled,
		TCPEnabled:      cfg.TCPEnabled,
		MultiHop:        append([]string(nil), cfg.MultiHop...),
		MultiHopDepth:   cfg.MultiHopDepth,
		BanMITM:         banMITM,
		MaxActiveRelays: cfg.MaxActiveRelays,
		Metadata:        metadataFromTunnelConfig(cfg),
	})
	if err != nil {
		return err
	}
	snapshot := exposure.Snapshot()
	t.mu.Lock()
	t.exposure = exposure
	t.runtime = types.AgentTunnelStatus{
		Address:         snapshot.Address,
		TargetAddr:      snapshot.TargetAddr,
		MaxActiveRelays: snapshot.MaxActiveRelays,
		MultiHop:        append([]string(nil), snapshot.MultiHop...),
		Relays:          append([]types.AgentRelayStatus(nil), snapshot.Relays...),
	}
	t.lastError = ""
	t.mu.Unlock()

	defer exposure.Close()

	if len(cfg.HTTPRoutes) > 0 {
		routes := make([]sdk.HTTPRoute, 0, len(cfg.HTTPRoutes))
		for _, route := range cfg.HTTPRoutes {
			routes = append(routes, sdk.HTTPRoute{
				Prefix:   route.Prefix,
				Upstream: route.Upstream,
			})
		}
		err = exposure.RunHTTPRoutes(ctx, routes, "")
	} else {
		err = sdk.ProxyExposure(ctx, exposure)
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return ctx.Err()
	}
	return err
}

func metadataFromTunnelConfig(cfg TunnelConfig) types.LeaseMetadata {
	return types.LeaseMetadata{
		Description: strings.TrimSpace(cfg.Description),
		Tags:        normalizeAgentMetadataTags(cfg.Tags),
		Owner:       strings.TrimSpace(cfg.Owner),
		Thumbnail:   strings.TrimSpace(cfg.Thumbnail),
		Hide:        cfg.Hide,
	}
}

func normalizeAgentMetadataTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		if tag = strings.TrimSpace(tag); tag != "" {
			out = append(out, tag)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
