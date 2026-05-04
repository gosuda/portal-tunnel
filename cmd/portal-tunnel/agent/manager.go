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
	"unicode"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
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

func (m *manager) AddRelay(id, relayURL string) error {
	exposure, err := m.runningExposure(id)
	if err != nil {
		return err
	}
	return exposure.AddRelay(relayURL)
}

func (m *manager) RemoveRelay(id, relayURL string) error {
	exposure, err := m.runningExposure(id)
	if err != nil {
		return err
	}
	return exposure.RemoveRelay(relayURL)
}

func (m *manager) SeedRelay(id, relayURL string) error {
	exposure, err := m.runningExposure(id)
	if err != nil {
		return err
	}
	return exposure.SeedRelay(relayURL)
}

func (m *manager) SetMultiHop(id string, relayURLs []string) error {
	exposure, err := m.runningExposure(id)
	if err != nil {
		return err
	}
	return exposure.SetMultiHop(relayURLs)
}

func (m *manager) runningExposure(id string) (*sdk.Exposure, error) {
	id = strings.TrimSpace(id)
	m.mu.RLock()
	tunnel := m.tunnels[id]
	m.mu.RUnlock()
	if tunnel == nil {
		return nil, fmt.Errorf("unknown tunnel %q", id)
	}
	tunnel.mu.RLock()
	tunnelID := tunnel.cfg.ID
	exposure := tunnel.exposure
	tunnel.mu.RUnlock()
	if exposure == nil {
		return nil, fmt.Errorf("tunnel %q is not running", tunnelID)
	}
	return exposure, nil
}

func (m *manager) AddTunnel(req types.AgentTunnelRequest) error {
	m.configMu.Lock()
	defer m.configMu.Unlock()

	cfg, path, mode, err := m.loadConfigDocument()
	if err != nil {
		return err
	}
	m.preserveCurrentIdentityPaths(&cfg)
	id := strings.TrimSpace(req.ID)
	name := strings.TrimSpace(req.Name)
	if id == "" {
		id = agentTunnelID(name)
	}
	if id == "" {
		return errors.New("tunnel name is required")
	}
	if strings.ContainsAny(id, " \t\r\n/") {
		return errors.New("tunnel id cannot contain whitespace or slash")
	}
	target := strings.TrimSpace(req.TargetAddr)
	if target == "" {
		target = defaultTargetAddr
	}
	if name == "" {
		name = id
	}
	discovery := true
	tunnelCfg := TunnelConfig{
		ID:         id,
		Name:       name,
		TargetAddr: target,
		RelayURLs:  append([]string(nil), req.RelayURLs...),
		Discovery:  &discovery,
	}
	for _, tunnel := range cfg.Tunnels {
		if tunnel.ID == tunnelCfg.ID {
			return fmt.Errorf("tunnel %q already exists", tunnelCfg.ID)
		}
	}
	cfg.Tunnels = append(cfg.Tunnels, tunnelCfg)
	return m.writeConfigAndApply(path, mode, cfg)
}

func agentTunnelID(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var out strings.Builder
	dash := false
	for _, r := range name {
		if r == '/' || unicode.IsSpace(r) {
			if out.Len() > 0 && !dash {
				out.WriteByte('-')
				dash = true
			}
			continue
		}
		if r < 0x20 {
			continue
		}
		out.WriteRune(r)
		dash = false
	}
	return strings.Trim(out.String(), "-")
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
	m.preserveCurrentIdentityPaths(&cfg)
	if len(cfg.Tunnels) <= 1 {
		return errors.New("cannot delete the last tunnel")
	}

	next := cfg.Tunnels[:0]
	found := false
	for _, tunnel := range cfg.Tunnels {
		if tunnel.ID == id {
			found = true
			continue
		}
		next = append(next, tunnel)
	}
	if !found {
		return fmt.Errorf("tunnel %q not found", id)
	}
	cfg.Tunnels = next
	return m.writeConfigAndApply(path, mode, cfg)
}

func (m *manager) loadConfigDocument() (Config, string, os.FileMode, error) {
	m.mu.RLock()
	configPath := m.cfg.sourcePath
	m.mu.RUnlock()
	return loadConfigDocument(configPath)
}

func (m *manager) preserveCurrentIdentityPaths(cfg *Config) {
	m.mu.RLock()
	identityPathByID := make(map[string]string, len(m.cfg.Tunnels))
	for _, tunnel := range m.cfg.Tunnels {
		if strings.TrimSpace(tunnel.IdentityPath) != "" {
			identityPathByID[tunnel.ID] = tunnel.IdentityPath
		}
	}
	m.mu.RUnlock()

	for i := range cfg.Tunnels {
		tunnel := &cfg.Tunnels[i]
		if strings.TrimSpace(tunnel.IdentityPath) != "" {
			continue
		}
		if identityPath := identityPathByID[tunnel.ID]; identityPath != "" {
			tunnel.IdentityPath = identityPath
		}
	}
}

func (m *manager) writeConfigAndApply(path string, mode os.FileMode, cfg Config) error {
	if err := validateConfigDocument(path, cfg); err != nil {
		return err
	}
	if err := writeConfigDocument(path, mode, cfg); err != nil {
		return err
	}
	next, err := LoadConfig(path)
	if err != nil {
		return err
	}
	return m.ApplyConfig(next)
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
		if !reflect.DeepEqual(tunnel.cfg, tunnelCfg) {
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
}

func newTunnel(cfg TunnelConfig) *managedTunnel {
	return &managedTunnel{cfg: cfg}
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

func (t *managedTunnel) Snapshot() types.AgentTunnelStatus {
	t.mu.RLock()
	cfg := t.cfg
	lastError := t.lastError
	exposure := t.exposure
	done := t.done
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
		ID:         cfg.ID,
		Name:       cfg.Name,
		State:      state,
		TargetAddr: cfg.TargetAddr,
		LastError:  lastError,
	}
	if exposure == nil {
		return status
	}
	snapshot := exposure.Snapshot()
	status.TargetAddr = snapshot.TargetAddr
	status.MultiHop = append([]string(nil), snapshot.MultiHop...)
	status.Relays = append([]types.AgentRelayStatus(nil), snapshot.Relays...)
	return status
}

func (t *managedTunnel) runLoop(ctx context.Context) {
	err := t.runOnce(ctx)

	t.mu.Lock()
	t.exposure = nil
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || err == nil {
		t.lastError = ""
	} else {
		t.lastError = err.Error()
	}
	t.mu.Unlock()
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
		IdentityPath:    cfg.IdentityPath,
		IdentityJSON:    cfg.IdentityJSON,
		Name:            cfg.Name,
		TargetAddr:      cfg.TargetAddr,
		UDPAddr:         cfg.UDPAddr,
		UDPEnabled:      cfg.UDPEnabled,
		TCPEnabled:      cfg.TCPEnabled,
		MultiHop:        append([]string(nil), cfg.MultiHop...),
		MultiHopDepth:   cfg.MultiHopDepth,
		BanMITM:         banMITM,
		MaxActiveRelays: cfg.MaxActiveRelays,
		Metadata: types.LeaseMetadata{
			Description: cfg.Description,
			Tags:        append([]string(nil), cfg.Tags...),
			Owner:       cfg.Owner,
			Thumbnail:   cfg.Thumbnail,
			Hide:        cfg.Hide,
		},
	})
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.exposure = exposure
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
