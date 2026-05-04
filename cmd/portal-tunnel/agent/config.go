package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/knadh/koanf/parsers/toml/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/agent/service"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	DefaultControlAddr = "127.0.0.1:4018"
	DefaultServiceName = "portal-agent"

	defaultIdentityFilename = "identity.json"
	defaultTargetAddr       = "127.0.0.1:3000"
)

type Config struct {
	sourcePath string
	Agent      AgentConfig    `koanf:"agent"`
	Tunnels    []TunnelConfig `koanf:"tunnels"`
}

type AgentConfig struct {
	StateDir    string `koanf:"state_dir"`
	ControlAddr string `koanf:"control_addr"`
	ServiceName string `koanf:"service_name"`
}

type TunnelConfig struct {
	ID              string            `koanf:"id"`
	Name            string            `koanf:"name"`
	TargetAddr      string            `koanf:"target"`
	HTTPRoutes      []HTTPRouteConfig `koanf:"http_routes"`
	RelayURLs       []string          `koanf:"relays"`
	Discovery       *bool             `koanf:"discovery"`
	IdentityPath    string            `koanf:"identity_path"`
	IdentityJSON    string            `koanf:"identity_json"`
	UDPEnabled      bool              `koanf:"udp"`
	UDPAddr         string            `koanf:"udp_addr"`
	TCPEnabled      bool              `koanf:"tcp"`
	MultiHop        []string          `koanf:"multi_hop"`
	MultiHopDepth   int               `koanf:"multi_hop_depth"`
	BanMITM         *bool             `koanf:"ban_mitm"`
	MaxActiveRelays int               `koanf:"max_active_relays"`
	Description     string            `koanf:"description"`
	Tags            []string          `koanf:"tags"`
	Owner           string            `koanf:"owner"`
	Thumbnail       string            `koanf:"thumbnail"`
	Hide            bool              `koanf:"hide"`
}

type HTTPRouteConfig struct {
	Prefix   string `koanf:"prefix"`
	Upstream string `koanf:"upstream"`
}

func LoadConfig(path string) (Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = service.DefaultConfigPath()
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return Config{}, err
	}
	configDir := filepath.Dir(absPath)
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return Config{}, fmt.Errorf("create agent config directory %q: %w", configDir, err)
	}
	if _, err := os.Stat(absPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			data := fmt.Sprintf(`[agent]
state_dir = %q
control_addr = %q
service_name = %q

[[tunnels]]
id = "default"
name = "default"
target = %q
discovery = true
`, service.DefaultDataDir(), DefaultControlAddr, DefaultServiceName, defaultTargetAddr)
			if err := os.WriteFile(absPath, []byte(data), 0o644); err != nil {
				return Config{}, fmt.Errorf("create default agent config %q: %w", absPath, err)
			}
		} else {
			return Config{}, err
		}
	}

	k := koanf.New(".")
	if err := k.Load(file.Provider(absPath), toml.Parser()); err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return Config{}, err
	}
	cfg.sourcePath = absPath
	if err := cfg.ApplyDefaults(absPath); err != nil {
		return Config{}, err
	}
	return cfg, cfg.Validate()
}

func loadConfigDocument(path string) (Config, string, os.FileMode, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = service.DefaultConfigPath()
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return Config{}, "", 0, err
	}
	if _, err := os.Stat(absPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if _, err := LoadConfig(absPath); err != nil {
				return Config{}, "", 0, err
			}
		} else {
			return Config{}, "", 0, err
		}
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return Config{}, "", 0, err
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return Config{}, "", 0, err
	}

	var cfg Config
	if strings.TrimSpace(string(data)) != "" {
		k := koanf.New(".")
		if err := k.Load(file.Provider(absPath), toml.Parser()); err != nil {
			return Config{}, "", 0, err
		}
		if err := k.Unmarshal("", &cfg); err != nil {
			return Config{}, "", 0, err
		}
	}
	cfg.sourcePath = absPath
	return cfg, absPath, info.Mode().Perm(), nil
}

func writeConfigDocument(path string, mode os.FileMode, cfg Config) error {
	data, err := toml.Parser().Marshal(configDocumentMap(cfg))
	if err != nil {
		return err
	}
	if mode == 0 {
		mode = 0o644
	}
	return os.WriteFile(path, data, mode)
}

func configDocumentMap(cfg Config) map[string]any {
	return map[string]any{
		"agent":   agentConfigDocumentMap(cfg.Agent),
		"tunnels": tunnelConfigDocumentMaps(cfg.Tunnels),
	}
}

func agentConfigDocumentMap(cfg AgentConfig) map[string]any {
	out := make(map[string]any)
	addStringDocumentField(out, "state_dir", cfg.StateDir)
	addStringDocumentField(out, "control_addr", cfg.ControlAddr)
	addStringDocumentField(out, "service_name", cfg.ServiceName)
	return out
}

func tunnelConfigDocumentMaps(tunnels []TunnelConfig) []map[string]any {
	out := make([]map[string]any, 0, len(tunnels))
	for _, tunnel := range tunnels {
		out = append(out, tunnelConfigDocumentMap(tunnel))
	}
	return out
}

func tunnelConfigDocumentMap(cfg TunnelConfig) map[string]any {
	out := make(map[string]any)
	addStringDocumentField(out, "id", cfg.ID)
	addStringDocumentField(out, "name", cfg.Name)
	addStringDocumentField(out, "target", cfg.TargetAddr)
	if len(cfg.HTTPRoutes) > 0 {
		routes := make([]map[string]any, 0, len(cfg.HTTPRoutes))
		for _, route := range cfg.HTTPRoutes {
			routeMap := make(map[string]any)
			addStringDocumentField(routeMap, "prefix", route.Prefix)
			addStringDocumentField(routeMap, "upstream", route.Upstream)
			routes = append(routes, routeMap)
		}
		out["http_routes"] = routes
	}
	addStringSliceDocumentField(out, "relays", cfg.RelayURLs)
	if cfg.Discovery != nil {
		out["discovery"] = *cfg.Discovery
	}
	addStringDocumentField(out, "identity_path", cfg.IdentityPath)
	addStringDocumentField(out, "identity_json", cfg.IdentityJSON)
	if cfg.UDPEnabled {
		out["udp"] = cfg.UDPEnabled
	}
	addStringDocumentField(out, "udp_addr", cfg.UDPAddr)
	if cfg.TCPEnabled {
		out["tcp"] = cfg.TCPEnabled
	}
	addStringSliceDocumentField(out, "multi_hop", cfg.MultiHop)
	if cfg.MultiHopDepth != 0 {
		out["multi_hop_depth"] = cfg.MultiHopDepth
	}
	if cfg.BanMITM != nil {
		out["ban_mitm"] = *cfg.BanMITM
	}
	if cfg.MaxActiveRelays != 0 {
		out["max_active_relays"] = cfg.MaxActiveRelays
	}
	addStringDocumentField(out, "description", cfg.Description)
	addStringSliceDocumentField(out, "tags", cfg.Tags)
	addStringDocumentField(out, "owner", cfg.Owner)
	addStringDocumentField(out, "thumbnail", cfg.Thumbnail)
	if cfg.Hide {
		out["hide"] = cfg.Hide
	}
	return out
}

func addStringDocumentField(out map[string]any, key, value string) {
	if strings.TrimSpace(value) != "" {
		out[key] = value
	}
}

func addStringSliceDocumentField(out map[string]any, key string, value []string) {
	if len(value) > 0 {
		out[key] = append([]string(nil), value...)
	}
}

func validateConfigDocument(path string, cfg Config) error {
	next := cloneConfig(cfg)
	if err := next.ApplyDefaults(path); err != nil {
		return err
	}
	return next.Validate()
}

func cloneConfig(cfg Config) Config {
	next := cfg
	next.Tunnels = append([]TunnelConfig(nil), cfg.Tunnels...)
	for i := range next.Tunnels {
		tunnel := &next.Tunnels[i]
		tunnel.HTTPRoutes = append([]HTTPRouteConfig(nil), tunnel.HTTPRoutes...)
		tunnel.RelayURLs = append([]string(nil), tunnel.RelayURLs...)
		tunnel.MultiHop = append([]string(nil), tunnel.MultiHop...)
		tunnel.Tags = append([]string(nil), tunnel.Tags...)
		if tunnel.Discovery != nil {
			value := *tunnel.Discovery
			tunnel.Discovery = &value
		}
		if tunnel.BanMITM != nil {
			value := *tunnel.BanMITM
			tunnel.BanMITM = &value
		}
	}
	return next
}

func (cfg *Config) ApplyDefaults(configPath string) error {
	configDir := "."
	if absConfig, err := filepath.Abs(strings.TrimSpace(configPath)); err == nil {
		configDir = filepath.Dir(absConfig)
	}

	if strings.TrimSpace(cfg.Agent.StateDir) == "" {
		cfg.Agent.StateDir = service.DefaultDataDir()
	} else if !filepath.IsAbs(cfg.Agent.StateDir) {
		cfg.Agent.StateDir = filepath.Join(configDir, cfg.Agent.StateDir)
	}
	if strings.TrimSpace(cfg.Agent.ControlAddr) == "" {
		cfg.Agent.ControlAddr = DefaultControlAddr
	}
	if strings.TrimSpace(cfg.Agent.ServiceName) == "" {
		cfg.Agent.ServiceName = DefaultServiceName
	}

	for i := range cfg.Tunnels {
		t := &cfg.Tunnels[i]
		t.ID = strings.TrimSpace(t.ID)
		t.Name = strings.TrimSpace(t.Name)
		if t.ID == "" {
			t.ID = t.Name
		}
		if t.ID == "" {
			t.ID = fmt.Sprintf("tunnel-%d", i+1)
		}
		if t.IdentityPath == "" {
			if len(cfg.Tunnels) <= 1 {
				t.IdentityPath = filepath.Join(cfg.Agent.StateDir, defaultIdentityFilename)
			} else {
				t.IdentityPath = filepath.Join(cfg.Agent.StateDir, t.ID, defaultIdentityFilename)
			}
		} else if !filepath.IsAbs(t.IdentityPath) {
			t.IdentityPath = filepath.Join(configDir, t.IdentityPath)
		}
		if t.MaxActiveRelays == 0 {
			t.MaxActiveRelays = 3
		}
		if len(t.RelayURLs) > 0 {
			relays, err := utils.NormalizeRelayURLs(t.RelayURLs...)
			if err != nil {
				return fmt.Errorf("tunnel %q relays: %w", t.ID, err)
			}
			t.RelayURLs = relays
		}
		for idx, relayURL := range t.MultiHop {
			normalized, err := utils.NormalizeRelayURL(relayURL)
			if err != nil {
				return fmt.Errorf("tunnel %q multi_hop: %w", t.ID, err)
			}
			t.MultiHop[idx] = normalized
		}
	}
	return nil
}

func (cfg Config) Validate() error {
	if strings.TrimSpace(cfg.Agent.StateDir) == "" {
		return errors.New("agent.state_dir is required")
	}
	if strings.TrimSpace(cfg.Agent.ControlAddr) == "" {
		return errors.New("agent.control_addr is required")
	}
	if len(cfg.Tunnels) == 0 {
		return errors.New("at least one tunnel is required")
	}

	seen := make(map[string]struct{}, len(cfg.Tunnels))
	for _, tunnel := range cfg.Tunnels {
		if err := tunnel.Validate(); err != nil {
			return err
		}
		if _, ok := seen[tunnel.ID]; ok {
			return fmt.Errorf("duplicate tunnel id %q", tunnel.ID)
		}
		seen[tunnel.ID] = struct{}{}
	}
	return nil
}

func (cfg TunnelConfig) Validate() error {
	if strings.TrimSpace(cfg.ID) == "" {
		return errors.New("tunnel id is required")
	}
	if strings.TrimSpace(cfg.TargetAddr) == "" && len(cfg.HTTPRoutes) == 0 {
		return fmt.Errorf("tunnel %q requires target or http_routes", cfg.ID)
	}
	if strings.TrimSpace(cfg.TargetAddr) != "" && len(cfg.HTTPRoutes) > 0 {
		return fmt.Errorf("tunnel %q cannot combine target and http_routes", cfg.ID)
	}
	if len(cfg.HTTPRoutes) > 0 && cfg.UDPEnabled {
		return fmt.Errorf("tunnel %q cannot combine udp and http_routes", cfg.ID)
	}
	if cfg.MultiHopDepth < 0 {
		return fmt.Errorf("tunnel %q multi_hop_depth cannot be negative", cfg.ID)
	}
	if len(cfg.MultiHop) == 1 {
		return fmt.Errorf("tunnel %q multi_hop requires at least entry and exit relays", cfg.ID)
	}
	if len(cfg.MultiHop) > 0 && cfg.MultiHopDepth > 1 {
		return fmt.Errorf("tunnel %q cannot combine multi_hop and multi_hop_depth", cfg.ID)
	}
	for _, route := range cfg.HTTPRoutes {
		if strings.TrimSpace(route.Prefix) == "" || strings.TrimSpace(route.Upstream) == "" {
			return fmt.Errorf("tunnel %q http_routes require prefix and upstream", cfg.ID)
		}
	}
	return nil
}
