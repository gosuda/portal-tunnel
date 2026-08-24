package agent

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

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
	agentPathInvalidChars   = `<>:"/\|?*`
)

type Config struct {
	sourcePath string
	Agent      AgentConfig    `koanf:"agent"`
	Tunnels    []TunnelConfig `koanf:"tunnels"`
}

type AgentConfig struct {
	StateDir       string   `koanf:"state_dir"`
	ControlAddr    string   `koanf:"control_addr"`
	ServiceName    string   `koanf:"service_name"`
	AllowedWallets []string `koanf:"allowed_wallets"`
}

type TunnelConfig struct {
	ID                   string            `koanf:"id"`
	Name                 string            `koanf:"name"`
	TargetAddr           string            `koanf:"target"`
	HTTPRoutes           []HTTPRouteConfig `koanf:"http_routes"`
	RelayURLs            []string          `koanf:"relays"`
	Discovery            *bool             `koanf:"discovery"`
	IdentityPath         string            `koanf:"identity_path"`
	IdentityJSON         string            `koanf:"identity_json"`
	UDPEnabled           bool              `koanf:"udp"`
	UDPAddr              string            `koanf:"udp_addr"`
	TCPEnabled           bool              `koanf:"tcp"`
	ECH                  bool              `koanf:"ech"`
	MultiHop             []string          `koanf:"multi_hop"`
	MultiHopDepth        int               `koanf:"multi_hop_depth"`
	BanMITM              *bool             `koanf:"ban_mitm"`
	MaxActiveRelays      int               `koanf:"max_active_relays"`
	Description          string            `koanf:"description"`
	Tags                 []string          `koanf:"tags"`
	Owner                string            `koanf:"owner"`
	Thumbnail            string            `koanf:"thumbnail"`
	Hide                 bool              `koanf:"hide"`
	X402PayTo            string            `koanf:"x402_pay_to"`
	X402Testnet          bool              `koanf:"x402_testnet"`
	X402Network          string            `koanf:"x402_network"`
	X402Asset            string            `koanf:"x402_asset"`
	X402Endpoints        []string          `koanf:"x402_endpoints"`
	X402FacilitatorToken string            `koanf:"x402_facilitator_token"`
}

type HTTPRouteConfig struct {
	Prefix   string   `koanf:"prefix"`
	Upstream string   `koanf:"upstream"`
	Methods  []string `koanf:"methods"`
	Amount   string   `koanf:"amount"`
}

func LoadExistingConfig(path string) (Config, error) {
	path = strings.TrimSpace(path)
	path = cmp.Or(path, service.DefaultConfigPath())
	absPath, err := filepath.Abs(path)
	if err != nil {
		return Config{}, err
	}
	if _, err := os.Stat(absPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, fmt.Errorf("agent config %q does not exist", absPath)
		}
		return Config{}, err
	}
	cfg, _, err := readConfigDocument(absPath)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func loadConfigDocument(path string) (Config, string, os.FileMode, error) {
	path = strings.TrimSpace(path)
	path = cmp.Or(path, service.DefaultConfigPath())
	absPath, err := filepath.Abs(path)
	if err != nil {
		return Config{}, "", 0, err
	}
	cfg, mode, err := readConfigDocument(absPath)
	if err != nil {
		return Config{}, "", 0, err
	}
	return cfg, absPath, mode, nil
}

func readConfigDocument(absPath string) (Config, os.FileMode, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return Config{}, 0, err
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return Config{}, 0, err
	}

	var cfg Config
	if strings.TrimSpace(string(data)) != "" {
		k := koanf.New(".")
		if err := k.Load(file.Provider(absPath), toml.Parser()); err != nil {
			return Config{}, 0, err
		}
		if err := k.Unmarshal("", &cfg); err != nil {
			return Config{}, 0, err
		}
	}
	cfg.sourcePath = absPath
	if err := cfg.ApplyDefaults(absPath); err != nil {
		return Config{}, 0, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, 0, err
	}
	return cfg, info.Mode().Perm(), nil
}

func writeConfigDocument(path string, mode os.FileMode, cfg Config) error {
	data, err := toml.Parser().Marshal(configMap(cfg))
	if err != nil {
		return err
	}
	mode = cmp.Or(mode, 0o644)
	return os.WriteFile(path, data, mode)
}

func configMap(cfg Config) map[string]any {
	agent := make(map[string]any)
	addStringDocumentField(agent, "state_dir", cfg.Agent.StateDir)
	addStringDocumentField(agent, "control_addr", cfg.Agent.ControlAddr)
	addStringDocumentField(agent, "service_name", cfg.Agent.ServiceName)
	addStringSliceDocumentField(agent, "allowed_wallets", cfg.Agent.AllowedWallets)

	tunnels := make([]map[string]any, 0, len(cfg.Tunnels))
	for _, tunnel := range cfg.Tunnels {
		tunnels = append(tunnels, tunnelConfigDocumentMap(tunnel))
	}

	out := map[string]any{
		"tunnels": tunnels,
	}
	if len(agent) > 0 {
		out["agent"] = agent
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
			addStringSliceDocumentField(routeMap, "methods", route.Methods)
			addStringDocumentField(routeMap, "amount", route.Amount)
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
	if cfg.ECH {
		out["ech"] = cfg.ECH
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
	addStringDocumentField(out, "x402_pay_to", cfg.X402PayTo)
	if cfg.X402Testnet {
		out["x402_testnet"] = cfg.X402Testnet
	}
	addStringDocumentField(out, "x402_network", cfg.X402Network)
	addStringDocumentField(out, "x402_asset", cfg.X402Asset)
	addStringSliceDocumentField(out, "x402_endpoints", cfg.X402Endpoints)
	addStringDocumentField(out, "x402_facilitator_token", cfg.X402FacilitatorToken)
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

func (cfg *Config) ApplyDefaults(configPath string) error {
	configDir := "."
	if absConfig, err := filepath.Abs(strings.TrimSpace(configPath)); err == nil {
		configDir = filepath.Dir(absConfig)
	}

	cfg.Agent.StateDir = strings.TrimSpace(cfg.Agent.StateDir)
	cfg.Agent.ControlAddr = strings.TrimSpace(cfg.Agent.ControlAddr)
	cfg.Agent.ServiceName = strings.TrimSpace(cfg.Agent.ServiceName)
	allowedWallets := cfg.Agent.AllowedWallets[:0]
	for _, wallet := range cfg.Agent.AllowedWallets {
		if wallet = strings.TrimSpace(wallet); wallet != "" {
			allowedWallets = append(allowedWallets, wallet)
		}
	}
	cfg.Agent.AllowedWallets = allowedWallets
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
		t.X402Network = strings.ToLower(strings.TrimSpace(t.X402Network))
		t.X402Asset = strings.TrimSpace(t.X402Asset)
		t.X402Endpoints = compactStrings(t.X402Endpoints)
		t.X402FacilitatorToken = strings.TrimSpace(t.X402FacilitatorToken)
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
	if err := validateAgentPathComponent("agent.service_name", cfg.Agent.ServiceName); err != nil {
		return err
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
	if err := validateAgentPathComponent("tunnel id", cfg.ID); err != nil {
		return err
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
	multiHopEnabled := len(cfg.MultiHop) > 0 || cfg.MultiHopDepth > 1
	nonStreamTransport := cfg.UDPEnabled || cfg.TCPEnabled
	if multiHopEnabled && nonStreamTransport {
		return fmt.Errorf("tunnel %q multi-hop supports only the default stream transport", cfg.ID)
	}
	if len(cfg.MultiHop) > 0 {
		uniqueMultiHop, err := utils.NormalizeRelayURLs(cfg.MultiHop...)
		if err != nil {
			return fmt.Errorf("tunnel %q multi_hop: %w", cfg.ID, err)
		}
		if len(uniqueMultiHop) != len(cfg.MultiHop) {
			return fmt.Errorf("tunnel %q multi_hop relay repeated", cfg.ID)
		}
	}
	for _, route := range cfg.HTTPRoutes {
		if strings.TrimSpace(route.Prefix) == "" || strings.TrimSpace(route.Upstream) == "" {
			return fmt.Errorf("tunnel %q http_routes require prefix and upstream", cfg.ID)
		}
		if strings.TrimSpace(route.Amount) != "" && strings.TrimSpace(cfg.X402PayTo) == "" {
			return fmt.Errorf("tunnel %q http route %q amount requires x402_pay_to", cfg.ID, strings.TrimSpace(route.Prefix))
		}
		if strings.TrimSpace(route.Amount) == "" && len(route.Methods) > 0 {
			return fmt.Errorf("tunnel %q http route %q methods require amount", cfg.ID, strings.TrimSpace(route.Prefix))
		}
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(cfg.X402Network)), "casper:") && strings.TrimSpace(cfg.X402Asset) == "" {
		return fmt.Errorf("tunnel %q Casper payments require x402_asset", cfg.ID)
	}
	return nil
}

func compactStrings(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func validateAgentPathComponent(name, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}
	if value == "." || value == ".." {
		return fmt.Errorf("%s cannot be %q", name, value)
	}
	for _, r := range value {
		if invalidAgentPathComponentRune(r) {
			return fmt.Errorf("%s contains invalid character %q", name, r)
		}
	}
	return nil
}

func invalidAgentPathComponentRune(r rune) bool {
	return unicode.IsSpace(r) || r < 0x20 || r == 0x7f || strings.ContainsRune(agentPathInvalidChars, r)
}
