package agent

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"unicode"

	"github.com/pelletier/go-toml/v2"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/agent/service"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errAgentStateDirIsRequired    = errors.New("agent.state_dir is required")
	errAgentControlAddrIsRequired = errors.New("agent.control_addr is required")
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
	Agent      AgentConfig    `toml:"agent,omitempty"`
	Tunnels    []TunnelConfig `toml:"tunnels"`
}

type AgentConfig struct {
	StateDir       string   `toml:"state_dir,omitempty"`
	ControlAddr    string   `toml:"control_addr,omitempty"`
	ServiceName    string   `toml:"service_name,omitempty"`
	AllowedWallets []string `toml:"allowed_wallets,omitempty"`
}

// TunnelConfig is one [[tunnels]] entry: the config of a tunnel under the ID the
// agent manages it by. The file, the Agent API and the dashboard change it, and
// Spec resolves it for the runtime.
type TunnelConfig struct {
	ID string `toml:"id,omitempty"`
	tunnel.Config
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
	if filepath.Clean(absPath) == filepath.Clean(service.DefaultConfigPath()) {
		if err := utils.EnsurePrivateDir(filepath.Dir(absPath)); err != nil {
			return Config{}, 0, fmt.Errorf("secure default agent config directory: %w", err)
		}
	}
	if err := utils.EnsurePrivateFile(absPath); err != nil {
		return Config{}, 0, fmt.Errorf("secure agent config: %w", err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return Config{}, 0, err
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return Config{}, 0, err
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return Config{}, 0, err
	}
	cfg.sourcePath = absPath
	if err := cfg.normalize(absPath); err != nil {
		return Config{}, 0, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, 0, err
	}
	return cfg, info.Mode().Perm(), nil
}

func writeConfigDocument(path string, mode os.FileMode, cfg Config) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}
	mode = cmp.Or(mode, 0o644)
	if err := utils.EnsurePrivateFile(path); err != nil {
		return fmt.Errorf("secure agent config before update: %w", err)
	}
	// EnsurePrivateFile does nothing outside Windows, and os.WriteFile keeps the
	// mode of a file that exists, so a 0644 config would hold a secret anyone can
	// read. The mode is restricted before the secret is written; when that is not
	// possible, nothing is written.
	if runtime.GOOS != "windows" && slices.ContainsFunc(cfg.Tunnels, TunnelConfig.holdsSecret) && mode&0o077 != 0 {
		mode &^= 0o077
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("restrict agent config that holds a secret: %w", err)
		}
	}
	return os.WriteFile(path, data, mode)
}

// holdsSecret reports whether writing the tunnel stores a credential: the
// OIDC client secret, an identity with its private key, or an x402 facilitator
// token.
func (cfg TunnelConfig) holdsSecret() bool {
	return strings.TrimSpace(cfg.OIDCClientSecret) != "" ||
		strings.TrimSpace(cfg.IdentityJSON) != "" ||
		strings.TrimSpace(cfg.FacilitatorToken) != ""
}

// normalize puts cfg in the form the agent saves and runs. The agent section
// gets its defaults. Each tunnel is normalized by tunnel.Config.Normalize, and
// its relative paths are resolved against the directory of the config file. A
// tunnel without an ID or an identity path gets one: they name the tunnel and
// its identity, so they are saved with it rather than derived again, which would
// move a tunnel to another identity once a second tunnel is added. No other
// default enters the config; Spec fills them in.
func (cfg *Config) normalize(configPath string) error {
	configDir := "."
	if absConfig, err := filepath.Abs(strings.TrimSpace(configPath)); err == nil {
		configDir = filepath.Dir(absConfig)
	}
	resolvePath := func(path string) string {
		if path != "" && !filepath.IsAbs(path) {
			return filepath.Join(configDir, path)
		}
		return path
	}

	cfg.Agent.StateDir = strings.TrimSpace(cfg.Agent.StateDir)
	cfg.Agent.ControlAddr = strings.TrimSpace(cfg.Agent.ControlAddr)
	cfg.Agent.ServiceName = strings.TrimSpace(cfg.Agent.ServiceName)
	cfg.Agent.AllowedWallets = utils.CompactStrings(cfg.Agent.AllowedWallets)
	if cfg.Agent.StateDir == "" {
		cfg.Agent.StateDir = service.DefaultDataDir()
	} else {
		cfg.Agent.StateDir = resolvePath(cfg.Agent.StateDir)
	}
	cfg.Agent.ControlAddr = cmp.Or(cfg.Agent.ControlAddr, DefaultControlAddr)
	cfg.Agent.ServiceName = cmp.Or(cfg.Agent.ServiceName, DefaultServiceName)

	for i := range cfg.Tunnels {
		t := &cfg.Tunnels[i]
		t.ID = cmp.Or(strings.TrimSpace(t.ID), strings.TrimSpace(t.Name), fmt.Sprintf("tunnel-%d", i+1))
		if err := t.Normalize(); err != nil {
			return fmt.Errorf("tunnel %q: %w", t.ID, err)
		}
		t.Serve = resolvePath(t.Serve)
		t.SAMLMetadataFile = resolvePath(t.SAMLMetadataFile)
		if t.IdentityPath == "" {
			if len(cfg.Tunnels) <= 1 {
				t.IdentityPath = filepath.Join(cfg.Agent.StateDir, defaultIdentityFilename)
			} else {
				t.IdentityPath = filepath.Join(cfg.Agent.StateDir, t.ID, defaultIdentityFilename)
			}
		} else {
			t.IdentityPath = resolvePath(t.IdentityPath)
		}
	}
	return nil
}

func (cfg Config) Validate() error {
	if strings.TrimSpace(cfg.Agent.StateDir) == "" {
		return errAgentStateDirIsRequired
	}
	if strings.TrimSpace(cfg.Agent.ControlAddr) == "" {
		return errAgentControlAddrIsRequired
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
	if _, err := cfg.Spec(); err != nil {
		return fmt.Errorf("tunnel %q: %w", cfg.ID, err)
	}
	return nil
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
