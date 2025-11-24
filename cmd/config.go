package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

var defaultProtocols = []string{"http/1.1", "h2"}

// RelayConfig describes a named relay endpoint and its bootstrap URLs.
type RelayConfig struct {
	Name string   `yaml:"name"`
	URLs []string `yaml:"urls"`
}

// ServiceConfig describes a local service exposed through the tunnel.
type ServiceConfig struct {
	Name            string   `yaml:"name"`
	RelayPreference []string `yaml:"relayPreference"`
	Target          string   `yaml:"target"`
	Protocols       []string `yaml:"protocols"`
}

// TunnelConfig represents the YAML configuration schema for portal-tunnel.
type TunnelConfig struct {
	Relays   []RelayConfig   `yaml:"relays"`
	Services []ServiceConfig `yaml:"services"`
}

// RelayDirectory provides lookup helpers for relay definitions.
type RelayDirectory struct {
	entries map[string]RelayConfig
}

// LoadConfig reads the YAML file at path, parses it into TunnelConfig, and validates it.
func LoadConfig(path string) (*TunnelConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg TunnelConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// NewRelayDirectory builds a lookup structure for relay definitions.
func NewRelayDirectory(relays []RelayConfig) *RelayDirectory {
	idx := make(map[string]RelayConfig, len(relays))
	for _, relay := range relays {
		idx[relay.Name] = relay
	}
	return &RelayDirectory{entries: idx}
}

// BootstrapServers aggregates URLs for the given relay preference list.
// Preference order is preserved and duplicate URLs are removed.
func (rd *RelayDirectory) BootstrapServers(preferences []string) ([]string, error) {
	if len(preferences) == 0 {
		return nil, fmt.Errorf("relayPreference must contain at least one relay name")
	}

	seen := map[string]struct{}{}
	var servers []string
	for _, relayName := range preferences {
		relayName = strings.TrimSpace(relayName)
		if relayName == "" {
			continue
		}
		relay, ok := rd.entries[relayName]
		if !ok {
			continue
		}
		for _, url := range relay.URLs {
			url = strings.TrimSpace(url)
			if url == "" {
				continue
			}
			if _, exists := seen[url]; exists {
				continue
			}
			seen[url] = struct{}{}
			servers = append(servers, url)
		}
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf("no bootstrap servers resolved for relayPreference %v", preferences)
	}

	return servers, nil
}

func (cfg *TunnelConfig) validate() error {
	var errs []string

	relayIdx := map[string]RelayConfig{}
	if len(cfg.Relays) == 0 {
		errs = append(errs, "at least one relay must be defined")
	}
	for i, relay := range cfg.Relays {
		prefix := fmt.Sprintf("relays[%d]", i)
		name := strings.TrimSpace(relay.Name)
		if name == "" {
			errs = append(errs, fmt.Sprintf("%s: name is required", prefix))
		} else {
			if _, exists := relayIdx[name]; exists {
				errs = append(errs, fmt.Sprintf("%s: duplicate relay name %q", prefix, name))
			} else {
				relayIdx[name] = relay
			}
		}

		if len(relay.URLs) == 0 {
			errs = append(errs, fmt.Sprintf("%s: at least one url is required", prefix))
		}
		for j, url := range relay.URLs {
			if strings.TrimSpace(url) == "" {
				errs = append(errs, fmt.Sprintf("%s.urls[%d]: url cannot be empty", prefix, j))
			}
		}
	}

	if len(cfg.Services) == 0 {
		errs = append(errs, "at least one service must be defined")
	}
	for i, service := range cfg.Services {
		prefix := fmt.Sprintf("services[%d]", i)
		name := strings.TrimSpace(service.Name)
		if name == "" {
			errs = append(errs, fmt.Sprintf("%s: name is required", prefix))
		}
		target := strings.TrimSpace(service.Target)
		if target == "" {
			errs = append(errs, fmt.Sprintf("%s: target is required", prefix))
		}
		for j, proto := range service.Protocols {
			if strings.TrimSpace(proto) == "" {
				errs = append(errs, fmt.Sprintf("%s.protocols[%d]: protocol cannot be empty", prefix, j))
			}
		}
		if len(service.RelayPreference) == 0 {
			errs = append(errs, fmt.Sprintf("%s: relayPreference must list at least one relay name", prefix))
		}
		for j, relayName := range service.RelayPreference {
			relayName = strings.TrimSpace(relayName)
			if relayName == "" {
				errs = append(errs, fmt.Sprintf("%s.relayPreference[%d]: relay name cannot be empty", prefix, j))
				continue
			}
			if _, exists := relayIdx[relayName]; !exists {
				errs = append(errs, fmt.Sprintf("%s.relayPreference[%d]: relay %q is not defined", prefix, j, relayName))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid config:\n - %s", strings.Join(errs, "\n - "))
	}

	return nil
}

func (cfg *TunnelConfig) applyDefaults() {
	for i := range cfg.Services {
		applyServiceDefaults(&cfg.Services[i])
	}
}

func applyServiceDefaults(svc *ServiceConfig) {
	if len(svc.Protocols) == 0 {
		svc.Protocols = append([]string(nil), defaultProtocols...)
	}
}
