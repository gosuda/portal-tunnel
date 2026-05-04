package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
)

const RelayRegistryFilename = "registry.json"

func PortalRelayRegistryURLs() []string {
	return []string{
		"https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json",
		"https://object.rly.best/portal-tunnel/registry.json",
	}
}

type relayRegistry struct {
	Relays []string `json:"relays"`
}

// ResolveDiscoveryBootstraps resolves the bootstrap relay URL set for relay
// discovery: explicit URLs merged with the public registry, falling back to
// <stateDir>/registry.json when every registry endpoint is unreachable.
func ResolveDiscoveryBootstraps(ctx context.Context, stateDir string, explicit []string) ([]string, error) {
	explicit, err := NormalizeRelayURLs(explicit...)
	if err != nil {
		return nil, err
	}

	bootstraps, err := ResolvePortalRelayURLs(ctx, explicit, true)
	if err != nil {
		return nil, err
	}
	if len(bootstraps) > len(explicit) {
		return bootstraps, nil
	}

	registryPath := filepath.Join(stateDir, RelayRegistryFilename)
	log.Warn().Str("path", registryPath).Msg("relay registry fetch failed; falling back to local registry file")
	local, err := LoadLocalRelayRegistry(registryPath)
	switch {
	case err == nil:
		log.Info().Str("path", registryPath).Int("relays", len(local)).Msg("loaded relay registry from local fallback")
		return MergeRelayURLs(local, nil, explicit)
	case os.IsNotExist(err):
		log.Warn().Str("path", registryPath).Msg("local relay registry fallback file not found")
	default:
		log.Warn().Err(err).Str("path", registryPath).Msg("local relay registry fallback failed")
	}
	return bootstraps, nil
}

func ResolvePortalRelayURLs(ctx context.Context, explicit []string, includeDefaults bool) ([]string, error) {
	explicit, err := NormalizeRelayURLs(explicit...)
	if err != nil {
		return nil, err
	}
	if !includeDefaults {
		return explicit, nil
	}

	// TODO(@oesni): do not create a new client for each call
	client := NewHTTPClient(WithHTTPTimeout(3 * time.Second))
	for _, registryURL := range PortalRelayRegistryURLs() {
		defaults, err := fetchRelayRegistry(ctx, client, registryURL)
		if err != nil {
			continue
		}
		return MergeRelayURLs(defaults, nil, explicit)
	}
	return explicit, nil
}

// LoadLocalRelayRegistry reads a registry.json file with the
// {"relays": [...]} envelope and returns the normalized relay URLs.
func LoadLocalRelayRegistry(path string) ([]string, error) {
	var registry relayRegistry
	if err := ReadJSONFile(path, &registry); err != nil {
		return nil, err
	}
	return NormalizeRelayURLs(registry.Relays...)
}

func fetchRelayRegistry(ctx context.Context, client *http.Client, registryURL string) ([]string, error) {
	resp, err := httpDo(ctx, client, http.MethodGet, registryURL, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	var registry relayRegistry
	if err := json.NewDecoder(resp.Body).Decode(&registry); err != nil {
		return nil, fmt.Errorf("decode registry: %w", err)
	}
	defaults, err := NormalizeRelayURLs(registry.Relays...)
	if err != nil {
		return nil, fmt.Errorf("normalize relays: %w", err)
	}
	if len(defaults) == 0 {
		return nil, errors.New("registry contained no relay urls")
	}
	return defaults, nil
}
