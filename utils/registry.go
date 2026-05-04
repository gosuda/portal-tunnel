package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

type relayRegistry struct {
	Relays []string `json:"relays"`
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
	for _, registryURL := range types.PortalRelayRegistryURLs() {
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
