package utils

// LoadLocalRelayRegistry reads a registry.json file with the
// {"relays": [...]} envelope and returns the normalized relay URLs.
func LoadLocalRelayRegistry(path string) ([]string, error) {
	var registry struct {
		Relays []string `json:"relays"`
	}
	if err := ReadJSONFile(path, &registry); err != nil {
		return nil, err
	}
	return NormalizeRelayURLs(registry.Relays...)
}
