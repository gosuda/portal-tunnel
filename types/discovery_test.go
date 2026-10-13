package types

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDiscoveryResponseRejectsOversizedCollections(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		body string
	}{
		{"relays", "{\"relays\":[" + strings.Repeat("{},", MaxDiscoveryEntries*64) + "{}]}"},
		{"incompatible relays", "{\"incompatible_relays\":[" + strings.Repeat("{},", MaxDiscoveryEntries) + "{}]}"},
		{"release versions", "{\"relay_release_versions\":{" + strings.Repeat("\"same\":\"v\",", MaxDiscoveryEntries) + "\"last\":\"v\"}}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var resp DiscoveryResponse
			if err := json.Unmarshal([]byte(tc.body), &resp); err == nil || !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("json.Unmarshal() error = %v, want collection limit error", err)
			}
		})
	}
}

func TestDiscoveryResponseAcceptsMaximumRelays(t *testing.T) {
	t.Parallel()

	body := "{\"relays\":[" + strings.Repeat("{},", MaxDiscoveryEntries-1) + "{}]}"
	var resp DiscoveryResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error = %v, want success", err)
	}
	if len(resp.Relays) != MaxDiscoveryEntries {
		t.Fatalf("relay count = %d, want %d", len(resp.Relays), MaxDiscoveryEntries)
	}
}

func TestDiscoveryResponseAllowsSelfAndCappedPool(t *testing.T) {
	t.Parallel()

	body := "{\"relays\":[" + strings.Repeat("{},", MaxDiscoveryEntries) + "{}]}"
	var resp DiscoveryResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error = %v, want success", err)
	}
	if len(resp.Relays) != MaxDiscoveryEntries+1 {
		t.Fatalf("relay count = %d, want %d", len(resp.Relays), MaxDiscoveryEntries+1)
	}
}

func TestDiscoveryResponseRejectsMoreThanSelfAndCappedPool(t *testing.T) {
	t.Parallel()

	body := "{\"relays\":[" + strings.Repeat("{},", MaxDiscoveryEntries+1) + "{}]}"
	var resp DiscoveryResponse
	if err := json.Unmarshal([]byte(body), &resp); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("json.Unmarshal() error = %v, want relay collection limit", err)
	}
}
