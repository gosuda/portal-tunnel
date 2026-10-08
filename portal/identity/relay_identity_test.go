package identity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestLoadOrCreateRelayIdentityCreatesAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, types.RelayIdentityFilename)
	created, err := LoadOrCreateRelayIdentity(path, "relay.example.com")
	if err != nil {
		t.Fatalf("create relay identity: %v", err)
	}
	if created.Name != "relay.example.com" || created.Address == "" || created.PrivateKey == "" {
		t.Fatalf("created relay identity incomplete: %+v", created)
	}

	reloaded, err := LoadOrCreateRelayIdentity(path, "relay.example.com")
	if err != nil {
		t.Fatalf("reload relay identity: %v", err)
	}
	if reloaded.PrivateKey != created.PrivateKey {
		t.Fatalf("reloaded relay identity mismatch: %+v", reloaded)
	}
}

// Relay identities written by older relays may carry a stale seed key that
// no longer exists in the file schema; it must be ignored, not rejected.
func TestLoadOrCreateRelayIdentityToleratesStaleSeed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, types.RelayIdentityFilename)
	created, err := LoadOrCreateRelayIdentity(path, "relay.example.com")
	if err != nil {
		t.Fatalf("create relay identity: %v", err)
	}

	stale, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read identity file: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(stale, &payload); err != nil {
		t.Fatalf("decode identity file: %v", err)
	}
	payload["encrypted_client_hello_seed"] = "stale-seed"
	withSeed, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode identity file: %v", err)
	}
	if err := os.WriteFile(path, withSeed, 0o600); err != nil {
		t.Fatalf("write identity file: %v", err)
	}

	reloaded, err := LoadOrCreateRelayIdentity(path, "relay.example.com")
	if err != nil {
		t.Fatalf("reload identity with stale seed: %v", err)
	}
	if reloaded.PrivateKey != created.PrivateKey {
		t.Fatalf("reloaded relay identity mismatch: %+v", reloaded)
	}
}
