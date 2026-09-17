package identity

import (
	"path/filepath"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// TestLoadOrCreateRelayIdentityCreatesAndReloads protects the persistence contract that a relay
// identity (with EncryptedClientHelloSeed) is written to disk and reloaded unchanged, so the
// relay's ECH configuration and signing key survive process restarts.
func TestLoadOrCreateRelayIdentityCreatesAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, types.RelayIdentityFilename)
	created, err := LoadOrCreateRelayIdentity(path, "relay.example.com")
	if err != nil {
		t.Fatalf("create relay identity: %v", err)
	}
	if created.Name != "relay.example.com" || created.Address == "" || created.PrivateKey == "" || created.EncryptedClientHelloSeed == "" {
		t.Fatalf("created relay identity incomplete: %+v", created)
	}

	reloaded, err := LoadOrCreateRelayIdentity(path, "relay.example.com")
	if err != nil {
		t.Fatalf("reload relay identity: %v", err)
	}
	if reloaded.PrivateKey != created.PrivateKey || reloaded.EncryptedClientHelloSeed != created.EncryptedClientHelloSeed {
		t.Fatalf("reloaded relay identity mismatch: %+v", reloaded)
	}
}
