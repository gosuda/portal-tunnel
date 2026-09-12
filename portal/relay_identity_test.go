package portal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateRelayIdentityCreatesAndReloads(t *testing.T) {
	dir := t.TempDir()
	created, err := LoadOrCreateRelayIdentity(dir, "relay.example.com")
	if err != nil {
		t.Fatalf("create relay identity: %v", err)
	}
	if created.Name != "relay.example.com" || created.Address == "" || created.PrivateKey == "" || created.EncryptedClientHelloSeed == "" {
		t.Fatalf("created relay identity incomplete: %+v", created)
	}

	reloaded, err := LoadOrCreateRelayIdentity(dir, "relay.example.com")
	if err != nil {
		t.Fatalf("reload relay identity: %v", err)
	}
	if reloaded.PrivateKey != created.PrivateKey || reloaded.EncryptedClientHelloSeed != created.EncryptedClientHelloSeed {
		t.Fatalf("reloaded relay identity mismatch: %+v", reloaded)
	}
}

func TestLoadOrCreateRelayIdentityPreservesUnchangedFile(t *testing.T) {
	dir := t.TempDir()
	created, err := LoadOrCreateRelayIdentity(dir, "relay.example.com")
	if err != nil {
		t.Fatalf("create relay identity: %v", err)
	}
	path := filepath.Join(dir, "identity.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read relay identity: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat relay identity: %v", err)
	}

	if _, err := LoadOrCreateRelayIdentity(dir, created.Name); err != nil {
		t.Fatalf("reload relay identity: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read reloaded relay identity: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("unchanged relay identity was rewritten")
	}
	afterInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat reloaded relay identity: %v", err)
	}
	if !afterInfo.ModTime().Equal(info.ModTime()) {
		t.Fatal("unchanged relay identity modification time changed")
	}
}
