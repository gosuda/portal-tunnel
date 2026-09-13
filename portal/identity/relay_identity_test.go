package identity

import (
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

func TestLoadOrCreateRelayIdentityPreservesUnchangedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, types.RelayIdentityFilename)
	created, err := LoadOrCreateRelayIdentity(path, "relay.example.com")
	if err != nil {
		t.Fatalf("create relay identity: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read relay identity: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat relay identity: %v", err)
	}

	if _, err := LoadOrCreateRelayIdentity(path, created.Name); err != nil {
		t.Fatalf("reload relay identity: %v", err)
	}
	if after, err := os.ReadFile(path); err != nil {
		t.Fatalf("read reloaded relay identity: %v", err)
	} else if string(after) != string(before) {
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
