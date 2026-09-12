package identity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func mustLoadOrCreate(t *testing.T, name, target, path, rawJSON string) types.Identity {
	t.Helper()
	loaded, err := LoadOrCreate(name, target, path, rawJSON)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	return loaded
}

func TestLoadOrCreatePersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")

	created := mustLoadOrCreate(t, "svc", "127.0.0.1:8080", path, "")
	if created.Name != "svc" || created.PrivateKey == "" {
		t.Fatalf("created identity incomplete: %+v", created)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("identity file not written: %v", err)
	}
	if reloaded := mustLoadOrCreate(t, "ignored", "", path, ""); reloaded.PrivateKey != created.PrivateKey || reloaded.Name != created.Name {
		t.Fatalf("reloaded identity mismatch: %+v", reloaded)
	}
}

func TestLoadOrCreateJSONTakesPrecedenceWithoutPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	mustLoadOrCreate(t, "stored-name", "", path, "")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read original identity: %v", err)
	}

	fresh := mustGenerate(t, "json-name")
	if resolved := mustLoadOrCreate(t, "ignored", "", path, string(mustMarshal(t, fresh))); resolved.PrivateKey != fresh.PrivateKey {
		t.Fatal("json identity not used")
	}

	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read identity after json resolve: %v", err)
	}
	if string(current) != string(original) {
		t.Fatal("in-memory json identity changed the configured file")
	}
}

func TestLoadOrCreateWithoutPathStaysEphemeral(t *testing.T) {
	resolved := mustLoadOrCreate(t, "", "127.0.0.1:9999", "", "")
	if resolved.Name == "" || resolved.PrivateKey == "" {
		t.Fatalf("generated identity incomplete: %+v", resolved)
	}
}

func TestLoadOrCreateNameOnlyAppliesWhenGenerating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	first := mustLoadOrCreate(t, "stored-name", "", path, "")

	reloaded := mustLoadOrCreate(t, "new-name", "", path, "")
	if reloaded.Name != first.Name || reloaded.PrivateKey != first.PrivateKey {
		t.Fatalf("existing identity changed: %+v", reloaded)
	}
}

func TestLoadOrCreateRejectsInvalidExistingName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	raw := withJSONField(t, mustMarshal(t, mustGenerate(t, "valid")), "name", "")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}

	if _, err := LoadOrCreate("replacement", "", path, ""); err == nil {
		t.Fatal("invalid existing identity was silently changed")
	}
}

func TestLoadOrCreateRejectsKeylessFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, []byte(`{"name":"foo"}`), 0o600); err != nil {
		t.Fatalf("write identity file: %v", err)
	}
	if _, err := LoadOrCreate("", "", path, ""); err == nil {
		t.Fatal("keyless identity file must fail instead of generating a key")
	}
}
