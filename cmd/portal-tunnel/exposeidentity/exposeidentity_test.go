package exposeidentity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func mustGenerate(t *testing.T, name string) types.Identity {
	t.Helper()
	generated, err := identity.Generate(name)
	if err != nil {
		t.Fatalf("Generate %q: %v", name, err)
	}
	return generated
}

func mustMarshal(t *testing.T, id types.Identity) []byte {
	t.Helper()
	data, err := identity.Marshal(id)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return data
}

func mustResolve(t *testing.T, name, target, path, rawJSON string) types.Identity {
	t.Helper()
	resolved, err := Resolve(name, target, path, rawJSON)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return resolved
}

func TestResolveCreatesPersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")

	created := mustResolve(t, "svc", "127.0.0.1:8080", path, "")
	if created.Name != "svc" || created.PrivateKey == "" {
		t.Fatalf("created identity incomplete: %+v", created)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("identity file not written: %v", err)
	}
	if reloaded := mustResolve(t, "ignored", "", path, ""); reloaded.PrivateKey != created.PrivateKey || reloaded.Name != created.Name {
		t.Fatalf("reloaded identity mismatch: %+v", reloaded)
	}
}

func TestResolveJSONTakesPrecedenceWithoutPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	mustResolve(t, "stored-name", "", path, "")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read original identity: %v", err)
	}

	fresh := mustGenerate(t, "json-name")
	if resolved := mustResolve(t, "ignored", "", path, string(mustMarshal(t, fresh))); resolved.PrivateKey != fresh.PrivateKey {
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

func TestResolveWithoutPathStaysEphemeral(t *testing.T) {
	resolved := mustResolve(t, "", "127.0.0.1:9999", "", "")
	if resolved.Name == "" || resolved.PrivateKey == "" {
		t.Fatalf("generated identity incomplete: %+v", resolved)
	}
}

func TestResolveNameOnlyAppliesWhenGenerating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	first := mustResolve(t, "stored-name", "", path, "")

	reloaded := mustResolve(t, "new-name", "", path, "")
	if reloaded.Name != first.Name || reloaded.PrivateKey != first.PrivateKey {
		t.Fatalf("existing identity changed: %+v", reloaded)
	}
}

func TestResolveRejectsInvalidExistingName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	generated := mustGenerate(t, "valid")
	var payload map[string]any
	if err := json.Unmarshal(mustMarshal(t, generated), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	payload["name"] = ""
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}

	if _, err := Resolve("replacement", "", path, ""); err == nil {
		t.Fatal("invalid existing identity was silently changed")
	}
}

func TestResolveRejectsKeylessFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, []byte(`{"name":"foo"}`), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	if _, err := Resolve("", "", path, ""); err == nil {
		t.Fatal("keyless identity file must fail instead of generating a key")
	}
}
