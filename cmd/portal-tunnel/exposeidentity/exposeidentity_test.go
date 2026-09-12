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

func mustMarshal(t *testing.T, id types.Identity) string {
	t.Helper()
	data, err := identity.Marshal(id)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(data)
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
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
	if reloaded := mustResolve(t, "", "", path, ""); reloaded.PrivateKey != created.PrivateKey {
		t.Fatal("reloaded private key mismatch")
	}
}

func TestResolveJSONTakesPrecedenceAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	mustResolve(t, "stored-name", "", path, "")

	fresh := mustGenerate(t, "json-name")
	if resolved := mustResolve(t, "", "", path, mustMarshal(t, fresh)); resolved.PrivateKey != fresh.PrivateKey {
		t.Fatal("json identity not used")
	}

	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted file: %v", err)
	}
	var decoded struct {
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(persisted, &decoded); err != nil {
		t.Fatalf("decode persisted file: %v", err)
	}
	if decoded.PrivateKey != fresh.PrivateKey {
		t.Fatal("json identity not persisted over the stored file")
	}
}

func TestResolveWithoutPathStaysEphemeral(t *testing.T) {
	if resolved := mustResolve(t, "", "127.0.0.1:9999", "", ""); resolved.Name == "" || resolved.PrivateKey == "" {
		t.Fatalf("generated identity incomplete: %+v", resolved)
	}
	fresh := mustGenerate(t, "json-name")
	if resolved := mustResolve(t, "", "", "", mustMarshal(t, fresh)); resolved.PrivateKey != fresh.PrivateKey {
		t.Fatal("json identity not used")
	}
}

func TestResolveNameOverridePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	first := mustResolve(t, "old-name", "", path, "")

	renamed := mustResolve(t, "new-name", "", path, "")
	if renamed.Name != "new-name" || renamed.PrivateKey != first.PrivateKey {
		t.Fatalf("rename mismatch: %+v", renamed)
	}
	if reloaded := mustResolve(t, "", "", path, ""); reloaded.Name != "new-name" {
		t.Fatalf("renamed identity not persisted: %+v", reloaded)
	}
}

func TestResolveNameOverrideFixesInvalidStoredName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	generated := mustGenerate(t, "valid")

	var payload map[string]any
	if err := json.Unmarshal([]byte(mustMarshal(t, generated)), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	payload["name"] = ""
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	mustWrite(t, path, string(raw))

	resolved := mustResolve(t, "replacement", "", path, "")
	if resolved.Name != "replacement" || resolved.PrivateKey != generated.PrivateKey {
		t.Fatalf("override mismatch: %+v", resolved)
	}
}

func TestResolveRejectsKeylessFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	mustWrite(t, path, `{"name":"foo"}`)
	if _, err := Resolve("", "", path, ""); err == nil {
		t.Fatal("keyless identity file must fail instead of generating a key")
	}
}
