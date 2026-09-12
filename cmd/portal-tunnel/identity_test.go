package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
)

func TestResolveExposeIdentityCreatesFileWhenAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")

	resolved, err := resolveExposeIdentity("svc", "127.0.0.1:8080", path, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if resolved.Name != "svc" || resolved.PrivateKey == "" {
		t.Fatalf("resolved identity incomplete: %+v", resolved)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("identity file not written: %v", err)
	}

	reloaded, err := resolveExposeIdentity("", "127.0.0.1:8080", path, "")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.PrivateKey != resolved.PrivateKey {
		t.Fatal("reloaded private key mismatch")
	}
}

func TestResolveExposeIdentityNameOverridePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	first, err := resolveExposeIdentity("old-name", "", path, "")
	if err != nil {
		t.Fatalf("first: %v", err)
	}

	renamed, err := resolveExposeIdentity("new-name", "", path, "")
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if renamed.Name != "new-name" || renamed.PrivateKey != first.PrivateKey {
		t.Fatalf("rename mismatch: %+v", renamed)
	}

	reloaded, err := resolveExposeIdentity("", "", path, "")
	if err != nil {
		t.Fatalf("after rename: %v", err)
	}
	if reloaded.Name != "new-name" {
		t.Fatalf("renamed identity not persisted: %+v", reloaded)
	}
}

func TestResolveExposeIdentityJSONOverridesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if _, err := resolveExposeIdentity("stored-name", "", path, ""); err != nil {
		t.Fatalf("stored: %v", err)
	}

	fresh, err := identity.Generate("json-name")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	freshData, err := identity.Marshal(fresh)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	resolved, err := resolveExposeIdentity("", "", path, string(freshData))
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if resolved.PrivateKey != fresh.PrivateKey {
		t.Fatal("json identity not used")
	}

	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted: %v", err)
	}
	if persistedKey(t, persisted) != fresh.PrivateKey {
		t.Fatal("json identity not persisted over the stored file")
	}
}

func TestResolveExposeIdentityRejectsKeylessFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, []byte(`{"name":"foo"}`), 0o600); err != nil {
		t.Fatalf("write keyless file: %v", err)
	}

	if _, err := resolveExposeIdentity("", "", path, ""); err == nil {
		t.Fatal("keyless identity file must fail instead of generating a key")
	}
}

func TestResolveExposeIdentityNameOverrideFixesInvalidStoredName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	generated, err := identity.Generate("valid")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := identity.Marshal(generated)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	payload["name"] = ""
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	resolved, err := resolveExposeIdentity("replacement", "", path, "")
	if err != nil {
		t.Fatalf("override: %v", err)
	}
	if resolved.Name != "replacement" || resolved.PrivateKey != generated.PrivateKey {
		t.Fatalf("override mismatch: %+v", resolved)
	}
}

func TestResolveExposeIdentityWithoutPathGenerates(t *testing.T) {
	resolved, err := resolveExposeIdentity("", "127.0.0.1:9999", "", "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if resolved.Name == "" || resolved.PrivateKey == "" {
		t.Fatalf("generated identity incomplete: %+v", resolved)
	}
}

func persistedKey(t *testing.T, data []byte) string {
	t.Helper()
	decoded, err := identity.Decode(data)
	if err != nil {
		t.Fatalf("decode persisted identity: %v", err)
	}
	return decoded.PrivateKey
}
