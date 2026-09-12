package identityfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
)

func TestResolveCreatesIdentityFileWhenAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")

	resolved, err := Resolve("svc", "127.0.0.1:8080", path, "")
	if err != nil {
		t.Fatalf("Resolve create: %v", err)
	}
	if resolved.Name != "svc" || resolved.PrivateKey == "" {
		t.Fatalf("resolved identity incomplete: %+v", resolved)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("identity file not written: %v", err)
	}

	reloaded, err := Resolve("", "127.0.0.1:8080", path, "")
	if err != nil {
		t.Fatalf("Resolve reload: %v", err)
	}
	if reloaded.PrivateKey != resolved.PrivateKey {
		t.Fatalf("reloaded private key mismatch")
	}
}

func TestResolveNameOverridePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	first, err := Resolve("old-name", "", path, "")
	if err != nil {
		t.Fatalf("Resolve first: %v", err)
	}

	renamed, err := Resolve("new-name", "", path, "")
	if err != nil {
		t.Fatalf("Resolve rename: %v", err)
	}
	if renamed.Name != "new-name" || renamed.PrivateKey != first.PrivateKey {
		t.Fatalf("rename mismatch: %+v", renamed)
	}

	reloaded, err := Resolve("", "", path, "")
	if err != nil {
		t.Fatalf("Resolve after rename: %v", err)
	}
	if reloaded.Name != "new-name" {
		t.Fatalf("renamed identity not persisted: %+v", reloaded)
	}
}

func TestResolveIdentityJSONOverridesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	stored, err := Resolve("stored-name", "", path, "")
	if err != nil {
		t.Fatalf("Resolve stored: %v", err)
	}
	storedData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read stored identity: %v", err)
	}
	_ = stored

	fresh, err := identity.Generate("json-name")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	freshData, err := identity.Marshal(fresh)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	resolved, err := Resolve("", "", path, string(freshData))
	if err != nil {
		t.Fatalf("Resolve json: %v", err)
	}
	if resolved.PrivateKey != fresh.PrivateKey {
		t.Fatalf("json identity not used: %+v", resolved)
	}

	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted identity: %v", err)
	}
	if string(persisted) == string(storedData) {
		t.Fatal("json identity was not persisted over the stored file")
	}
}

func TestResolveWithoutPathOrJSONGenerates(t *testing.T) {
	resolved, err := Resolve("", "127.0.0.1:9999", "", "")
	if err != nil {
		t.Fatalf("Resolve generate: %v", err)
	}
	if resolved.Name == "" || resolved.PrivateKey == "" {
		t.Fatalf("generated identity incomplete: %+v", resolved)
	}
}
