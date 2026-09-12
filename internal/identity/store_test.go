package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateParseLoadIdentityRoundTrip(t *testing.T) {
	generated, err := GenerateIdentity("facade-roundtrip")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if generated.Name == "" || generated.Address == "" || generated.PublicKey == "" || generated.PrivateKey == "" {
		t.Fatalf("generated identity incomplete: %+v", generated)
	}

	path := filepath.Join(t.TempDir(), "identity.json")
	if err := saveIdentity(path, generated); err != nil {
		t.Fatalf("saveIdentity: %v", err)
	}

	loaded, err := LoadIdentity(path)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if loaded.Name != generated.Name || loaded.Address != generated.Address || loaded.PrivateKey != generated.PrivateKey {
		t.Fatalf("loaded identity mismatch:\n loaded %+v\ngenerated %+v", loaded, generated)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read identity file: %v", err)
	}
	parsed, err := ParseIdentity(data)
	if err != nil {
		t.Fatalf("ParseIdentity: %v", err)
	}
	if parsed.Address != generated.Address || parsed.PrivateKey != generated.PrivateKey {
		t.Fatalf("parsed identity mismatch:\n parsed %+v\ngenerated %+v", parsed, generated)
	}
}

func TestParseIdentityRejectsInvalidInput(t *testing.T) {
	if _, err := ParseIdentity([]byte("not json")); err == nil || !strings.Contains(err.Error(), "decode identity json") {
		t.Fatalf("invalid json: got %v", err)
	}
	if _, err := ParseIdentity(nil); err == nil || !strings.Contains(err.Error(), "identity json is required") {
		t.Fatalf("empty input: got %v", err)
	}
}

func TestLoadIdentityRejectsMissingFile(t *testing.T) {
	_, err := LoadIdentity(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil || !strings.Contains(err.Error(), "read identity file") {
		t.Fatalf("missing file: got %v", err)
	}
}

func TestGenerateIdentityRejectsEmptyName(t *testing.T) {
	if _, err := GenerateIdentity("  "); err == nil {
		t.Fatal("empty name must be rejected")
	}
}
