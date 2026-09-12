package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestResolveDerivesAddressAndFillsTokenSecret(t *testing.T) {
	generated, err := Generate("derive-check")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if generated.Address == "" || generated.PublicKey == "" || generated.PrivateKey == "" || generated.TokenSecret == "" {
		t.Fatalf("generated identity incomplete: %+v", generated)
	}

	resolved, err := Resolve(types.Identity{Name: generated.Name, PrivateKey: generated.PrivateKey})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Address != generated.Address || resolved.PublicKey != generated.PublicKey {
		t.Fatalf("Resolve derived mismatch:\n resolved %+v\ngenerated %+v", resolved, generated)
	}
}

func TestResolveRejectsMismatchedAddress(t *testing.T) {
	generated, err := Generate("mismatch-check")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	generated.Address = "0x0000000000000000000000000000000000000001"
	if _, err := Resolve(generated); err == nil || !strings.Contains(err.Error(), "does not match private key") {
		t.Fatalf("Resolve mismatched address: got %v", err)
	}
}

func TestResolveRejectsMissingKeyMaterial(t *testing.T) {
	if _, err := Resolve(types.Identity{Name: "no-key"}); err == nil || !strings.Contains(err.Error(), "private key is required") {
		t.Fatalf("Resolve without key material: got %v, want implicit generation rejected", err)
	}
}

func TestParseRejectsKeylessDocument(t *testing.T) {
	if _, err := Parse([]byte(`{"name":"foo"}`)); err == nil || !strings.Contains(err.Error(), "private key is required") {
		t.Fatalf("Parse keyless document: got %v, want error instead of implicit generation", err)
	}
}

func TestResolveRejectsEmptyName(t *testing.T) {
	generated, err := Generate("name-check")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	generated.Name = ""
	if _, err := Resolve(generated); err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("Resolve empty name: got %v", err)
	}
}

func TestGenerateMarshalParseRoundTrip(t *testing.T) {
	generated, err := Generate("round-trip")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	data, err := Marshal(generated)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Name != generated.Name || parsed.Address != generated.Address ||
		parsed.PublicKey != generated.PublicKey || parsed.PrivateKey != generated.PrivateKey ||
		parsed.TokenSecret != generated.TokenSecret {
		t.Fatalf("round trip mismatch:\n parsed %+v\ngenerated %+v", parsed, generated)
	}

	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write identity file: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read identity file: %v", err)
	}
	loaded, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse file: %v", err)
	}
	if loaded.PrivateKey != generated.PrivateKey {
		t.Fatalf("loaded private key mismatch")
	}
}

func TestParseRejectsInvalidInput(t *testing.T) {
	if _, err := Parse([]byte("not json")); err == nil || !strings.Contains(err.Error(), "decode identity json") {
		t.Fatalf("Parse invalid json: got %v", err)
	}
	if _, err := Parse(nil); err == nil || !strings.Contains(err.Error(), "identity json is required") {
		t.Fatalf("Parse empty: got %v", err)
	}
}

func TestLoadOrCreateRelayIdentityCreatesAndReloads(t *testing.T) {
	dir := t.TempDir()

	created, err := LoadOrCreateRelayIdentity(dir, "relay.example.com")
	if err != nil {
		t.Fatalf("LoadOrCreateRelayIdentity create: %v", err)
	}
	if created.Name != "relay.example.com" || created.Address == "" || created.PrivateKey == "" {
		t.Fatalf("created relay identity incomplete: %+v", created)
	}
	if created.EncryptedClientHelloSeed == "" {
		t.Fatal("relay identity missing ECH seed")
	}
	if _, err := os.Stat(filepath.Join(dir, types.RelayIdentityFilename)); err != nil {
		t.Fatalf("identity file not written: %v", err)
	}

	reloaded, err := LoadOrCreateRelayIdentity(dir, "relay.example.com")
	if err != nil {
		t.Fatalf("LoadOrCreateRelayIdentity reload: %v", err)
	}
	if reloaded.PrivateKey != created.PrivateKey || reloaded.EncryptedClientHelloSeed != created.EncryptedClientHelloSeed {
		t.Fatalf("reloaded relay identity mismatch:\n reloaded %+v\n created %+v", reloaded, created)
	}
}
func TestLoadOrCreateRelayIdentitySkipsUnchangedWrite(t *testing.T) {
	dir := t.TempDir()
	created, err := LoadOrCreateRelayIdentity(dir, "relay.example.com")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	path := filepath.Join(dir, types.RelayIdentityFilename)
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatalf("chmod read-only: %v", err)
	}
	defer func() { _ = os.Chmod(path, 0o600) }()

	reloaded, err := LoadOrCreateRelayIdentity(dir, "relay.example.com")
	if err != nil {
		t.Fatalf("unchanged identity must not be rewritten: %v", err)
	}
	if reloaded.PrivateKey != created.PrivateKey || reloaded.EncryptedClientHelloSeed != created.EncryptedClientHelloSeed {
		t.Fatalf("reloaded mismatch:\n reloaded %+v\n created %+v", reloaded, created)
	}
}
