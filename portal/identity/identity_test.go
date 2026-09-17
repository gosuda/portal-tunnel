package identity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func mustGenerate(t *testing.T, name string) types.Identity {
	t.Helper()
	generated, err := Generate(name)
	if err != nil {
		t.Fatalf("Generate %q: %v", name, err)
	}
	return generated
}

func mustMarshal(t *testing.T, id types.Identity) []byte {
	t.Helper()
	data, err := Marshal(id)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return data
}

func withJSONField(t *testing.T, data []byte, field string, value any) []byte {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	payload[field] = value
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// TestGenerateReturnsValidIdentity protects the data-integrity contract that Generate() produces
// an identity with all required fields (Name, Address, PublicKey, PrivateKey, TokenSecret) populated,
// and that the identity round-trips through Marshal and Parse unchanged.
func TestGenerateReturnsValidIdentity(t *testing.T) {
	generated := mustGenerate(t, "generate-check")
	if generated.Name != "generate-check" ||
		generated.Address == "" || generated.PublicKey == "" ||
		generated.PrivateKey == "" || generated.TokenSecret == "" {
		t.Fatalf("generated identity incomplete: %+v", generated)
	}

	parsed, err := Parse(mustMarshal(t, generated))
	if err != nil {
		t.Fatalf("Parse(Marshal(Generate())): %v", err)
	}
	if parsed != generated {
		t.Fatalf("round trip mismatch:\n parsed   %+v\ngenerated %+v", parsed, generated)
	}
}

// TestParseRejectsInvalidStorageInput protects the data-integrity contract that Parse() rejects
// corrupted or malformed identity storage: missing private key, invalid JSON, mismatched address
// (does not match the key), empty name, or derivation path without mnemonic.
func TestParseRejectsInvalidStorageInput(t *testing.T) {
	valid := mustMarshal(t, mustGenerate(t, "parse-check"))

	cases := []struct {
		name    string
		raw     func() []byte
		wantErr string
	}{
		{"keyless document", func() []byte { return []byte(`{"name":"foo"}`) }, "private key is required"},
		{"invalid json", func() []byte { return []byte("not json") }, "decode identity json"},
		{"empty input", func() []byte { return nil }, "identity json is required"},
		{
			"mismatched address",
			func() []byte { return withJSONField(t, valid, "address", "0x0000000000000000000000000000000000000001") },
			"does not match private key",
		},
		{"empty name", func() []byte { return withJSONField(t, valid, "name", "") }, "name"},
		{"derivation without mnemonic", func() []byte { return withJSONField(t, valid, "derivation_path", "m/44'/60'/0'/0/0") }, "derivation_path requires mnemonic"},
	}
	for _, tc := range cases {
		if _, err := Parse(tc.raw()); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: got %v, want error containing %q", tc.name, err, tc.wantErr)
		}
	}
}

// TestMarshalSerializesValidIdentity protects the wire-protocol compatibility contract that
// Marshal() outputs JSON containing all required fields (name, address, public_key, private_key,
// token_secret) under their canonical lowercase keys, so the format is stable for storage and parsing.
func TestMarshalSerializesValidIdentity(t *testing.T) {
	data := mustMarshal(t, mustGenerate(t, "marshal-check"))

	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"name", "address", "public_key", "private_key", "token_secret"} {
		if _, ok := payload[field]; !ok {
			t.Fatalf("marshaled identity missing field %q: %s", field, data)
		}
	}
}

// TestNewRegisterChallengeNormalizesWireIdentity protects the wire-protocol contract that the
// identity embedded in a RegisterChallenge has a lowercased name, matching the normalization applied
// during initial identity creation, so challenge verification is consistent.
func TestNewRegisterChallengeNormalizesWireIdentity(t *testing.T) {
	generated := mustGenerate(t, "wire-check")
	challenge, err := NewRegisterChallenge(types.RegisterChallengeRequest{
		Identity: types.Identity{Name: "Demo-App", Address: generated.Address},
	}, "portal.example.com", "https://portal.example.com", time.Now(), time.Minute)
	if err != nil {
		t.Fatalf("NewRegisterChallenge: %v", err)
	}
	if name := challenge.Request.Identity.Name; name != "demo-app" {
		t.Fatalf("challenge identity name = %q, want %q", name, "demo-app")
	}
}
