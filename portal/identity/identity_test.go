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
