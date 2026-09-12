package identity

import (
	"strings"
	"testing"

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

func TestResolveDerivesAddressAndFillsTokenSecret(t *testing.T) {
	generated := mustGenerate(t, "derive-check")
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

func TestResolveRejectsInvalidIdentities(t *testing.T) {
	generated := mustGenerate(t, "reject-check")
	generated.Address = "0x0000000000000000000000000000000000000001"
	nameCheck := mustGenerate(t, "name-check")
	nameCheck.Name = ""

	cases := []struct {
		name    string
		parse   bool
		id      types.Identity
		raw     string
		wantErr string
	}{
		{"mismatched address", false, generated, "", "does not match private key"},
		{"missing key material", false, types.Identity{Name: "no-key"}, "", "private key is required"},
		{"empty name", false, nameCheck, "", "name"},
		{"keyless document", true, types.Identity{}, `{"name":"foo"}`, "private key is required"},
		{"invalid json", true, types.Identity{}, "not json", "decode identity json"},
		{"empty input", true, types.Identity{}, "", "identity json is required"},
	}
	for _, tc := range cases {
		var err error
		if tc.parse {
			_, err = Parse([]byte(tc.raw))
		} else {
			_, err = Resolve(tc.id)
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: got %v, want error containing %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestGenerateMarshalParseRoundTrip(t *testing.T) {
	generated := mustGenerate(t, "round-trip")

	data, err := Marshal(generated)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed != generated {
		t.Fatalf("round trip mismatch:\n parsed   %+v\ngenerated %+v", parsed, generated)
	}
}
