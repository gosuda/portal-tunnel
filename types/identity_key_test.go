package types

import (
	"fmt"
	"strings"
	"testing"
)

func TestCanonicalIdentityKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		keyName string
		address string
		want    string
	}{
		{"already canonical", "alice", "addr", "alice:addr"},
		{"uppercase normalized", "Alice", "ADDR", "alice:addr"},
		{"whitespace trimmed", "  alice\t", "\naddr ", "alice:addr"},
		{"empty name keeps separator", "", "addr", ":addr"},
		{"empty address keeps separator", "alice", "", "alice:"},
		{"both empty", "", "", ""},
		{"whitespace only", " \t", " \n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := CanonicalIdentityKey(tt.keyName, tt.address); got != tt.want {
				t.Errorf("CanonicalIdentityKey(%q, %q) = %q, want %q", tt.keyName, tt.address, got, tt.want)
			}
		})
	}
}

func TestParseIdentityKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"canonical round-trip", "alice:addr", "alice:addr"},
		{"uppercase normalized", "Alice:ADDR", "alice:addr"},
		{"whitespace normalized", " alice :\taddr ", "alice:addr"},
		{"first separator wins, colons kept in address", "a:b:c", "a:b:c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseIdentityKey(tt.raw)
			if err != nil {
				t.Fatalf("ParseIdentityKey(%q) error = %v, want nil", tt.raw, err)
			}
			if got != tt.want {
				t.Errorf("ParseIdentityKey(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestParseIdentityKeyRejectsMalformed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
	}{
		{"missing separator", "aliceaddr"},
		{"empty input", ""},
		{"separator only", ":"},
		{"empty name", ":addr"},
		{"empty address", "alice:"},
		{"whitespace-only name", "  :addr"},
		{"whitespace-only address", "alice: \t"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseIdentityKey(tt.raw)
			if err == nil {
				t.Fatalf("ParseIdentityKey(%q) = %q, want error", tt.raw, got)
			}
		})
	}
}

func TestParseIdentityKeyErrorMentionsInputAndShape(t *testing.T) {
	t.Parallel()
	const raw = "Alice:"
	_, err := ParseIdentityKey(raw)
	if err == nil {
		t.Fatal("ParseIdentityKey(\"Alice:\") error = nil, want error")
	}
	wantInput := fmt.Sprintf("%q", raw)
	if !strings.Contains(err.Error(), wantInput) {
		t.Errorf("error %q does not mention offending input %s", err, wantInput)
	}
	if !strings.Contains(err.Error(), `"name:address"`) {
		t.Errorf("error %q does not describe expected name:address shape", err)
	}
}

func TestIdentityKeyMirrorsLegacyBehavior(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		identity Identity
		want     string
	}{
		{"zero identity", Identity{}, ""},
		{"whitespace-only identity", Identity{Name: " \t", Address: " \n"}, ""},
		{"canonical parts", Identity{Name: "alice", Address: "addr"}, "alice:addr"},
		{"mixed case", Identity{Name: "Alice", Address: "Addr"}, "alice:addr"},
		{"surrounding whitespace", Identity{Name: " alice ", Address: " addr "}, "alice:addr"},
		{"name only", Identity{Name: "alice"}, "alice:"},
		{"address only", Identity{Address: "addr"}, ":addr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.identity.Key(); got != tt.want {
				t.Errorf("Identity{Name: %q, Address: %q}.Key() = %q, want %q", tt.identity.Name, tt.identity.Address, got, tt.want)
			}
			if delegated := CanonicalIdentityKey(tt.identity.Name, tt.identity.Address); delegated != tt.want {
				t.Errorf("CanonicalIdentityKey(%q, %q) = %q, want %q; Key() and constructor disagree", tt.identity.Name, tt.identity.Address, delegated, tt.want)
			}
		})
	}
}
