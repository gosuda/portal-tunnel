package types

import "testing"

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
		{"multiple separators", "a:b:c"},
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

func TestIdentityKeyDelegatesToCanonicalIdentityKey(t *testing.T) {
	t.Parallel()
	identity := Identity{Name: " Alice ", Address: "ADDR"}
	if got, want := identity.Key(), CanonicalIdentityKey(identity.Name, identity.Address); got != want {
		t.Errorf("Identity.Key() = %q, want CanonicalIdentityKey(%q, %q) = %q", got, identity.Name, identity.Address, want)
	}
}
